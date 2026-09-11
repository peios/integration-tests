/* pt-logsink — stand in for eventd's log socket, and say exactly what arrived.
 *
 * TRM §11.4 describes what peinit puts on the wire to eventd: one msgpack
 * array of records per datagram, a map per record, a drop that leaves the
 * connection standing, a replay that waits rather than loses. None of that
 * is visible through eventd itself. eventd decodes the datagram, keeps what
 * it wants and answers queries about the result, so what the suite can see
 * is eventd's opinion of the traffic rather than the traffic — and a
 * receive buffer the suite cannot fill on demand.
 *
 * peinit reads the socket path from `Machine\System\eventd\LogSocketPath`
 * at boot and again on every reload, while eventd defers a change to that
 * key until it restarts. So a test that binds this tool somewhere and
 * points the key at it gets, from then on, exactly the datagrams peinit
 * would have sent eventd, and a receiver it controls.
 *
 * Usage:
 *   pt-logsink listen PATH OUT [--fill] [--hold FILE]
 *   pt-logsink peers PATH
 *
 * listen binds a SOCK_DGRAM Unix socket at PATH and appends to OUT one line
 * per datagram, followed by one line per record in it:
 *
 *   ready path=/run/x.sock inode=1234 filled=11
 *   dgram d=1 bytes=180 format=array records=2 trailing=0
 *   rec d=1 i=0 entries=5 keys=origin,is_error,message,timestamp,job_id
 *       types=str,bool,str,uint,bin origin=pt-say is_error=false
 *       timestamp=1757000000000000000 job_id=<32 hex> message=the line
 *
 * (one line each; wrapped here). A datagram that is not a msgpack array is
 * reported as `format=other head=<hex>`, and one that starts as an array
 * and then breaks as `format=bad why=<reason> at=<offset>`. The message is
 * last on its line and has backslash and every byte outside printable
 * ASCII written as \xNN, so a line of the file is always a line of the
 * report. The origin is escaped the same way and also has its spaces
 * escaped, so it is always one whitespace-free field.
 *
 *   --fill       Fill the socket's receive queue before anybody else can
 *                reach it. The socket is bound at PATH.pt-tmp, datagrams
 *                are sent to it from fresh sockets until a fresh socket's
 *                very first send is refused — which a sender's own buffer
 *                cannot cause, so it is the receiver's queue that is full
 *                — and only then is it renamed to PATH. Every datagram a
 *                sender then offers is refused with EAGAIN until the
 *                queue is read. `filled=` says how many it took. The
 *                filler datagrams read back later as `format=other`.
 *   --hold FILE  Read nothing while FILE exists. Checked every 20 ms; once
 *                FILE is gone the tool reads for the rest of its life.
 *
 * peers prints the inode of the socket bound at PATH and of every socket
 * connected to it, from sock_diag:
 *
 *   bound path=/run/x.sock inode=1234
 *   peer inode=5678
 *
 * or `bound path=… missing`. The inode is what ties a peer to a descriptor
 * in /proc/<pid>/fd, and so says which process's socket it is, and whether
 * it is still the same socket as last time.
 *
 * Like the other pt-* tools it is staged into the guest rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM (1024 * 1024)
#define MAX_FILLERS 4096

static FILE *out;

static void die(const char *what)
{
    fprintf(stderr, "pt-logsink: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void unix_addr(struct sockaddr_un *addr, socklen_t *len, const char *path)
{
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr->sun_path) {
        errno = ENAMETOOLONG;
        die(path);
    }
    strcpy(addr->sun_path, path);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
}

/* ---- msgpack, as far as a log record needs it ------------------------ */

struct cursor {
    const uint8_t *base, *p, *end;
    const char *why;
};

static int take(struct cursor *c, size_t n, const uint8_t **at)
{
    if ((size_t)(c->end - c->p) < n) {
        c->why = "short";
        return -1;
    }
    *at = c->p;
    c->p += n;
    return 0;
}

static int be(struct cursor *c, size_t n, uint64_t *v)
{
    const uint8_t *at;
    if (take(c, n, &at)) return -1;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v = (*v << 8) | at[i];
    return 0;
}

enum kind { K_STR, K_BOOL, K_UINT, K_INT, K_BIN, K_NIL, K_OTHER };

static const char *kind_name[] = { "str", "bool", "uint", "int", "bin", "nil", "other" };

struct value {
    enum kind kind;
    const uint8_t *data; /* str, bin */
    uint64_t n;          /* length for str/bin, the value otherwise */
};

static int read_value(struct cursor *c, struct value *v)
{
    const uint8_t *tag;
    uint64_t len = 0;
    if (take(c, 1, &tag)) return -1;
    uint8_t t = *tag;
    v->data = NULL;
    v->n = 0;
    if (t <= 0x7f) { v->kind = K_UINT; v->n = t; return 0; }
    if (t >= 0xe0) { v->kind = K_INT; v->n = t; return 0; }
    if (t >= 0xa0 && t <= 0xbf) { v->kind = K_STR; len = t & 0x1f; goto bytes; }
    switch (t) {
    case 0xc0: v->kind = K_NIL; return 0;
    case 0xc2: v->kind = K_BOOL; v->n = 0; return 0;
    case 0xc3: v->kind = K_BOOL; v->n = 1; return 0;
    case 0xcc: v->kind = K_UINT; return be(c, 1, &v->n);
    case 0xcd: v->kind = K_UINT; return be(c, 2, &v->n);
    case 0xce: v->kind = K_UINT; return be(c, 4, &v->n);
    case 0xcf: v->kind = K_UINT; return be(c, 8, &v->n);
    case 0xd0: v->kind = K_INT; return be(c, 1, &v->n);
    case 0xd1: v->kind = K_INT; return be(c, 2, &v->n);
    case 0xd2: v->kind = K_INT; return be(c, 4, &v->n);
    case 0xd3: v->kind = K_INT; return be(c, 8, &v->n);
    case 0xd9: v->kind = K_STR; if (be(c, 1, &len)) return -1; goto bytes;
    case 0xda: v->kind = K_STR; if (be(c, 2, &len)) return -1; goto bytes;
    case 0xdb: v->kind = K_STR; if (be(c, 4, &len)) return -1; goto bytes;
    case 0xc4: v->kind = K_BIN; if (be(c, 1, &len)) return -1; goto bytes;
    case 0xc5: v->kind = K_BIN; if (be(c, 2, &len)) return -1; goto bytes;
    case 0xc6: v->kind = K_BIN; if (be(c, 4, &len)) return -1; goto bytes;
    default:
        /* Anything a record has no business carrying — a nested array or
         * map, a float, an extension type — stops the decode here. */
        c->why = "unexpected-type";
        return -1;
    }
bytes:
    v->n = len;
    return take(c, (size_t)len, &v->data);
}

static int read_len(struct cursor *c, uint8_t fix, uint8_t fix_mask, uint8_t b16, uint8_t b32,
                    uint64_t *n, const char *why)
{
    const uint8_t *tag;
    if (take(c, 1, &tag)) return -1;
    if ((*tag & ~fix_mask) == fix) { *n = *tag & fix_mask; return 0; }
    if (*tag == b16) return be(c, 2, n);
    if (*tag == b32) return be(c, 4, n);
    c->p--;
    c->why = why;
    return -1;
}

static void put_escaped(const uint8_t *s, size_t n, int escape_space)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t b = s[i];
        if (b < 0x20 || b >= 0x7f || b == '\\' || (escape_space && b == ' '))
            fprintf(out, "\\x%02x", b);
        else
            fputc(b, out);
    }
}

static int key_is(const struct value *k, const char *name)
{
    return k->kind == K_STR && k->n == strlen(name) && memcmp(k->data, name, k->n) == 0;
}

/* One record, as one `rec` line. Returns -1 and leaves c->why set when the
 * map does not decode. */
static int report_record(struct cursor *c, unsigned long dgram, uint64_t index)
{
    uint64_t entries;
    if (read_len(c, 0x80, 0x0f, 0xde, 0xdf, &entries, "record-not-a-map")) return -1;
    if (entries > 64) { c->why = "too-many-entries"; return -1; }

    char keys[1024] = "", types[512] = "";
    struct value origin = { K_OTHER, NULL, 0 }, message = { K_OTHER, NULL, 0 };
    struct value is_error = { K_OTHER, NULL, 0 }, timestamp = { K_OTHER, NULL, 0 };
    struct value job_id = { K_OTHER, NULL, 0 };
    int have_origin = 0, have_message = 0, have_error = 0, have_time = 0, have_job = 0;

    for (uint64_t i = 0; i < entries; i++) {
        struct value k, v;
        if (read_value(c, &k) || read_value(c, &v)) return -1;
        if (k.kind != K_STR) { c->why = "key-not-a-string"; return -1; }
        size_t kl = strlen(keys);
        if (kl + k.n + 2 < sizeof keys) {
            if (kl) strcat(keys, ",");
            strncat(keys, (const char *)k.data, (size_t)k.n);
        }
        size_t tl = strlen(types);
        if (tl + 8 < sizeof types) {
            if (tl) strcat(types, ",");
            strcat(types, kind_name[v.kind]);
        }
        if (key_is(&k, "origin")) { origin = v; have_origin = 1; }
        else if (key_is(&k, "message")) { message = v; have_message = 1; }
        else if (key_is(&k, "is_error")) { is_error = v; have_error = 1; }
        else if (key_is(&k, "timestamp")) { timestamp = v; have_time = 1; }
        else if (key_is(&k, "job_id")) { job_id = v; have_job = 1; }
    }

    fprintf(out, "rec d=%lu i=%llu entries=%llu keys=%s types=%s origin=",
            dgram, (unsigned long long)index, (unsigned long long)entries, keys, types);
    if (have_origin && (origin.kind == K_STR)) put_escaped(origin.data, (size_t)origin.n, 1);
    else fputc('-', out);
    fprintf(out, " is_error=%s", !have_error ? "-" :
            is_error.kind != K_BOOL ? "?" : is_error.n ? "true" : "false");
    if (have_time && timestamp.kind == K_UINT)
        fprintf(out, " timestamp=%llu", (unsigned long long)timestamp.n);
    else
        fputs(" timestamp=-", out);
    fputs(" job_id=", out);
    if (have_job && job_id.kind == K_BIN) {
        for (uint64_t i = 0; i < job_id.n; i++) fprintf(out, "%02x", job_id.data[i]);
        if (job_id.n == 0) fputc('-', out);
    } else {
        fputc('-', out);
    }
    fputs(" message=", out);
    if (have_message && message.kind == K_STR) put_escaped(message.data, (size_t)message.n, 0);
    fputc('\n', out);
    return 0;
}

static void report_datagram(unsigned long d, const uint8_t *buf, size_t len, size_t real_len)
{
    struct cursor c = { buf, buf, buf + len, NULL };
    uint64_t count;
    uint8_t first = len ? buf[0] : 0;
    int is_array = len && ((first & 0xf0) == 0x90 || first == 0xdc || first == 0xdd);

    if (real_len > len) {
        fprintf(out, "dgram d=%lu bytes=%zu format=truncated\n", d, real_len);
        return;
    }
    if (!is_array) {
        fprintf(out, "dgram d=%lu bytes=%zu format=other head=", d, len);
        for (size_t i = 0; i < len && i < 24; i++) fprintf(out, "%02x", buf[i]);
        fputc('\n', out);
        return;
    }
    if (read_len(&c, 0x90, 0x0f, 0xdc, 0xdd, &count, "not-an-array")) {
        fprintf(out, "dgram d=%lu bytes=%zu format=bad why=%s at=%zu\n",
                d, len, c.why, (size_t)(c.p - c.base));
        return;
    }
    /* The records are rendered into memory first, so the datagram's own
     * line — which comes before them — can say whether the whole thing
     * decoded and how many bytes were left over: the claim is about the
     * datagram as a unit, not about each record on its own. */
    char *body = NULL;
    size_t body_len = 0;
    FILE *real = out;
    out = open_memstream(&body, &body_len);
    if (!out) die("open_memstream");
    uint64_t decoded = 0;
    for (; decoded < count; decoded++)
        if (report_record(&c, d, decoded)) break;
    fclose(out);
    out = real;
    if (decoded < count) {
        fprintf(out, "dgram d=%lu bytes=%zu format=bad why=%s at=%zu records=%llu\n",
                d, len, c.why ? c.why : "?", (size_t)(c.p - c.base),
                (unsigned long long)count);
    } else {
        fprintf(out, "dgram d=%lu bytes=%zu format=array records=%llu trailing=%zu\n",
                d, len, (unsigned long long)count, (size_t)(c.end - c.p));
        fwrite(body, 1, body_len, out);
    }
    free(body);
}

/* ---- listen ----------------------------------------------------------- */

static unsigned long fill_queue(const char *path)
{
    struct sockaddr_un addr;
    socklen_t addr_len;
    unix_addr(&addr, &addr_len, path);
    unsigned long filled = 0;
    for (int n = 0; n < MAX_FILLERS; n++) {
        int f = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (f < 0) die("filler socket");
        if (connect(f, (struct sockaddr *)&addr, addr_len) < 0) die("filler connect");
        unsigned long sent = 0;
        while (send(f, "pt-logsink-fill", 15, 0) == 15) sent++;
        int err = errno;
        /* A datagram already queued at the receiver stays there when its
         * sender closes: close releases the sender's own queue, not what
         * it has delivered. */
        close(f);
        if (err != EAGAIN) {
            errno = err;
            die("filler send");
        }
        filled += sent;
        if (sent == 0) return filled;
    }
    fprintf(stderr, "pt-logsink: the queue never filled\n");
    exit(2);
}

static int cmd_listen(int argc, char **argv)
{
    if (argc < 4) return 64;
    const char *path = argv[2], *out_path = argv[3], *hold = NULL;
    int fill = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--fill") == 0) fill = 1;
        else if (strcmp(argv[i], "--hold") == 0 && i + 1 < argc) hold = argv[++i];
        else return 64;
    }

    out = fopen(out_path, "a");
    if (!out) die(out_path);

    char tmp[256];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.pt-tmp", path) >= sizeof tmp) {
        errno = ENAMETOOLONG;
        die(path);
    }
    unlink(path);
    unlink(tmp);

    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) die("socket");
    struct sockaddr_un addr;
    socklen_t addr_len;
    unix_addr(&addr, &addr_len, tmp);
    if (bind(s, (struct sockaddr *)&addr, addr_len) < 0) die("bind");

    unsigned long filled = fill ? fill_queue(tmp) : 0;
    /* Exposed only now, so nothing can reach the socket before the queue
     * is in the state the caller asked for. A bound socket is found by its
     * inode, so renaming the path moves the socket with it. */
    if (rename(tmp, path) < 0) die("rename");

    /* The socket's own inode — the one /proc/<pid>/fd names as
     * socket:[N] — rather than the inode of the file at PATH. */
    struct stat st;
    if (fstat(s, &st) < 0) die("fstat");
    fprintf(out, "ready path=%s inode=%lu filled=%lu\n", path, (unsigned long)st.st_ino, filled);
    fflush(out);

    if (hold) {
        struct timespec tick = { 0, 20 * 1000 * 1000 };
        while (access(hold, F_OK) == 0) nanosleep(&tick, NULL);
        fprintf(out, "released\n");
        fflush(out);
    }

    static uint8_t buf[MAX_DATAGRAM];
    for (unsigned long d = 1;; d++) {
        ssize_t n = recv(s, buf, sizeof buf, MSG_TRUNC);
        if (n < 0) {
            if (errno == EINTR) { d--; continue; }
            die("recv");
        }
        size_t got = (size_t)n > sizeof buf ? sizeof buf : (size_t)n;
        report_datagram(d, buf, got, (size_t)n);
        fflush(out);
    }
}

/* ---- peers ------------------------------------------------------------ */

struct unix_sock {
    unsigned int inode;
    unsigned int peer;
    int have_peer;
    unsigned int vfs_ino, vfs_dev;
    int have_vfs;
};

static struct unix_sock socks[16384];
static size_t sock_count;

static void record_sock(const struct unix_diag_msg *msg, size_t len)
{
    if (sock_count == sizeof socks / sizeof socks[0]) return;
    struct unix_sock *u = &socks[sock_count];
    memset(u, 0, sizeof *u);
    u->inode = msg->udiag_ino;
    struct rtattr *attr = (struct rtattr *)(msg + 1);
    size_t remaining = len - NLMSG_ALIGN(sizeof *msg);
    for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
        if (attr->rta_type == UNIX_DIAG_VFS && RTA_PAYLOAD(attr) >= sizeof(struct unix_diag_vfs)) {
            struct unix_diag_vfs vfs;
            memcpy(&vfs, RTA_DATA(attr), sizeof vfs);
            u->vfs_ino = vfs.udiag_vfs_ino;
            u->vfs_dev = vfs.udiag_vfs_dev;
            u->have_vfs = 1;
        } else if (attr->rta_type == UNIX_DIAG_PEER && RTA_PAYLOAD(attr) >= sizeof(uint32_t)) {
            uint32_t peer;
            memcpy(&peer, RTA_DATA(attr), sizeof peer);
            u->peer = peer;
            u->have_peer = 1;
        }
    }
    sock_count++;
}

static int dump_unix_sockets(void)
{
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (s < 0) return errno;
    struct {
        struct nlmsghdr nlh;
        struct unix_diag_req req;
    } request;
    memset(&request, 0, sizeof request);
    request.nlh.nlmsg_len = sizeof request;
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.req.sdiag_family = AF_UNIX;
    request.req.udiag_states = ~0u;
    request.req.udiag_show = UDIAG_SHOW_VFS | UDIAG_SHOW_PEER;
    if (send(s, &request, sizeof request, 0) < 0) {
        int err = errno;
        close(s);
        return err;
    }
    static char buffer[64 * 1024];
    for (;;) {
        ssize_t got = recv(s, buffer, sizeof buffer, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            int err = errno;
            close(s);
            return err;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buffer; NLMSG_OK(h, (size_t)got);
             h = NLMSG_NEXT(h, got)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                close(s);
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                close(s);
                return e->error ? -e->error : EPROTO;
            }
            record_sock(NLMSG_DATA(h), h->nlmsg_len - NLMSG_HDRLEN);
        }
    }
}

static int cmd_peers(int argc, char **argv)
{
    if (argc != 3) return 64;
    /* Matched by the file at PATH rather than by the name the socket was
     * bound with: `listen --fill` binds under a temporary name and renames,
     * and the kernel remembers the name given to bind, not where the file
     * is now. */
    struct stat st;
    if (stat(argv[2], &st) < 0 || !S_ISSOCK(st.st_mode)) {
        printf("bound path=%s missing\n", argv[2]);
        return 0;
    }
    int err = dump_unix_sockets();
    if (err) {
        printf("dump failed errno=%d %s\n", err, strerror(err));
        return 3;
    }
    const struct unix_sock *bound = NULL;
    /* sock_diag reports the superblock's device in the kernel's own
     * encoding (major << 20 | minor), which is not st_dev's. */
    for (size_t i = 0; i < sock_count; i++)
        if (socks[i].have_vfs && socks[i].vfs_ino == (unsigned int)st.st_ino
            && (socks[i].vfs_dev >> 20) == major(st.st_dev)
            && (socks[i].vfs_dev & 0xfffff) == minor(st.st_dev))
            bound = &socks[i];
    if (!bound) {
        printf("bound path=%s missing\n", argv[2]);
        return 0;
    }
    printf("bound path=%s inode=%u\n", argv[2], bound->inode);
    for (size_t i = 0; i < sock_count; i++)
        if (socks[i].have_peer && socks[i].peer == bound->inode && &socks[i] != bound)
            printf("peer inode=%u\n", socks[i].inode);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 64;
    if (argc >= 2 && strcmp(argv[1], "listen") == 0) rc = cmd_listen(argc, argv);
    else if (argc >= 2 && strcmp(argv[1], "peers") == 0) rc = cmd_peers(argc, argv);
    if (rc == 64)
        fprintf(stderr, "usage: pt-logsink listen PATH OUT [--fill] [--hold FILE]\n"
                        "       pt-logsink peers PATH\n");
    return rc;
}
