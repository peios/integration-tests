-- resolvd TRM ch.7 (the NSS shim: §7.1 the module, §7.2 forward
-- lookups, §7.3 reverse lookups) and PSPU §6.10 (the hosts shim).
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), a whole Peios (helpers.network), and pt-nss, an
-- instrument whose C source is below.
--
-- Why an instrument. The image has no compiler and no python, and
-- nothing it ships reports an NSS status or h_errno: `getent` gives an
-- exit status, and `ping`/`nc`/`curl` give gai_strerror text at best. The
-- guest's glibc is 2.44 and the host's 2.43, and the guest has the usual
-- /lib64 loader, so a program compiled DYNAMICALLY on the host runs in the
-- guest against the guest's own glibc (tests/tools/build.sh builds static
-- binaries, which cannot dlopen an NSS module reliably). pt-nss is compiled
-- here at file scope and staged into the boot as /usr/bin/pt-nss.
--
-- What it does:
--   * dlopens the installed libnss_peios_net.so.2 and calls its six entry
--     points directly, with a buffer of a chosen size and errno, h_errno
--     and TTL out-parameters preset to -77, so "left alone" and "written
--     0" differ;
--   * calls glibc too (getaddrinfo, gethostbyname2_r, gethostbyaddr,
--     __nss_configure_lookup), for what a program sees;
--   * defines socket, connect, close, setsockopt, read/recv*, write/send*
--     and open*/fopen* itself, exported (-rdynamic), so they interpose the
--     module's PLT calls. Each call's trace is therefore exactly the
--     module's socket and file activity — glibc's own internal calls do not
--     go through the PLT and are not traced — including the request bytes
--     it wrote and the reply bytes it read, which are decoded here;
--   * optionally (PTNSS_FAKE) runs a stand-in server in a child process and
--     redirects the module's connect to /run/resolvd/resolv.sock to it, for
--     the replies the real resolvd cannot be made to give (silence for ten
--     seconds, a reply of the wrong kind, bytes that do not decode). Every
--     other test talks to the real resolvd.
--
-- Answers come from static names (`Dns\Hosts`, written at file scope;
-- synthetic, never sent upstream) and, where the claim needs TTLs, CNAMEs
-- or PTR records, from the gateway's DNS server, which DHCP names as the
-- interface's server. A question that goes upstream runs while the gateway
-- pumps (`served`).
--
-- Order matters at the end: the access-denied and unreachable test sets
-- and then clears ControlSecurity, and stops resolvd; the test after it
-- runs with resolvd stopped and starts it again.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local PT_NSS_C = [==[
/* pt-nss: drive libnss_peios_net.so.2 directly and through glibc, and
   trace what the module does on its sockets and files. See the Lua
   header for why it exists and how it is built. Ops are separated by
   "+"; NAME "@null" is a null pointer, "@hex:<bytes>" raw bytes. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <netdb.h>
#include <nss.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SOCK_PATH "/run/resolvd/resolv.sock"

static int tracing, in_child;
static char tbuf[1 << 20];
static size_t tlen;
static char redirect[108];
static int socks[1024];

static void T(const char *fmt, ...) {
    if (!tracing || in_child) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tbuf + tlen, sizeof tbuf - tlen, fmt, ap);
    va_end(ap);
    if (n > 0 && tlen + n < sizeof tbuf) tlen += n;
}

static void Thex(const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) T("%02x", b[i]);
}

#define REAL(name) \
    static __typeof__(name) *real_##name; \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

int socket(int d, int t, int p) {
    REAL(socket);
    int r = real_socket(d, t, p);
    int e = errno;
    if (tracing && !in_child) {
        T("t socket family=%d type=%d ret=%d\n", d, t & 0xf, r);
        if (r >= 0 && r < 1024) socks[r] = 1;
    }
    errno = e;
    return r;
}

int connect(int fd, const struct sockaddr *a, socklen_t l) {
    REAL(connect);
    struct sockaddr_un u;
    const struct sockaddr *use = a;
    socklen_t ul = l;
    char path[110] = "";
    if (a && a->sa_family == AF_UNIX) {
        const struct sockaddr_un *s = (const void *)a;
        size_t n = l > offsetof(struct sockaddr_un, sun_path) ? l - offsetof(struct sockaddr_un, sun_path) : 0;
        if (n > sizeof s->sun_path) n = sizeof s->sun_path;
        memcpy(path, s->sun_path, n);
        path[n] = 0;
        if (redirect[0] && strcmp(path, SOCK_PATH) == 0) {
            memset(&u, 0, sizeof u);
            u.sun_family = AF_UNIX;
            strcpy(u.sun_path, redirect);
            use = (void *)&u;
            ul = offsetof(struct sockaddr_un, sun_path) + strlen(redirect) + 1;
        }
    }
    int r = real_connect(fd, use, ul);
    int e = errno;
    if (a && a->sa_family == AF_UNIX) T("t connect fd=%d family=1 path=%s ret=%d errno=%d\n", fd, path, r, r ? e : 0);
    else T("t connect fd=%d family=%d ret=%d\n", fd, a ? a->sa_family : -1, r);
    errno = e;
    return r;
}

int close(int fd) {
    REAL(close);
    if (tracing && !in_child && fd >= 0 && fd < 1024 && socks[fd]) {
        T("t close fd=%d\n", fd);
        socks[fd] = 0;
    }
    return real_close(fd);
}

int setsockopt(int fd, int lvl, int opt, const void *v, socklen_t l) {
    REAL(setsockopt);
    if (lvl == SOL_SOCKET && (opt == SO_RCVTIMEO || opt == SO_SNDTIMEO) && l >= (socklen_t)sizeof(struct timeval)) {
        const struct timeval *tv = v;
        T("t setsockopt fd=%d opt=%s sec=%ld usec=%ld\n", fd, opt == SO_RCVTIMEO ? "rcvtimeo" : "sndtimeo",
          (long)tv->tv_sec, (long)tv->tv_usec);
    } else {
        T("t setsockopt fd=%d level=%d opt=%d\n", fd, lvl, opt);
    }
    return real_setsockopt(fd, lvl, opt, v, l);
}

static int traced(int fd) { return tracing && !in_child && fd >= 0 && fd < 1024 && socks[fd]; }

static void out_bytes(const char *what, int fd, const void *b, ssize_t r) {
    if (r > 0) { T("t %s fd=%d hex=", what, fd); Thex(b, r); T("\n"); }
    else T("t %s fd=%d ret=%zd errno=%d\n", what, fd, r, r < 0 ? errno : 0);
}

ssize_t write(int fd, const void *b, size_t n) {
    REAL(write);
    ssize_t r = real_write(fd, b, n);
    int e = errno;
    if (traced(fd)) out_bytes("send", fd, b, r);
    errno = e;
    return r;
}
ssize_t send(int fd, const void *b, size_t n, int f) {
    REAL(send);
    ssize_t r = real_send(fd, b, n, f);
    int e = errno;
    if (traced(fd)) out_bytes("send", fd, b, r);
    errno = e;
    return r;
}
ssize_t sendto(int fd, const void *b, size_t n, int f, const struct sockaddr *a, socklen_t l) {
    REAL(sendto);
    ssize_t r = real_sendto(fd, b, n, f, a, l);
    int e = errno;
    T("t sendto fd=%d family=%d ret=%zd\n", fd, a ? a->sa_family : -1, r);
    errno = e;
    return r;
}
ssize_t sendmsg(int fd, const struct msghdr *m, int f) {
    REAL(sendmsg);
    ssize_t r = real_sendmsg(fd, m, f);
    int e = errno;
    T("t sendmsg fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}
ssize_t writev(int fd, const struct iovec *v, int c) {
    REAL(writev);
    ssize_t r = real_writev(fd, v, c);
    int e = errno;
    if (traced(fd)) {
        T("t send fd=%d hex=", fd);
        ssize_t left = r;
        for (int i = 0; i < c && left > 0; i++) {
            size_t k = v[i].iov_len < (size_t)left ? v[i].iov_len : (size_t)left;
            Thex(v[i].iov_base, k);
            left -= k;
        }
        T("\n");
    }
    errno = e;
    return r;
}
ssize_t read(int fd, void *b, size_t n) {
    REAL(read);
    ssize_t r = real_read(fd, b, n);
    int e = errno;
    if (traced(fd)) { errno = e; out_bytes("recv", fd, b, r); }
    errno = e;
    return r;
}
ssize_t recv(int fd, void *b, size_t n, int f) {
    REAL(recv);
    ssize_t r = real_recv(fd, b, n, f);
    int e = errno;
    if (traced(fd)) { errno = e; out_bytes("recv", fd, b, r); }
    errno = e;
    return r;
}
ssize_t recvfrom(int fd, void *b, size_t n, int f, struct sockaddr *a, socklen_t *l) {
    REAL(recvfrom);
    ssize_t r = real_recvfrom(fd, b, n, f, a, l);
    int e = errno;
    if (traced(fd)) { errno = e; out_bytes("recv", fd, b, r); }
    errno = e;
    return r;
}
ssize_t recvmsg(int fd, struct msghdr *m, int f) {
    REAL(recvmsg);
    ssize_t r = real_recvmsg(fd, m, f);
    int e = errno;
    T("t recvmsg fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}
ssize_t readv(int fd, const struct iovec *v, int c) {
    REAL(readv);
    ssize_t r = real_readv(fd, v, c);
    int e = errno;
    T("t readv fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}

#define OPEN_WRAP(name)                                              \
    int name(const char *p, int fl, ...) {                           \
        REAL(name);                                                  \
        mode_t m = 0;                                                \
        if (fl & (O_CREAT | O_TMPFILE)) {                            \
            va_list ap; va_start(ap, fl); m = va_arg(ap, int); va_end(ap); \
        }                                                            \
        T("t open path=%s\n", p);                                     \
        return real_##name(p, fl, m);                                \
    }
OPEN_WRAP(open)
OPEN_WRAP(open64)
#define OPENAT_WRAP(name)                                            \
    int name(int d, const char *p, int fl, ...) {                    \
        REAL(name);                                                  \
        mode_t m = 0;                                                \
        if (fl & (O_CREAT | O_TMPFILE)) {                            \
            va_list ap; va_start(ap, fl); m = va_arg(ap, int); va_end(ap); \
        }                                                            \
        T("t open path=%s\n", p);                                     \
        return real_##name(d, p, fl, m);                             \
    }
OPENAT_WRAP(openat)
OPENAT_WRAP(openat64)
FILE *fopen(const char *p, const char *m) {
    REAL(fopen);
    T("t open path=%s\n", p ? p : "(null)");
    return real_fopen(p, m);
}
FILE *fopen64(const char *p, const char *m) {
    REAL(fopen64);
    T("t open path=%s\n", p ? p : "(null)");
    return real_fopen64(p, m);
}

/* ------------------------------------------------------------------ */

static void *module;
static size_t buflen = 65536;
static char *buf;
static double t0;
static int base_socks;
static int open_sockets(void);

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void begin(void) {
    tlen = 0;
    tbuf[0] = 0;
    memset(socks, 0, sizeof socks);
    free(buf);
    buf = malloc(buflen ? buflen : 1);
    memset(buf, 0xAA, buflen);
    base_socks = open_sockets();
    t0 = now_ms();
    tracing = 1;
}

static int open_sockets(void) {
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    struct dirent *e;
    char p[300], l[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "/proc/self/fd/%s", e->d_name);
        ssize_t k = readlink(p, l, sizeof l - 1);
        if (k > 0) { l[k] = 0; if (strncmp(l, "socket:", 7) == 0) n++; }
    }
    closedir(d);
    return n;
}

static void end(void) {
    tracing = 0;
    printf("elapsed_ms=%.0f\n", now_ms() - t0);
    fputs(tbuf, stdout);
    printf("sockets_left=%d\n", open_sockets() - base_socks);
}

static int inbuf(const void *p, size_t n) {
    return (const char *)p >= buf && (const char *)p + n <= buf + buflen;
}

static void *sym(const char *n) {
    if (!module) {
        const char *m = getenv("PTNSS_MODULE");
        module = dlopen(m ? m : "libnss_peios_net.so.2", RTLD_NOW | RTLD_GLOBAL);
        if (!module) { printf("error=dlopen %s\n", dlerror()); exit(3); }
    }
    void *f = dlsym(module, n);
    if (!f) { printf("error=dlsym %s\n", n); exit(3); }
    return f;
}

static char namebuf[512];
static const char *name_arg(const char *a) {
    if (strcmp(a, "@null") == 0) return NULL;
    if (strncmp(a, "@hex:", 5) == 0) {
        const char *h = a + 5;
        size_t i = 0;
        for (; h[0] && h[1] && i < sizeof namebuf - 1; h += 2) {
            unsigned v;
            sscanf(h, "%2x", &v);
            namebuf[i++] = v;
        }
        namebuf[i] = 0;
        return namebuf;
    }
    return a;
}

static void addr_text(int af, const void *a, char *out) {
    if (!inet_ntop(af, a, out, INET6_ADDRSTRLEN)) strcpy(out, "?");
}

#define SENT (-77)

static void print_hostent(int st, int err, int herr, struct hostent *h, int ttl, char *canon) {
    printf("status=%d errno=%d herrno=%d ttl=%d\n", st, err, herr, ttl);
    if (st != NSS_STATUS_SUCCESS) return;
    int ok = inbuf(h->h_name, strlen(h->h_name) + 1) && inbuf(h->h_aliases, sizeof(char *))
          && inbuf(h->h_addr_list, sizeof(char *));
    printf("h_name=%s\n", h->h_name);
    printf("addrtype=%d length=%d\n", h->h_addrtype, h->h_length);
    int na = 0;
    for (char **a = h->h_aliases; a && *a; a++) {
        na++;
        ok = ok && inbuf(a + 1, sizeof(char *)) && inbuf(*a, strlen(*a) + 1);
        printf("alias=%s\n", *a);
    }
    printf("aliases=%d\n", na);
    for (char **a = h->h_addr_list; a && *a; a++) {
        char t[INET6_ADDRSTRLEN];
        ok = ok && inbuf(a + 1, sizeof(char *)) && inbuf(*a, h->h_length);
        addr_text(h->h_length == 16 ? AF_INET6 : AF_INET, *a, t);
        printf("addr=%s\n", t);
    }
    if (canon) printf("canon_is_h_name=%d\n", canon == h->h_name);
    printf("inbuf=%d\n", ok);
}

typedef enum nss_status (*fn4)(const char *, struct gaih_addrtuple **, char *, size_t, int *, int *, int32_t *);
typedef enum nss_status (*fn3)(const char *, int, struct hostent *, char *, size_t, int *, int *, int32_t *, char **);
typedef enum nss_status (*fn2)(const char *, int, struct hostent *, char *, size_t, int *, int *);
typedef enum nss_status (*fn1)(const char *, struct hostent *, char *, size_t, int *, int *);
typedef enum nss_status (*fa2)(const void *, socklen_t, int, struct hostent *, char *, size_t, int *, int *, int32_t *);
typedef enum nss_status (*fa1)(const void *, socklen_t, int, struct hostent *, char *, size_t, int *, int *);

static int op(char **a, int n) {
    const char *o = a[0];
    int err = SENT, herr = SENT;
    int32_t ttl = SENT;
    struct hostent h;
    memset(&h, 0, sizeof h);
    printf("op=%s\n", o);
    if (!strcmp(o, "n4") && n >= 2) {
        fn4 f = sym("_nss_peios_net_gethostbyname4_r");
        struct gaih_addrtuple *pat = NULL;
        begin();
        int st = f(name_arg(a[1]), &pat, buf, buflen, &err, &herr, &ttl);
        end();
        printf("status=%d errno=%d herrno=%d ttl=%d\n", st, err, herr, ttl);
        if (st == NSS_STATUS_SUCCESS) {
            int ok = 1, shared = 1;
            char *first = pat ? pat->name : NULL;
            if (first) { ok = inbuf(first, strlen(first) + 1); printf("name=%s\n", first); }
            for (struct gaih_addrtuple *t = pat; t; t = t->next) {
                char s[INET6_ADDRSTRLEN];
                ok = ok && inbuf(t, sizeof *t);
                if (t->name != first) shared = 0;
                addr_text(t->family, t->addr, s);
                printf("tuple family=%d addr=%s scopeid=%u\n", t->family, s, t->scopeid);
            }
            printf("name_shared=%d\ninbuf=%d\n", shared, ok);
        }
    } else if (!strcmp(o, "n3") && n >= 3) {
        fn3 f = sym("_nss_peios_net_gethostbyname3_r");
        char *canon = (char *)1;
        begin();
        int st = f(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &err, &herr, &ttl, &canon);
        end();
        print_hostent(st, err, herr, &h, ttl, canon);
    } else if (!strcmp(o, "n2") && n >= 3) {
        fn2 f = sym("_nss_peios_net_gethostbyname2_r");
        begin();
        int st = f(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &err, &herr);
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if (!strcmp(o, "n1") && n >= 2) {
        fn1 f = sym("_nss_peios_net_gethostbyname_r");
        begin();
        int st = f(name_arg(a[1]), &h, buf, buflen, &err, &herr);
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if ((!strcmp(o, "a2") || !strcmp(o, "a1")) && n >= 2) {
        unsigned char addr[16];
        int af = AF_INET, len = 4;
        const void *ap = addr;
        memset(addr, 0, sizeof addr);
        if (!strcmp(a[1], "@null")) ap = NULL;
        else if (inet_pton(AF_INET, a[1], addr) == 1) { af = AF_INET; len = 4; }
        else if (inet_pton(AF_INET6, a[1], addr) == 1) { af = AF_INET6; len = 16; }
        else { printf("error=bad address\n"); return 2; }
        if (n >= 4) { af = atoi(a[2]); len = atoi(a[3]); }
        int st;
        if (!strcmp(o, "a2")) {
            fa2 f = sym("_nss_peios_net_gethostbyaddr2_r");
            begin();
            st = f(ap, len, af, &h, buf, buflen, &err, &herr, &ttl);
        } else {
            fa1 f = sym("_nss_peios_net_gethostbyaddr_r");
            begin();
            st = f(ap, len, af, &h, buf, buflen, &err, &herr);
        }
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if (!strcmp(o, "gai") && n >= 3) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = atoi(a[2]);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;
        begin();
        int r = getaddrinfo(name_arg(a[1]), NULL, &hints, &res);
        end();
        printf("gai=%d gaistr=%s\n", r, gai_strerror(r));
        int k = 0;
        for (struct addrinfo *i = res; i; i = i->ai_next) {
            char s[INET6_ADDRSTRLEN];
            if (i->ai_canonname) printf("canon=%s\n", i->ai_canonname);
            if (i->ai_family == AF_INET) addr_text(AF_INET, &((struct sockaddr_in *)i->ai_addr)->sin_addr, s);
            else addr_text(AF_INET6, &((struct sockaddr_in6 *)i->ai_addr)->sin6_addr, s);
            printf("addr=%s\n", s);
            k++;
        }
        printf("count=%d\n", k);
        if (res) freeaddrinfo(res);
    } else if (!strcmp(o, "ghbn") && n >= 3) {
        struct hostent *res = NULL;
        int he = SENT;
        begin();
        int r = gethostbyname2_r(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &res, &he);
        end();
        printf("ret=%d herrno=%d found=%d\n", r, he, res != NULL);
        h_errno = SENT;
        struct hostent *g = gethostbyname2(name_arg(a[1]), atoi(a[2]));
        int k = 0;
        if (g) for (char **x = g->h_addr_list; *x; x++) k++;
        printf("growing_found=%d growing_herrno=%d growing_count=%d\n", g != NULL, g ? 0 : h_errno, k);
    } else if (!strcmp(o, "ghba") && n >= 2) {
        unsigned char addr[16];
        int af = AF_INET, len = 4;
        if (inet_pton(AF_INET, a[1], addr) != 1) { af = AF_INET6; len = 16; inet_pton(AF_INET6, a[1], addr); }
        h_errno = SENT;
        begin();
        struct hostent *g = gethostbyaddr(addr, len, af);
        end();
        printf("found=%d herrno=%d\n", g != NULL, g ? 0 : h_errno);
        if (g) printf("h_name=%s\n", g->h_name);
    } else if (!strcmp(o, "cfg") && n >= 3) {
        printf("ret=%d\n", __nss_configure_lookup(a[1], a[2]));
    } else if (!strcmp(o, "where")) {
        void *m = dlopen("libnss_peios_net.so.2", RTLD_NOW | RTLD_NOLOAD);
        void *c = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
        struct link_map *lm;
        if (m && dlinfo(m, RTLD_DI_LINKMAP, &lm) == 0) printf("module=%s\n", lm->l_name);
        else printf("module=(not loaded)\n");
        if (c && dlinfo(c, RTLD_DI_LINKMAP, &lm) == 0) printf("libc=%s\n", lm->l_name);
    } else if (!strcmp(o, "elf") && n >= 2) {
        FILE *f = fopen(a[1], "rb");
        if (!f) { printf("error=open %s\n", strerror(errno)); return 2; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz);
        if (fread(b, 1, sz, f) != (size_t)sz) { printf("error=read\n"); return 2; }
        fclose(f);
        Elf64_Ehdr *e = (void *)b;
        Elf64_Shdr *s = (void *)(b + e->e_shoff);
        for (int i = 0; i < e->e_shnum; i++) {
            if (s[i].sh_type == SHT_DYNAMIC) {
                const char *str = (const char *)b + s[s[i].sh_link].sh_offset;
                for (Elf64_Dyn *d = (void *)(b + s[i].sh_offset); d->d_tag != DT_NULL; d++) {
                    if (d->d_tag == DT_NEEDED) printf("needed=%s\n", str + d->d_un.d_val);
                    if (d->d_tag == DT_SONAME) printf("soname=%s\n", str + d->d_un.d_val);
                }
            }
            if (s[i].sh_type == SHT_DYNSYM) {
                const char *str = (const char *)b + s[s[i].sh_link].sh_offset;
                Elf64_Sym *y = (void *)(b + s[i].sh_offset);
                size_t k = s[i].sh_size / sizeof *y;
                for (size_t j = 0; j < k; j++) {
                    int bind = ELF64_ST_BIND(y[j].st_info), type = ELF64_ST_TYPE(y[j].st_info);
                    if (y[j].st_shndx != SHN_UNDEF && (bind == STB_GLOBAL || bind == STB_WEAK)
                        && ELF64_ST_VISIBILITY(y[j].st_other) == STV_DEFAULT)
                        printf("export=%s type=%s\n", str + y[j].st_name, type == STT_FUNC ? "func" : "other");
                }
            }
        }
        free(b);
    } else if (!strcmp(o, "wait") && n >= 2) {
        struct stat st;
        for (int i = 0; i < 600 && stat(a[1], &st) != 0; i++) usleep(50000);
        printf("waited=%d\n", stat(a[1], &st) == 0);
    } else if (!strcmp(o, "touch") && n >= 2) {
        FILE *f = fopen(a[1], "w");
        if (f) fclose(f);
        printf("touched=%d\n", f != NULL);
    } else if (!strcmp(o, "sleep") && n >= 2) {
        usleep(atoi(a[1]) * 1000);
    } else {
        printf("error=bad op\n");
        return 2;
    }
    fflush(stdout);
    return 0;
}

static pid_t fake_pid;
static char fake_path[108];

static void fake(const char *mode) {
    snprintf(fake_path, sizeof fake_path, "/tmp/ptnss-%d.sock", getpid());
    unlink(fake_path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un u;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    strcpy(u.sun_path, fake_path);
    if (bind(ls, (void *)&u, sizeof u) || listen(ls, 8)) { printf("error=fake bind %s\n", strerror(errno)); exit(3); }
    fflush(stdout);
    fake_pid = fork();
    if (fake_pid == 0) {
        in_child = 1;
        for (;;) {
            int c = accept(ls, NULL, NULL);
            if (c < 0) continue;
            unsigned char hdr[4];
            size_t got = 0;
            while (got < 4) { ssize_t r = read(c, hdr + got, 4 - got); if (r <= 0) break; got += r; }
            uint32_t len = hdr[0] | hdr[1] << 8 | hdr[2] << 16 | (uint32_t)hdr[3] << 24;
            char tmp[4096];
            while (got >= 4 && len > 0) { ssize_t r = read(c, tmp, len < sizeof tmp ? len : sizeof tmp); if (r <= 0) break; len -= r; }
            if (!strcmp(mode, "silent")) { sleep(60); }
            else if (!strncmp(mode, "hex:", 4)) {
                const char *h = mode + 4;
                size_t k = strlen(h) / 2;
                unsigned char *o = malloc(k + 1);
                for (size_t i = 0; i < k; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = v; }
                size_t off = 0;
                while (off < k) { ssize_t r = write(c, o + off, k - off); if (r <= 0) break; off += r; }
                free(o);
            }
            close(c);
        }
    }
    close(ls);
    strcpy(redirect, fake_path);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    if (getenv("PTNSS_BUF")) buflen = strtoul(getenv("PTNSS_BUF"), NULL, 0);
    if (getenv("PTNSS_FAKE")) fake(getenv("PTNSS_FAKE"));
    int rc = 0, i = 1;
    while (i < argc) {
        int j = i;
        while (j < argc && strcmp(argv[j], "+")) j++;
        rc |= op(argv + i, j - i);
        i = j + 1;
    }
    fflush(stdout);
    if (fake_pid > 0) { kill(fake_pid, SIGKILL); waitpid(fake_pid, NULL, 0); unlink(fake_path); }
    return rc;
}
]==]

--- Compile pt-nss on the host, dynamically, and return it as a `files`
--- entry for the boot.
local function build_pt_nss()
    local base = os.tmpname()
    local src, bin = base .. ".c", base .. ".bin"
    local f = assert(io.open(src, "w"))
    f:write(PT_NSS_C)
    f:close()
    local ok = os.execute("cc -O2 -rdynamic -o '" .. bin .. "' '" .. src .. "' -ldl")
    assert(ok, "pt-nss: the host could not compile the instrument")
    local b = assert(io.open(bin, "rb"), "pt-nss: no binary")
    local bytes = b:read("a")
    b:close()
    os.remove(src)
    os.remove(bin)
    os.remove(base)
    return { ["usr/bin/pt-nss"] = { bytes, exec = true } }
end

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

local SOCK = "/run/resolvd/resolv.sock"
local MODULE = "/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2"
local NSS = { SUCCESS = 1, NOTFOUND = 0, UNAVAIL = -1, TRYAGAIN = -2 }
local E = { ENOENT = 2, EAGAIN = 11, ERANGE = 34, EAFNOSUPPORT = 97 }
local H = { HOST_NOT_FOUND = 1, TRY_AGAIN = 2, NO_RECOVERY = 3, NO_DATA = 4, NETDB_INTERNAL = -1 }
local AF = { UNSPEC = 0, UNIX = 1, INET = 2, INET6 = 10 }
local ENTRY_POINTS = {
    "_nss_peios_net_gethostbyaddr2_r", "_nss_peios_net_gethostbyaddr_r",
    "_nss_peios_net_gethostbyname2_r", "_nss_peios_net_gethostbyname3_r",
    "_nss_peios_net_gethostbyname4_r", "_nss_peios_net_gethostbyname_r",
}

-- The static names (Dns\Hosts). `many` is 120 IPv4 addresses: more than
-- fit glibc's first 1024-byte buffer as a hostent (getaddrinfo's AF_INET
-- path, gethostbyname2) or as address tuples (getaddrinfo's AF_UNSPEC
-- path), so each of them must grow its buffer to answer.
local MANY_N = 120
local MANY = {}
for i = 1, MANY_N do MANY[i] = "10.89." .. (i // 100) .. "." .. (i % 100) end
local HOSTS = {
    ["both.nss.test"] = "multi:10.88.0.1,fd88::1,10.88.0.2,fd88::2",
    ["v4only.nss.test"] = "sz:10.88.0.5",
    ["ll.nss.test"] = "sz:fe80::5",
    ["change.nss.test"] = "sz:10.88.0.7",
    ["many.nss.test"] = "multi:" .. table.concat(MANY, ","),
}

-- The gateway's zone, for the claims that need TTLs, CNAMEs and PTRs.
local ZONE = {
    ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
    ["alias.example.test"] = { { type = "CNAME", ttl = 30, data = "www.example.test" } },
    ["ttl.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" },
                             { type = "A", ttl = 120, data = "10.77.0.82" },
                             { type = "AAAA", ttl = 200, data = "fd77::81" } },
    -- The same, under a name only one test asks, so its TTLs are not
    -- lowered by a cache hit.
    ["ttl4.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" },
                              { type = "A", ttl = 120, data = "10.77.0.82" },
                              { type = "AAAA", ttl = 200, data = "fd77::81" } },
    ["81.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 400, data = "ptr-one.example.test" },
                                    { type = "PTR", ttl = 200, data = "ptr-two.example.test" } },
    ["82.0.77.10.in-addr.arpa"] = { { type = "CNAME", ttl = 30, data = "82.sub.0.77.10.in-addr.arpa" } },
    ["82.sub.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 300, data = "classless.example.test" } },
    ["83.0.77.10.in-addr.arpa"] = { { type = "CNAME", ttl = 30, data = "83.gone.example.test" } },
    ["83.gone.example.test"] = { { type = "TXT", ttl = 30, data = "no ptr here" } },
    ["84.0.77.10.in-addr.arpa"] = { { type = "TXT", ttl = 30, data = "no ptr here" } },
}

-- ---------------------------------------------------------------------------
-- The pair
-- ---------------------------------------------------------------------------

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
dns.serve(gw, {
    zone = ZONE,
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q)
        -- A server that never answers this name: resolvd's attempts run
        -- out and the lookup is `unavailable`.
        if q.questions[1] and dns.same_name(q.questions[1].name, "slow.example.test") then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw, files = build_pt_nss() })

-- ---------------------------------------------------------------------------
-- Talking to resolvd and running pt-nss
-- ---------------------------------------------------------------------------

local function native(req) return network.call(sut, req, { path = SOCK, timeout_ms = 5000 }) end

local function addresses_of(reply)
    local out = {}
    for _, a in ipairs((reply and reply.addresses) or {}) do out[#out + 1] = a.address end
    return out
end

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

-- The static names, at file scope: every test below reads them.
network.write(sut, "Dns", {})
network.write(sut, "Dns\\Hosts", HOSTS)
wait_until(function()
    local a = native({ query = "lookup", name = "many.nss.test", family = "inet" })
    local b = native({ query = "lookup", name = "both.nss.test", family = "any" })
    return a and #addresses_of(a) == MANY_N and b and #addresses_of(b) == 4
end, { timeout = 30, interval = 0.3, desc = "resolvd answering the static names" })

--- Run `cmd` in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

--- One length-prefixed native message from its bytes, decoded.
local function message(bytes)
    if #bytes < 4 then return nil end
    local n = string.unpack("<I4", bytes)
    if #bytes < 4 + n then return nil end
    local ok, m = pcall(msgpack.decode, bytes:sub(5, 4 + n))
    return ok and m or nil
end

--- A native frame, as hex, for PTNSS_FAKE.
local function frame_hex(payload)
    if type(payload) == "table" then payload = msgpack.encode(payload) end
    return hex(string.pack("<I4", #payload) .. payload)
end

local function parse(out)
    local ops, cur = {}, nil
    for line in out:gmatch("[^\n]+") do
        local o = line:match("^op=(%S+)$")
        if o then
            cur = { op = o, addrs = {}, alias_list = {}, tuples = {}, trace = {}, sockets = {}, connects = {},
                    closes = {}, opens = {}, inet_sends = {}, timeouts = {}, exports = {}, needed = {},
                    sent = "", got = "", recv_errors = {} }
            ops[#ops + 1] = cur
        elseif cur and line:match("^t ") then
            cur.trace[#cur.trace + 1] = line
            local kind = line:match("^t (%S+)")
            local f = {}
            for k, v in line:gmatch("(%S+)=(%S*)") do f[k] = tonumber(v) or v end
            f.hex = line:match(" hex=(%x+)$")
            if kind == "send" and f.hex then cur.sent = cur.sent .. unhex(f.hex)
            elseif kind == "recv" and f.hex then cur.got = cur.got .. unhex(f.hex)
            elseif kind == "recv" then cur.recv_errors[#cur.recv_errors + 1] = f
            elseif kind == "socket" then cur.sockets[#cur.sockets + 1] = f
            elseif kind == "connect" then cur.connects[#cur.connects + 1] = f
            elseif kind == "close" then cur.closes[#cur.closes + 1] = f
            elseif kind == "open" then cur.opens[#cur.opens + 1] = line:match("path=(.*)$")
            elseif kind == "sendto" or kind == "sendmsg" then cur.inet_sends[#cur.inet_sends + 1] = f
            elseif kind == "setsockopt" and f.opt then cur.timeouts[f.opt] = f end
        elseif cur and line:match("^tuple ") then
            local f = {}
            for k, v in line:gmatch("(%S+)=(%S*)") do f[k] = tonumber(v) or v end
            cur.tuples[#cur.tuples + 1] = f
        elseif cur and line:match("^addr=") then cur.addrs[#cur.addrs + 1] = line:sub(6)
        elseif cur and line:match("^alias=") then cur.alias_list[#cur.alias_list + 1] = line:sub(7)
        elseif cur and line:match("^needed=") then cur.needed[#cur.needed + 1] = line:sub(8)
        elseif cur and line:match("^export=") then
            local name, ty = line:match("^export=(%S+) type=(%S+)")
            cur.exports[#cur.exports + 1] = { name = name, type = ty }
        elseif cur and line:match("^gai=") then
            local code, text = line:match("^gai=(%-?%d+) gaistr=(.*)$")
            cur.gai, cur.gaistr = tonumber(code), text
        elseif cur and line:find(" [%w_]+=") then
            for k, v in line:gmatch("([%w_]+)=(%S*)") do cur[k] = tonumber(v) or v end
        elseif cur then
            local k, v = line:match("^([%w_]+)=(.*)$")
            if k then cur[k] = tonumber(v) or v end
        end
    end
    for _, r in ipairs(ops) do
        r.request = message(r.sent)
        r.reply = message(r.got)
    end
    return ops
end

--- Run pt-nss with `ops` (a list of argument lists). `o.buf`, `o.fake`
--- (a PTNSS_FAKE value), `o.serve` (pump the gateway while it runs),
--- `o.timeout`. Returns the parsed results, one per op.
local function pt(t, ops, o)
    o = o or {}
    local args = {}
    for i, op in ipairs(ops) do
        if i > 1 then args[#args + 1] = "+" end
        for _, a in ipairs(op) do args[#args + 1] = quote(a) end
    end
    local env = ""
    if o.buf then env = env .. "PTNSS_BUF=" .. o.buf .. " " end
    if o.fake then env = env .. "PTNSS_FAKE=" .. o.fake .. " " end
    local cmd = env .. "pt-nss " .. table.concat(args, " ")
    local r
    if o.serve then r = served(cmd, o.timeout) else r = sut:run(cmd, { timeout = o.timeout or 60 }) end
    t:log("$ " .. cmd .. "\n" .. r.stdout .. (r.stderr ~= "" and ("stderr: " .. r.stderr) or ""))
    t:assert(not r.stdout:find("\nerror=", 1, true) and not r.stdout:find("^error="),
        "pt-nss ran every op (exit " .. tostring(r.exit_code) .. ")")
    local out = parse(r.stdout)
    t:assert_eq(#out, #ops, "pt-nss reported every op")
    return out
end

--- Assert an NSS result's status, errno and h_errno.
local function expect(t, r, status, errno, herrno, what)
    t:assert_eq(r.status, status, what .. ": NSS status")
    t:assert_eq(r.errno, errno, what .. ": errno")
    t:assert_eq(r.herrno, herrno, what .. ": h_errno")
end

--- The call made no socket at all.
local function no_socket(t, r, what)
    t:assert_eq(#r.sockets, 0, what .. ": no socket was opened")
    t:assert_eq(#r.connects, 0, what .. ": nothing was connected to")
end

--- The call opened exactly one connection, to resolvd's socket, and
--- closed it before returning.
local function one_connection(t, r, what)
    t:assert_eq(#r.sockets, 1, what .. ": one socket")
    t:assert_eq(r.sockets[1] and r.sockets[1].family, 1, what .. ": an AF_UNIX socket")
    t:assert_eq(#r.connects, 1, what .. ": one connect")
    t:assert_eq(r.connects[1] and r.connects[1].path, SOCK, what .. ": to " .. SOCK)
    t:assert_eq(#r.closes, 1, what .. ": one close")
    t:assert_eq(r.closes[1] and r.closes[1].fd, r.sockets[1] and r.sockets[1].ret, what .. ": of that socket")
    t:assert_eq(r.sockets_left, 0, what .. ": no socket left open after the call")
end

local function same_list(t, got, want, what)
    t:assert_eq(list(got), list(want), what)
end

--- Wait for the interface's scope to carry the gateway as its server.
local function scope_ready(t)
    local ok = wait_until(function()
        local s = native({ query = "status" })
        for _, sc in ipairs((s and s.scopes) or {}) do
            for _, sv in ipairs(sc.servers or {}) do
                if sv == "10.77.0.1" then return true end
            end
        end
        -- Keep the gateway answering DHCP while we wait.
        gw:pump(100)
        return false
    end, { timeout = 60, interval = 0.2, desc = "a scope with the gateway as its server" })
    t:assert(ok ~= false, "resolvd has a scope whose server is the gateway")
end

-- ---------------------------------------------------------------------------
-- §7.1 the object
-- ---------------------------------------------------------------------------

test("the module is installed by dev.peios.resolvd-nss at the TRM's path, with SONAME libnss_peios_net.so.2, in the directory glibc's own libc is loaded from, and glibc loads it from there",
    { spec = "resolvd *nss-module.installed-path PSPU *nri-shim.soname-and-location" }, function(t)
        local owns = sut:run("peipkg owns " .. MODULE)
        t:log("peipkg owns: exit " .. owns.exit_code .. "\n" .. owns.stdout .. owns.stderr)
        t:assert_eq(owns.exit_code, 0, "peipkg knows the file")
        t:assert(owns.stdout:find("dev.peios.resolvd-nss", 1, true), "the owning package is dev.peios.resolvd-nss")

        local r = pt(t, { { "elf", MODULE }, { "gai", "localhost", "0" }, { "where" } })
        t:assert_eq(r[1].soname, "libnss_peios_net.so.2", "the SONAME")
        t:assert_eq(r[2].gai, 0, "getaddrinfo(localhost) succeeds, so glibc has loaded the hosts module")
        t:assert(r[3].module ~= "(not loaded)" and r[3].module, "glibc loaded libnss_peios_net.so.2")
        local real = sut:run("readlink -f " .. quote(r[3].module) .. " " .. quote(r[3].libc))
        local mod_path, libc_path = real.stdout:match("^(%S+)\n(%S+)")
        t:log("glibc loaded the module from " .. tostring(mod_path) .. "; libc is " .. tostring(libc_path))
        t:assert_eq(mod_path, MODULE, "glibc loaded the installed file")
        t:assert_eq(mod_path and mod_path:match("^(.*)/"), libc_path and libc_path:match("^(.*)/"),
            "the module is in libc's own library directory")
    end)

test("the module exports the six entry points and no other symbol, and each asks resolvd what the TRM's table says",
    { spec = "resolvd *nss-module.entry-points PSPU *nri-shim.entry-points" }, function(t)
        local r = pt(t, {
            { "elf", MODULE },
            { "n4", "both.nss.test" },
            { "n3", "both.nss.test", "2" }, { "n3", "both.nss.test", "10" },
            { "n2", "both.nss.test", "2" }, { "n2", "both.nss.test", "10" },
            { "n1", "both.nss.test" },
            { "a2", "10.88.0.1" }, { "a1", "10.88.0.1" },
        })
        local names = {}
        for _, e in ipairs(r[1].exports) do
            names[#names + 1] = e.name
            t:assert_eq(e.type, "func", e.name .. " is a function")
        end
        table.sort(names)
        same_list(t, names, ENTRY_POINTS, "the exported symbols are exactly the six entry points")

        local function asks(i, what, want)
            local q = r[i].request
            t:assert(q, what .. ": a request was written")
            for k, v in pairs(want) do t:assert_eq(q[k], v, what .. ": request " .. k) end
            local n = 0
            for _ in pairs(q) do n = n + 1 end
            local m = 0
            for _ in pairs(want) do m = m + 1 end
            t:assert_eq(n, m, what .. ": the request has no other field")
            t:assert_eq(r[i].status, NSS.SUCCESS, what .. ": answered")
        end
        asks(2, "gethostbyname4_r", { query = "lookup", name = "both.nss.test", family = "any" })
        asks(3, "gethostbyname3_r AF_INET", { query = "lookup", name = "both.nss.test", family = "inet" })
        asks(4, "gethostbyname3_r AF_INET6", { query = "lookup", name = "both.nss.test", family = "inet6" })
        asks(5, "gethostbyname2_r AF_INET", { query = "lookup", name = "both.nss.test", family = "inet" })
        asks(6, "gethostbyname2_r AF_INET6", { query = "lookup", name = "both.nss.test", family = "inet6" })
        asks(7, "gethostbyname_r", { query = "lookup", name = "both.nss.test", family = "inet" })
        t:assert_eq(r[7].addrtype, AF.INET, "gethostbyname_r answers AF_INET")
        asks(8, "gethostbyaddr2_r", { query = "reverse", address = "10.88.0.1" })
        asks(9, "gethostbyaddr_r", { query = "reverse", address = "10.88.0.1" })
        -- gethostbyname3_r reports a TTL and canonical name; 2_r and _r
        -- have no such out-parameters; gethostbyaddr2_r reports a TTL and
        -- gethostbyaddr_r none (pt-nss's -77 is left in place).
        t:assert_eq(r[3].ttl, 0, "gethostbyname3_r writes the TTL (a static name's is 0)")
        t:assert_eq(r[3].canon_is_h_name, 1, "gethostbyname3_r points canonp at h_name")
        t:assert_eq(r[5].ttl, -77, "gethostbyname2_r has no TTL out")
        t:assert_eq(r[8].ttl, 0, "gethostbyaddr2_r writes the TTL")
        t:assert_eq(r[9].ttl, -77, "gethostbyaddr_r has no TTL out")
    end)

test("the module needs libgcc_s.so.1, libc.so.6 and ld-linux-x86-64.so.2, and not libpeios; the codec is compiled in",
    { spec = "resolvd *nss-module.link-dependencies" }, function(t)
        -- PEI-1374: libgcc_s.so.1 is needed as well as libc and the loader,
        -- so every resolving process also loads GCC's runtime. This test
        -- asserts the module as built; the PSPU test below asserts the spec.
        local r = pt(t, { { "elf", MODULE } })
        t:log("needed: " .. list(r[1].needed))
        t:assert(#r[1].needed > 0, "the module's dynamic section was read")
        local needed = {}
        for i, n in ipairs(r[1].needed) do
            needed[i] = n
            t:assert(not n:find("peios", 1, true), "it does not link libpeios (" .. n .. ")")
        end
        table.sort(needed)
        t:assert_eq(table.concat(needed, " "), "ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1",
            "exactly libgcc_s, libc and the dynamic loader")
    end)

test("the shim links against libc and the wire codec and nothing else",
    { spec = "PSPU *nri-shim.links-libc-and-codec-only", tags = { "known-bug" } }, function(t)
        -- PEI-1374: libnss_peios_net.so.2 NEEDs
        -- libgcc_s.so.1 as well as libc.so.6 and ld-linux-x86-64.so.2, so
        -- every resolving process also loads GCC's runtime.
        local r = pt(t, { { "elf", MODULE } })
        t:log("needed: " .. list(r[1].needed))
        t:assert(#r[1].needed > 0, "the module's dynamic section was read")
        for _, n in ipairs(r[1].needed) do
            t:assert(n == "libc.so.6" or n == "ld-linux-x86-64.so.2",
                "needed " .. n .. " is libc (the codec is compiled in)")
        end
    end)

-- ---------------------------------------------------------------------------
-- localhost and loopback, in the process
-- ---------------------------------------------------------------------------

test("localhost, a name under it and a loopback address are answered with no socket: 127.0.0.1 then ::1, canonical localhost, TTL 0; h_name localhost with no aliases for the reverse",
    { spec = "resolvd *nss-forward.localhost-answer PSPU *nri-shim.answers-localhost-itself resolvd *nss-reverse.loopback-answered-in-process" }, function(t)
        local r = pt(t, {
            { "n4", "localhost" }, { "n4", "LOCALHOST." }, { "n4", "printer.Localhost" },
            { "n3", "localhost", "2" }, { "n3", "localhost", "10" },
            { "a2", "127.0.0.1" }, { "a2", "127.9.8.7" }, { "a2", "::1" },
        })
        for i = 1, 3 do
            local x = r[i]
            no_socket(t, x, x.op .. " #" .. i)
            t:assert_eq(x.status, NSS.SUCCESS, "#" .. i .. " found")
            t:assert_eq(#x.tuples, 2, "#" .. i .. " two addresses")
            t:assert_eq(x.tuples[1] and x.tuples[1].addr, "127.0.0.1", "#" .. i .. " IPv4 first")
            t:assert_eq(x.tuples[2] and x.tuples[2].addr, "::1", "#" .. i .. " then IPv6")
            t:assert_eq(x.name, "localhost", "#" .. i .. " canonical localhost")
            t:assert_eq(x.ttl, 0, "#" .. i .. " TTL 0")
        end
        for i, want in pairs({ [4] = "127.0.0.1", [5] = "::1" }) do
            no_socket(t, r[i], "gethostbyname3_r #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, "#" .. i .. " found")
            same_list(t, r[i].addrs, { want }, "#" .. i .. " the one address of the family")
            t:assert_eq(r[i].h_name, "localhost", "#" .. i .. " h_name")
            t:assert_eq(r[i].ttl, 0, "#" .. i .. " TTL 0")
        end
        for i = 6, 8 do
            no_socket(t, r[i], "gethostbyaddr2_r #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, "#" .. i .. " found")
            t:assert_eq(r[i].h_name, "localhost", "#" .. i .. " h_name localhost")
            t:assert_eq(r[i].aliases, 0, "#" .. i .. " no aliases")
            t:assert_eq(r[i].ttl, 0, "#" .. i .. " TTL 0")
        end
    end)

-- ---------------------------------------------------------------------------
-- found: the hostent and the address tuples
-- ---------------------------------------------------------------------------

test("a found name is SUCCESS; the tuples and the hostent carry the reply's addresses in reply order, one tuple each with its own family and one shared name; the hostent's h_name is the reply's canonical name, with no aliases",
    { spec = "resolvd *nss-module.found-is-success PSPU *nri-shim.found-is-success resolvd *nss-forward.hostent-layout resolvd *nss-forward.reply-order-kept resolvd *nss-forward.gaih-addrtuple-order resolvd *nss-forward.gaih-addrtuple-name-shared resolvd *nss-forward.gaih-addrtuple-family" }, function(t)
        local r = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" }, { "n2", "both.nss.test", "10" } })
        local n4, n3, n2 = r[1], r[2], r[3]
        for _, x in ipairs(r) do
            t:assert_eq(x.status, NSS.SUCCESS, x.op .. ": SUCCESS")
            t:assert(x.reply and x.reply.outcome == "found", x.op .. ": resolvd said found")
        end
        local reply4 = addresses_of(n4.reply)
        local got4 = {}
        for _, tu in ipairs(n4.tuples) do
            got4[#got4 + 1] = tu.addr
            t:assert_eq(tu.family, tu.addr:find(":", 1, true) and AF.INET6 or AF.INET, tu.addr .. ": its own family")
        end
        same_list(t, got4, reply4, "one tuple per address, in the reply's order")
        t:assert_eq(#got4, 4, "all four addresses")
        t:assert_eq(n4.name_shared, 1, "every tuple points at one copy of the name")
        t:assert_eq(n4.name, n4.reply.canonical, "the name is the reply's canonical name")

        same_list(t, n3.addrs, addresses_of(n3.reply), "gethostbyname3_r: h_addr_list in the reply's order")
        same_list(t, n3.addrs, { "10.88.0.1", "10.88.0.2" }, "gethostbyname3_r AF_INET: both IPv4 addresses")
        t:assert_eq(n3.h_name, n3.reply.canonical, "h_name is the reply's canonical name")
        t:assert_eq(n3.aliases, 0, "h_aliases is empty")
        t:assert_eq(n3.addrtype, AF.INET, "h_addrtype is the af asked")
        t:assert_eq(n3.length, 4, "h_length 4")

        same_list(t, n2.addrs, addresses_of(n2.reply), "gethostbyname2_r AF_INET6: reply order")
        same_list(t, n2.addrs, { "fd88::1", "fd88::2" }, "both IPv6 addresses")
        t:assert_eq(n2.addrtype, AF.INET6, "h_addrtype AF_INET6")
        t:assert_eq(n2.length, 16, "h_length 16")
        t:assert_eq(n2.aliases, 0, "h_aliases is empty")
    end)

test("an IPv6 link-local address comes back in a tuple with scope id 0",
    { spec = "resolvd *nss-forward.gaih-addrtuple-scopeid-zero" }, function(t)
        local r = pt(t, { { "n4", "ll.nss.test" } })[1]
        t:assert_eq(r.status, NSS.SUCCESS, "found")
        t:assert_eq(#r.tuples, 1, "one address")
        t:assert_eq(r.tuples[1].addr, "fe80::5", "the link-local address")
        t:assert_eq(r.tuples[1].family, AF.INET6, "AF_INET6")
        t:assert_eq(r.tuples[1].scopeid, 0, "scope id 0")
    end)

-- ---------------------------------------------------------------------------
-- found, but not in the family asked
-- ---------------------------------------------------------------------------

test("a name resolvd finds with no address of the family asked is NOTFOUND, ENOENT, HOST_NOT_FOUND, as a name that does not exist",
    { spec = "resolvd *nss-module.found-without-family-is-host-not-found" }, function(t)
        -- PEI-1345: the spec wants NO_DATA here; the TRM records HOST_NOT_FOUND.
        local r = pt(t, { { "n3", "v4only.nss.test", "10" }, { "n2", "v4only.nss.test", "10" } })
        for _, x in ipairs(r) do
            t:assert(x.reply and x.reply.outcome == "found", x.op .. ": resolvd said found")
            t:assert_eq(#addresses_of(x.reply), 0, x.op .. ": with no IPv6 address")
            expect(t, x, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, x.op)
        end
    end)

test("a found name with no address of the family asked is NOTFOUND with NO_DATA",
    { spec = "PSPU *nri-shim.found-without-family-is-no-data", tags = { "known-bug" } }, function(t)
        -- PEI-1345: the shim gives HOST_NOT_FOUND, the h_errno of a name
        -- that does not exist.
        local r = pt(t, { { "n3", "v4only.nss.test", "10" } })[1]
        t:assert(r.reply and r.reply.outcome == "found" and #addresses_of(r.reply) == 0,
            "resolvd said found, with no IPv6 address")
        t:assert_eq(r.status, NSS.NOTFOUND, "NOTFOUND")
        t:assert_eq(r.herrno, H.NO_DATA, "h_errno NO_DATA")
    end)

-- ---------------------------------------------------------------------------
-- Families, bad input, buffers
-- ---------------------------------------------------------------------------

test("an unsupported family is UNAVAIL with EAFNOSUPPORT: NO_DATA forward (AF_UNSPEC too, except through gethostbyname4_r, which asks for both), NO_RECOVERY in reverse for any af/length but AF_INET/4 and AF_INET6/16",
    { spec = "resolvd *nss-module.unsupported-family-forward resolvd *nss-module.af-unspec-only-via-gethostbyname4 resolvd *nss-module.unsupported-family-reverse" }, function(t)
        local r = pt(t, {
            { "n3", "both.nss.test", "1" }, { "n2", "both.nss.test", "1" },
            { "n3", "both.nss.test", "0" }, { "n2", "both.nss.test", "0" },
            { "n4", "both.nss.test" },
            { "a2", "10.88.0.1", "2", "16" }, { "a2", "10.88.0.1", "10", "4" },
            { "a1", "10.88.0.1", "1", "4" }, { "a2", "10.88.0.1", "0", "4" },
        })
        for i = 1, 4 do
            expect(t, r[i], NSS.UNAVAIL, E.EAFNOSUPPORT, H.NO_DATA, r[i].op .. " af " .. (i <= 2 and "AF_UNIX" or "AF_UNSPEC"))
            no_socket(t, r[i], r[i].op .. " #" .. i)
        end
        t:assert_eq(r[5].status, NSS.SUCCESS, "gethostbyname4_r answers")
        t:assert_eq(r[5].request and r[5].request.family, "any", "gethostbyname4_r asks for family any")
        local fams = {}
        for _, tu in ipairs(r[5].tuples) do fams[tu.family] = true end
        t:assert(fams[AF.INET] and fams[AF.INET6], "and returns both families")
        for i = 6, 9 do
            expect(t, r[i], NSS.UNAVAIL, E.EAFNOSUPPORT, H.NO_RECOVERY, r[i].op .. " #" .. i)
            no_socket(t, r[i], r[i].op .. " #" .. i)
        end
    end)

test("a null name, a name that is not UTF-8 and a null address are NOTFOUND, ENOENT, HOST_NOT_FOUND",
    { spec = "resolvd *nss-module.null-or-non-utf8-input-is-notfound" }, function(t)
        local r = pt(t, {
            { "n4", "@null" }, { "n3", "@null", "2" }, { "n1", "@null" },
            { "n4", "@hex:ff2e6e73732e74657374" }, { "n3", "@hex:c3286e7373", "2" },
            { "a2", "@null" }, { "a1", "@null" },
        })
        for i, x in ipairs(r) do expect(t, x, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, x.op .. " #" .. i) end
    end)

test("a buffer too small for the result is TRYAGAIN, ERANGE, h_errno 0; everything a successful call returns lies inside the caller's buffer",
    { spec = "resolvd *nss-module.small-buffer-is-erange resolvd *nss-module.results-placed-in-caller-buffer" }, function(t)
        local small = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "10" }, { "a2", "10.88.0.1" },
                              { "n1", "localhost" } }, { buf = 16 })
        for i, x in ipairs(small) do expect(t, x, NSS.TRYAGAIN, E.ERANGE, 0, x.op .. " #" .. i .. " with a 16-byte buffer") end
        local ok = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "10" }, { "a2", "10.88.0.1" },
                           { "n4", "many.nss.test" } })
        for i, x in ipairs(ok) do
            t:assert_eq(x.status, NSS.SUCCESS, x.op .. " #" .. i .. " found")
            t:assert_eq(x.inbuf, 1, x.op .. " #" .. i .. ": every name, pointer array, address and tuple is in the buffer")
        end
        t:assert_eq(#ok[4].tuples, MANY_N, "the " .. MANY_N .. "-address name fits a 64 KiB buffer")
    end)

test("an over-full caller buffer is TRYAGAIN with ERANGE, so glibc retries with a larger one",
    { spec = "PSPU *nri-shim.over-full-buffer-is-tryagain-erange", tags = { "known-bug" } }, function(t)
        -- PEI-1341: the shim sets h_errno 0 rather than NETDB_INTERNAL, and
        -- glibc grows its buffer only for TRYAGAIN + ERANGE + NETDB_INTERNAL,
        -- so a name whose answer outgrows glibc's first buffer fails.
        local direct = pt(t, { { "n4", "many.nss.test" } }, { buf = 64 })[1]
        t:assert_eq(direct.status, NSS.TRYAGAIN, "the module answers an over-full buffer TRYAGAIN")
        t:assert_eq(direct.errno, E.ERANGE, "with ERANGE")
        t:log("h_errno with it: " .. tostring(direct.herrno) .. " (glibc retries only on NETDB_INTERNAL, -1)")
        local r = pt(t, { { "gai", "many.nss.test", "0" }, { "gai", "many.nss.test", "2" },
                          { "ghbn", "many.nss.test", "2" } }, { buf = 64 })
        for i = 1, 2 do
            t:log("getaddrinfo #" .. i .. ": " .. tostring(r[i].gai) .. " " .. tostring(r[i].gaistr) .. ", "
                .. tostring(r[i].count) .. " addresses")
        end
        t:log("gethostbyname2_r with a 64-byte buffer: ret " .. tostring(r[3].ret) .. ", h_errno " .. tostring(r[3].herrno)
            .. "; gethostbyname2: found " .. tostring(r[3].growing_found) .. ", h_errno " .. tostring(r[3].growing_herrno))
        t:assert_eq(r[1].gai, 0, "getaddrinfo(AF_UNSPEC) retries with a larger buffer and succeeds")
        t:assert_eq(r[1].count, MANY_N, "with every address")
        t:assert_eq(r[2].gai, 0, "getaddrinfo(AF_INET) retries with a larger buffer and succeeds")
        t:assert_eq(r[2].count, MANY_N, "with every address")
        t:assert_eq(r[3].ret, E.ERANGE, "gethostbyname2_r passes ERANGE back, so its caller can grow the buffer")
        t:assert_eq(r[3].growing_count, MANY_N, "gethostbyname2, which grows its own buffer, returns every address")
    end)

-- ---------------------------------------------------------------------------
-- Connections, files, timeouts, caching
-- ---------------------------------------------------------------------------

test("every call that needs resolvd opens one connection to resolv.sock with ten-second read and write timeouts, sends one request, reads one reply and closes it; nothing is held between calls and no file is opened",
    { spec = "resolvd *nss-module.one-connection-per-call resolvd *nss-module.no-state-no-files resolvd *nss-module.ten-second-socket-timeouts PSPU *nri-shim.one-connection-per-call PSPU *nri-shim.no-connection-across-calls PSPU *nri-shim.reads-no-file" }, function(t)
        local r = pt(t, {
            { "n4", "both.nss.test" }, { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" },
            { "n2", "both.nss.test", "10" }, { "n1", "both.nss.test" },
            { "a2", "10.88.0.1" }, { "a1", "10.88.0.2" },
            { "gai", "both.nss.test", "0" }, { "ghbn", "both.nss.test", "2" }, { "ghba", "10.88.0.1" },
        })
        for i, x in ipairs(r) do
            local what = x.op .. " #" .. i
            one_connection(t, x, what)
            t:assert(x.request ~= nil, what .. ": one request written")
            t:assert(x.reply ~= nil, what .. ": one reply read")
            t:assert_eq(#x.opens, 0, what .. ": no file opened (" .. list(x.opens) .. ")")
            local rcv, snd = x.timeouts.rcvtimeo, x.timeouts.sndtimeo
            t:assert(rcv and rcv.sec == 10 and rcv.usec == 0, what .. ": a ten-second read timeout")
            t:assert(snd and snd.sec == 10 and snd.usec == 0, what .. ": a ten-second write timeout")
        end
        t:assert_eq(r[8].gai, 0, "getaddrinfo found the name")
        t:assert_eq(r[9].found, 1, "gethostbyname2_r found the name")
        t:assert_eq(r[10].found, 1, "gethostbyaddr found the address")
    end)

test("the shim does not cache: a second call in the same process asks resolvd again and gets the changed answer",
    { spec = "PSPU *nri-shim.does-not-cache" }, function(t)
        sut:run("rm -f /tmp/r11-first /tmp/r11-go")
        local p = sut:run_async("sh", { args = { "-c",
            "pt-nss n4 change.nss.test + touch /tmp/r11-first + wait /tmp/r11-go + n4 change.nss.test" } })
        wait_until(function() return sut:run("test -e /tmp/r11-first").exit_code == 0 end,
            { timeout = 20, interval = 0.2, desc = "the first call done" })
        network.write(sut, "Dns\\Hosts", { ["change.nss.test"] = "sz:10.88.0.8" })
        wait_until(function()
            local a = native({ query = "lookup", name = "change.nss.test", family = "inet" })
            return list(addresses_of(a)) == "[10.88.0.8]"
        end, { timeout = 20, interval = 0.2, desc = "resolvd answering the new address" })
        sut:run("touch /tmp/r11-go")
        local done = p:wait(30)
        t:log(done.stdout)
        local r = parse(done.stdout)
        local first, second = r[1], r[4]
        t:assert(first and second, "both calls ran")
        t:assert_eq(first.tuples[1] and first.tuples[1].addr, "10.88.0.7", "the first call: the old address")
        one_connection(t, second, "the second call")
        t:assert_eq(second.tuples[1] and second.tuples[1].addr, "10.88.0.8", "the second call: the new address")
    end)

-- ---------------------------------------------------------------------------
-- Through the network: TTLs, canonical names, notfound, reverse
-- ---------------------------------------------------------------------------

test("gethostbyname3_r: h_name is the reply's canonical name (the end of the CNAME chain), canonp points at it, and the TTL is the least among the addresses, not the CNAME's",
    { spec = "resolvd *nss-forward.gethostbyname3-ttl-and-canon PSPU *nri-shim.h-name-is-canonical PSPU *nri-shim.ttl-is-least-address-ttl" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n3", "alias.example.test", "2" }, { "n3", "ttl.example.test", "2" } }, { serve = true })
        local a = r[1]
        t:assert_eq(a.status, NSS.SUCCESS, "alias.example.test found")
        t:assert_eq(a.reply and a.reply.canonical, "www.example.test", "resolvd's canonical name is the chain's end")
        t:assert_eq(a.h_name, "www.example.test", "h_name is the canonical name")
        t:assert_eq(a.canon_is_h_name, 1, "canonp points at h_name")
        same_list(t, a.addrs, { "10.77.0.80" }, "the address")
        t:assert_eq(a.ttl, 60, "the TTL is the address's (60), not the CNAME's (30)")
        local b = r[2]
        t:assert_eq(b.status, NSS.SUCCESS, "ttl.example.test found")
        t:assert_eq(b.ttl, 120, "the least of the IPv4 addresses' TTLs (300, 120)")
        t:assert_eq(b.h_name, b.reply and b.reply.canonical, "h_name is the canonical name")
    end)

test("gethostbyname4_r's TTL is the least among all the addresses",
    { spec = "resolvd *nss-forward.gethostbyname4-ttl-least" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n4", "ttl4.example.test" } }, { serve = true })[1]
        t:assert_eq(r.status, NSS.SUCCESS, "found")
        t:assert_eq(#r.tuples, 3, "three addresses")
        local ttls = {}
        for _, a in ipairs((r.reply and r.reply.addresses) or {}) do ttls[#ttls + 1] = tostring(a.ttl) end
        t:log("the reply's TTLs: " .. list(ttls))
        t:assert_eq(r.ttl, 120, "the least TTL (300, 120, 200)")
    end)

test("notfound is NOTFOUND, ENOENT, HOST_NOT_FOUND",
    { spec = "resolvd *nss-module.notfound-is-host-not-found PSPU *nri-shim.notfound-is-host-not-found" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n4", "nosuch.example.test" }, { "n3", "nosuch.example.test", "2" } }, { serve = true })
        for _, x in ipairs(r) do
            t:assert_eq(x.reply and x.reply.outcome, "notfound", x.op .. ": resolvd said notfound")
            expect(t, x, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, x.op)
        end
    end)

test("a reverse is rendered from the PTR records in order, trailing dots removed: the first is h_name, the rest are aliases, the address alone in h_addr_list; the TTL is the least of all the reply's records, PTR or not",
    { spec = "resolvd *nss-reverse.hostent-layout resolvd *nss-reverse.ttl-least-of-all-records" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "a2", "10.77.0.81" }, { "a2", "10.77.0.82" } }, { serve = true })
        local a = r[1]
        t:assert_eq(a.status, NSS.SUCCESS, "10.77.0.81 found")
        local texts = {}
        for _, rec in ipairs((a.reply and a.reply.records) or {}) do texts[#texts + 1] = rec.text end
        t:log("the reply's records: " .. list(texts))
        t:assert_eq(a.h_name, "ptr-one.example.test", "h_name is the first PTR, without a trailing dot")
        same_list(t, a.alias_list, { "ptr-two.example.test" }, "the second PTR is the alias")
        t:assert_eq(a.aliases, 1, "and the only one")
        t:assert_eq(a.addrtype, AF.INET, "h_addrtype")
        t:assert_eq(a.length, 4, "h_length")
        same_list(t, a.addrs, { "10.77.0.81" }, "the address asked, alone")
        t:assert_eq(a.ttl, 200, "the least TTL of the two PTRs (400, 200)")
        local b = r[2]
        t:assert_eq(b.status, NSS.SUCCESS, "10.77.0.82 found")
        local types = {}
        for _, rec in ipairs((b.reply and b.reply.records) or {}) do types[#types + 1] = tostring(rec.type) end
        t:log("the reply's record types: " .. list(types))
        t:assert_eq(b.h_name, "classless.example.test", "h_name is the PTR at the end of the CNAME")
        t:assert_eq(b.aliases, 0, "a CNAME is not an alias")
        t:assert_eq(b.ttl, 30, "the least TTL includes the CNAME's (30) as well as the PTR's (300)")
    end)

test("a reverse found with no records, or with records but no PTR among them, is NOTFOUND with HOST_NOT_FOUND",
    { spec = "resolvd *nss-reverse.found-without-records-is-notfound resolvd *nss-reverse.no-ptr-record-is-notfound" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "a2", "10.77.0.84" }, { "a2", "10.77.0.83" } }, { serve = true })
        local empty, cname = r[1], r[2]
        t:assert_eq(empty.reply and empty.reply.outcome, "found", "10.77.0.84: resolvd said found")
        t:assert_eq(#((empty.reply and empty.reply.records) or {}), 0, "10.77.0.84: with no records")
        expect(t, empty, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, "found without records")
        t:assert_eq(cname.reply and cname.reply.outcome, "found", "10.77.0.83: resolvd said found")
        local recs = (cname.reply and cname.reply.records) or {}
        t:assert(#recs > 0, "10.77.0.83: with records")
        for _, rec in ipairs(recs) do t:assert(rec.type ~= 12, "none of them a PTR (type " .. tostring(rec.type) .. ")") end
        expect(t, cname, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, "records but no PTR")
    end)

-- ---------------------------------------------------------------------------
-- Replies the real resolvd cannot be made to give (the stand-in server)
-- ---------------------------------------------------------------------------

test("no reply within ten seconds is TRYAGAIN, EAGAIN, TRY_AGAIN",
    { spec = "resolvd *nss-module.timeout-is-try-again" }, function(t)
        local r = pt(t, { { "n4", "quiet.nss.test" }, { "a2", "10.66.0.1" } }, { fake = "silent", timeout = 90 })
        for _, x in ipairs(r) do
            t:assert_eq(x.connects[1] and x.connects[1].ret, 0, x.op .. ": connected (to the stand-in)")
            t:assert(x.request ~= nil, x.op .. ": the request was sent")
            t:assert(x.elapsed_ms >= 9800 and x.elapsed_ms < 13000,
                x.op .. ": gave up after ten seconds (" .. x.elapsed_ms .. " ms)")
            t:assert_eq(x.recv_errors[1] and x.recv_errors[1].errno, E.EAGAIN, x.op .. ": the read timed out")
            expect(t, x, NSS.TRYAGAIN, E.EAGAIN, H.TRY_AGAIN, x.op)
        end
    end)

test("a reply of the wrong kind, a reply that does not decode, an oversized frame and a closed connection are UNAVAIL, ENOENT, NO_RECOVERY",
    { spec = "resolvd *nss-module.other-failures-are-unavail" }, function(t)
        local status = frame_hex({ ok = true, kind = "status", hostname = "x", netd = false,
            scopes = msgpack.array({}), fallback_servers = msgpack.array({}), cache_entries = 0,
            counters = { queries = 0 } })
        local addresses = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "x",
            addresses = { { address = "10.66.0.1", ttl = 5 } }, source = "dns", validation = "unvalidated" })
        local cases = {
            { "a status reply to a lookup", status, { "n4", "odd.nss.test" } },
            { "an ok with no kind to a lookup", frame_hex({ ok = true }), { "n3", "odd.nss.test", "2" } },
            { "an addresses reply to a reverse", addresses, { "a2", "10.66.0.1" } },
            { "bytes that are not MessagePack", frame_hex("\xc1\xc1\xc1"), { "n4", "odd.nss.test" } },
            { "a map without ok", frame_hex({ kind = "addresses" }), { "n4", "odd.nss.test" } },
            { "a frame longer than 65,536 bytes", hex(string.pack("<I4", 65537)) .. "00", { "n4", "odd.nss.test" } },
            { "a short frame then the close", hex(string.pack("<I4", 40)) .. "81a26f6b", { "n4", "odd.nss.test" } },
        }
        for _, c in ipairs(cases) do
            local x = pt(t, { c[3] }, { fake = "hex:" .. c[2] })[1]
            t:assert_eq(x.connects[1] and x.connects[1].ret, 0, c[1] .. ": connected (to the stand-in)")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, c[1])
        end
        local closed = pt(t, { { "n4", "odd.nss.test" } }, { fake = "close" })[1]
        expect(t, closed, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, "the connection closed with no reply")
    end)

test("a name is asked as a lookup in the entry point's family, the reply's addresses are filtered to that family, and an empty result is NOTFOUND",
    { spec = "resolvd *nss-forward.addresses-filtered-to-family" }, function(t)
        -- A reply carrying both families to a single-family question,
        -- which resolvd itself never sends.
        local mixed = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "mix.nss.test",
            addresses = { { address = "fd66::1", ttl = 50 }, { address = "10.66.0.1", ttl = 40 },
                          { address = "fd66::2", ttl = 45 }, { address = "10.66.0.2", ttl = 30 } },
            source = "dns", validation = "unvalidated" })
        local r = pt(t, { { "n3", "mix.nss.test", "2" }, { "n2", "mix.nss.test", "10" }, { "n1", "mix.nss.test" },
                          { "n4", "mix.nss.test" } }, { fake = "hex:" .. mixed })
        t:assert_eq(r[1].request and r[1].request.family, "inet", "gethostbyname3_r AF_INET asks inet")
        same_list(t, r[1].addrs, { "10.66.0.1", "10.66.0.2" }, "AF_INET: the IPv4 addresses only, in order")
        t:assert_eq(r[1].ttl, 30, "the TTL is the least among the kept addresses")
        t:assert_eq(r[2].request and r[2].request.family, "inet6", "gethostbyname2_r AF_INET6 asks inet6")
        same_list(t, r[2].addrs, { "fd66::1", "fd66::2" }, "AF_INET6: the IPv6 addresses only, in order")
        same_list(t, r[3].addrs, { "10.66.0.1", "10.66.0.2" }, "gethostbyname_r: IPv4 only")
        t:assert_eq(#r[4].tuples, 4, "gethostbyname4_r keeps every family")

        local v6only = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "six.nss.test",
            addresses = { { address = "fd66::6", ttl = 50 } }, source = "dns", validation = "unvalidated" })
        local e = pt(t, { { "n3", "six.nss.test", "2" } }, { fake = "hex:" .. v6only })[1]
        expect(t, e, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, "nothing left after the filter")
    end)

-- ---------------------------------------------------------------------------
-- glibc's hosts database
-- ---------------------------------------------------------------------------

test("glibc's hosts database is peios_net whatever nsswitch.conf or __nss_configure_lookup says, and /etc/hosts is not read",
    { spec = "PSPU *nri-shim.hosts-database-fixed-to-peios-net" }, function(t)
        scope_ready(t)
        local cfg = pt(t, { { "cfg", "hosts", "files" } })[1]
        t:assert_eq(cfg.ret, -1, "__nss_configure_lookup(\"hosts\", \"files\") is refused")
        sut:run("mkdir -p /etc")
        sut:run("printf 'hosts: files\\n' > /etc/nsswitch.conf")
        sut:run("printf '10.66.0.9 filesonly.nss.test\\n' > /etc/hosts")
        local written = sut:run("cat /etc/nsswitch.conf /etc/hosts")
        t:log(written.stdout .. written.stderr)
        t:assert(written.stdout:find("hosts: files", 1, true) and written.stdout:find("filesonly", 1, true),
            "the test wrote /etc/nsswitch.conf and /etc/hosts")
        local r = pt(t, { { "gai", "filesonly.nss.test", "0" }, { "gai", "both.nss.test", "2" } }, { serve = true })
        t:assert(r[1].gai ~= 0, "the /etc/hosts name does not resolve (" .. tostring(r[1].gaistr) .. ")")
        one_connection(t, r[1], "getaddrinfo(filesonly.nss.test) went to resolvd")
        t:assert_eq(r[2].gai, 0, "a static name resolves")
        one_connection(t, r[2], "getaddrinfo(both.nss.test) went to resolvd")
        local ge = served("getent hosts filesonly.nss.test")
        t:assert_eq(ge.exit_code, 2, "getent hosts: not found")
        sut:run("rm -f /etc/nsswitch.conf /etc/hosts")
    end)

-- ---------------------------------------------------------------------------
-- unavailable (late in the file: the silent server may get demoted)
-- ---------------------------------------------------------------------------

test("unavailable from resolvd is TRYAGAIN, EAGAIN, TRY_AGAIN, not NOTFOUND",
    { spec = "resolvd *nss-module.unavailable-is-try-again PSPU *nri-shim.unavailable-is-tryagain" }, function(t)
        scope_ready(t)
        dns.forget(gw)
        local x = pt(t, { { "n4", "slow.example.test" } }, { serve = true, timeout = 60 })[1]
        local asked = dns.queries(gw, function(e) return e.msg and e.msg.questions[1]
            and dns.same_name(e.msg.questions[1].name, "slow.example.test") end)
        t:log(#asked .. " questions for slow.example.test reached the (silent) gateway")
        t:assert(#asked > 0, "resolvd asked the gateway, which did not answer")
        t:assert_eq(x.reply and x.reply.outcome, "unavailable", "resolvd said unavailable (its attempts ran out)")
        t:assert(x.elapsed_ms < 10000, "resolvd answered inside the shim's ten seconds (" .. x.elapsed_ms .. " ms)")
        expect(t, x, NSS.TRYAGAIN, E.EAGAIN, H.TRY_AGAIN, "gethostbyname4_r")
    end)

-- ---------------------------------------------------------------------------
-- An error reply, then resolvd unreachable (left stopped for the next test)
-- ---------------------------------------------------------------------------

test("an error reply (access denied) and an unreachable resolvd are UNAVAIL, ENOENT, NO_RECOVERY",
    { spec = "resolvd *nss-module.error-reply-is-unavail resolvd *nss-module.unreachable-is-unavail PSPU *nri-shim.unreachable-or-error-is-no-recovery PSPU *nri-shim.unreachable-resolver-is-unavail" }, function(t)
        local dnskey = network.KEY .. "\\Dns"
        -- SYSTEM may only flush: lookup and reverse are denied to everyone.
        network.reg(sut, { "set", dnskey, "ControlSecurity", "hex:" .. peinit.system_descriptor_hex(0x2) }):assert_ok()
        wait_until(function()
            local a = native({ query = "lookup", name = "both.nss.test", family = "any" })
            return a and a.ok == false and a.error == "access denied"
        end, { timeout = 20, interval = 0.2, desc = "resolvd denying lookups" })
        local denied = pt(t, { { "n4", "both.nss.test" }, { "a2", "10.88.0.1" } })
        network.reg(sut, { "del", dnskey, "ControlSecurity" })
        wait_until(function()
            local a = native({ query = "lookup", name = "both.nss.test", family = "any" })
            return a and a.ok == true
        end, { timeout = 20, interval = 0.2, desc = "resolvd answering again" })
        for _, x in ipairs(denied) do
            t:assert(x.reply and x.reply.ok == false, x.op .. ": resolvd replied with an error")
            t:assert_eq(x.reply and x.reply.error, "access denied", x.op .. ": access denied")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, x.op .. " (error reply)")
        end

        sut:run("svctl stop resolvd", { timeout = 60 })
        wait_until(function() return native({ query = "status" }) == nil end,
            { timeout = 30, interval = 0.3, desc = "resolv.sock refusing connections" })
        local gone = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" }, { "a2", "10.88.0.1" } })
        for _, x in ipairs(gone) do
            t:assert(x.connects[1] and x.connects[1].ret == -1, x.op .. ": the connect failed (errno "
                .. tostring(x.connects[1] and x.connects[1].errno) .. ")")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, x.op .. " (resolvd stopped)")
        end
    end)

test("with resolvd stopped, localhost is still answered in the process, and the shim never falls back to DNS: no inet socket, no question on the wire",
    { spec = "resolvd *nss-forward.localhost-answered-in-process PSPU *nri-shim.speaks-no-dns" }, function(t)
        t:assert(native({ query = "status" }) == nil, "resolvd is still stopped")
        dns.forget(gw)
        local r = pt(t, { { "n4", "localhost" }, { "n3", "sub.LOCALHOST.", "10" }, { "n4", "www.example.test" },
                          { "gai", "www.example.test", "0" }, { "ghbn", "www.example.test", "2" } },
            { serve = true })
        for i = 1, 2 do
            no_socket(t, r[i], r[i].op .. " #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, r[i].op .. " #" .. i .. ": answered without resolvd")
        end
        same_list(t, r[2].addrs, { "::1" }, "sub.LOCALHOST. AF_INET6 is ::1")
        for i = 3, 5 do
            for _, s in ipairs(r[i].sockets) do
                t:assert_eq(s.family, 1, r[i].op .. ": only AF_UNIX sockets (saw family " .. s.family .. ")")
            end
            t:assert_eq(#r[i].inet_sends, 0, r[i].op .. ": no datagram sent")
        end
        t:assert_eq(r[3].status, NSS.UNAVAIL, "the shim gives UNAVAIL rather than asking DNS itself")
        t:assert(r[4].gai ~= 0, "getaddrinfo fails")
        -- Pump a little longer: anything sent would have reached the gateway.
        gw:serve({ timeout = 2, until_ = function() return false end })
        local asked = dns.queries(gw, function(e) return e.msg and e.msg.questions[1]
            and dns.same_name(e.msg.questions[1].name, "www.example.test") end)
        t:assert_eq(#asked, 0, "the gateway saw no question for www.example.test")

        -- PEI-1373: a resolvd started over the old /run/resolvd crash-loops
        -- on `native socket: Permission denied`; clear it first.
        sut:run("rm -rf /run/resolvd; svctl start resolvd", { timeout = 60 })
        wait_until(function()
            local s = native({ query = "status" })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.3, desc = "resolvd answering again" })
    end)
