/* pt-notify — a service that says exactly what a test tells it to say.
 *
 * peinit authenticates a notification by its sender's pid: the datagram
 * must come from the *main job* of a service (execution/notify/auth.rs).
 * Nothing else counts — not a child of that process, not the provium
 * agent. So the whole of the notification protocol (TRM §10.5) and the
 * fd store (§10.6) were unreachable from the suite, because the image
 * ships nothing that can write a Unix datagram with ancillary data and
 * nothing that could be a service's main process while doing it.
 *
 * This is that program. A test defines a service whose ImagePath is
 * /usr/bin/pt-notify and whose Arguments are a script of steps; the
 * process runs them in order and records what each one did. Because the
 * process itself is the service's main job, its datagrams authenticate.
 *
 * It is injected into the image the way the provium agent is (see
 * build.sh), rather than packaged: it is test apparatus, and it has no
 * business on a real Peios.
 *
 * Usage:
 *   pt-notify [--socket PATH] [--log PATH] STEP...
 *
 * The socket defaults to $NOTIFY_SOCKET, which is what peinit puts in a
 * service's environment. --socket overrides it, so a test can also aim a
 * datagram at a path that is not this service's socket.
 *
 * Steps, each a verb and its own fixed number of following arguments:
 *
 *   send MSG                 one datagram, with credentials
 *   send-nocred MSG          the same, with no SCM_CREDENTIALS attached
 *   send-cred PID UID GID MSG   credentials with these values, which the
 *                            kernel accepts only from a caller allowed
 *                            to forge them; the errno is recorded either
 *                            way, and that is the point of the step
 *   send-fd PATH MSG         open PATH O_RDONLY and pass it in SCM_RIGHTS
 *   send-fds N PATH MSG      pass that one descriptor N times
 *   send-listener PATH MSG   bind and listen on a Unix socket at PATH and
 *                            pass it — a stored descriptor a test can
 *                            recognise again after a restart
 *   send-pad N MSG           pad the payload to N bytes with 'x', for the
 *                            64 KiB datagram bound
 *   sleep SECS               stay alive (a service that exits is not one
 *                            peinit will accept a notification from)
 *   report PATH              write what this process was handed: the
 *                            LISTEN_* environment, and every descriptor
 *                            from 3 up with its type and socket path
 *   write PATH TEXT          drop a marker file
 *   exit CODE                exit now with that status
 *
 * MSG understands \n, \t, \0 and \\ escapes, so a multi-line datagram —
 * and a NUL in the middle of one — is expressible from a registry
 * Arguments array.
 *
 * Every step appends one line to the log (default: stdout):
 *
 *   step=send rc=13 errno=0 detail=READY=1
 *
 * rc is the syscall's return, errno its error. A test reads the log
 * through the service's output or from a file, and knows what the guest
 * actually managed to send rather than what it was asked to.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static FILE *logf;

static void logline(const char *verb, long rc, int err, const char *fmt, ...)
{
    va_list ap;
    fprintf(logf, "step=%s rc=%ld errno=%d", verb, rc, err);
    if (fmt) {
        fputs(" detail=", logf);
        va_start(ap, fmt);
        vfprintf(logf, fmt, ap);
        va_end(ap);
    }
    fputc('\n', logf);
    fflush(logf);
}

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

/* Decode \n, \t, \0 and \\ in place. Returns the decoded length, which a
 * payload containing a NUL needs and strlen cannot give. */
static size_t unescape(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = in; *p && n < cap; p++) {
        if (*p != '\\') { out[n++] = *p; continue; }
        switch (*++p) {
        case 'n': out[n++] = '\n'; break;
        case 't': out[n++] = '\t'; break;
        case '0': out[n++] = '\0'; break;
        case '\\': out[n++] = '\\'; break;
        case '\0': out[n++] = '\\'; return n;
        default: out[n++] = '\\'; out[n++] = *p; break;
        }
    }
    return n;
}

/* One datagram.
 *
 * creds < 0 attaches no SCM_CREDENTIALS at all; creds == 0 attaches this
 * process's real ones; creds > 0 attaches the (pid, uid, gid) given.
 * Returns sendmsg's result and leaves errno alone.
 */
static long send_datagram(const char *sock_path,
                          const char *payload, size_t payload_len,
                          int creds, pid_t pid, uid_t uid, gid_t gid,
                          const int *fds, size_t fd_count)
{
    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;

    /* The kernel only fills in credentials the sender did not supply if
     * the socket has SO_PASSCRED; attaching them explicitly is what lets
     * a test both omit them and forge them. */
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof addr.sun_path) { errno = ENAMETOOLONG; close(s); return -1; }
    strcpy(addr.sun_path, sock_path);

    struct iovec iov = { .iov_base = (void *)payload, .iov_len = payload_len };
    /* Room for one ucred and up to 128 descriptors: the receiver's bound
     * is 64, and a test that wants to cross it has to be able to send 65. */
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(128 * sizeof(int))];
    memset(control, 0, sizeof control);

    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &addr;
    msg.msg_namelen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(sock_path) + 1);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = 0;

    struct cmsghdr *cmsg = NULL;
    size_t used = 0;

    if (creds >= 0) {
        msg.msg_controllen = sizeof control;   /* so CMSG_FIRSTHDR resolves */
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        struct ucred uc = {
            .pid = creds > 0 ? pid : getpid(),
            .uid = creds > 0 ? uid : getuid(),
            .gid = creds > 0 ? gid : getgid(),
        };
        memcpy(CMSG_DATA(cmsg), &uc, sizeof uc);
        used += CMSG_SPACE(sizeof(struct ucred));
    }

    if (fd_count) {
        msg.msg_controllen = sizeof control;
        cmsg = cmsg ? CMSG_NXTHDR(&msg, cmsg) : CMSG_FIRSTHDR(&msg);
        if (!cmsg) { errno = EINVAL; close(s); return -1; }
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, fd_count * sizeof(int));
        used += CMSG_SPACE(fd_count * sizeof(int));
    }

    msg.msg_controllen = used;
    if (used == 0) msg.msg_control = NULL;

    long rc = sendmsg(s, &msg, 0);
    int saved = errno;
    close(s);
    errno = saved;
    return rc;
}

/* What this process was handed. The fd store's whole observable effect on
 * a restarted service is here: LISTEN_FDS, LISTEN_FDNAMES, LISTEN_PID and
 * the descriptors themselves from 3 upward. */
static void report(const char *path)
{
    FILE *f = strcmp(path, "-") == 0 ? stdout : fopen(path, "w");
    if (!f) { logline("report", -1, errno, "%s", path); return; }

    fprintf(f, "pid=%d\n", (int)getpid());
    const char *keys[] = { "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PID", "NOTIFY_SOCKET" };
    for (size_t i = 0; i < sizeof keys / sizeof *keys; i++) {
        const char *v = getenv(keys[i]);
        fprintf(f, "%s=%s\n", keys[i], v ? v : "");
    }

    for (int fd = 3; fd < 64; fd++) {
        struct stat st;
        if (fstat(fd, &st) != 0) continue;
        const char *kind = "other";
        if (S_ISSOCK(st.st_mode)) kind = "socket";
        else if (S_ISREG(st.st_mode)) kind = "file";
        else if (S_ISFIFO(st.st_mode)) kind = "fifo";
        else if (S_ISDIR(st.st_mode)) kind = "dir";
        else if (S_ISCHR(st.st_mode)) kind = "chr";
        fprintf(f, "fd%d=%s", fd, kind);
        if (S_ISSOCK(st.st_mode)) {
            struct sockaddr_un a;
            socklen_t len = sizeof a;
            memset(&a, 0, sizeof a);
            if (getsockname(fd, (struct sockaddr *)&a, &len) == 0 && a.sun_family == AF_UNIX)
                fprintf(f, " path=%s", a.sun_path);
            int accepting = 0;
            len = sizeof accepting;
            if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &len) == 0)
                fprintf(f, " listening=%d", accepting);
        }
        fputc('\n', f);
    }
    if (f != stdout) fclose(f); else fflush(f);
    logline("report", 0, 0, "%s", path);
}

int main(int argc, char **argv)
{
    logf = stdout;
    const char *sock = getenv("NOTIFY_SOCKET");

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            logf = fopen(argv[++i], "w");
            if (!logf) die("pt-notify: cannot open log %s: %s", argv[i], strerror(errno));
        } else break;
    }

    /* One buffer, big enough for the receiver's 64 KiB bound and a step
     * that deliberately exceeds it. */
    static char payload[128 * 1024];

    for (; i < argc; i++) {
        const char *verb = argv[i];
        int need = 1;
        if (strcmp(verb, "send-cred") == 0) need = 4;
        else if (strcmp(verb, "send-fd") == 0 || strcmp(verb, "send-pad") == 0 ||
                 strcmp(verb, "send-listener") == 0 || strcmp(verb, "write") == 0) need = 2;
        else if (strcmp(verb, "send-fds") == 0) need = 3;
        else if (strcmp(verb, "send") == 0 || strcmp(verb, "send-nocred") == 0 ||
                 strcmp(verb, "sleep") == 0 || strcmp(verb, "report") == 0 ||
                 strcmp(verb, "exit") == 0) need = 1;
        else die("pt-notify: unknown step `%s`", verb);
        if (i + need >= argc) die("pt-notify: step `%s` wants %d argument(s)", verb, need);

        if (strcmp(verb, "sleep") == 0) {
            struct timespec ts = { .tv_sec = atol(argv[i + 1]), .tv_nsec = 0 };
            logline("sleep", ts.tv_sec, 0, NULL);
            nanosleep(&ts, NULL);
        } else if (strcmp(verb, "exit") == 0) {
            int code = atoi(argv[i + 1]);
            logline("exit", code, 0, NULL);
            return code;
        } else if (strcmp(verb, "report") == 0) {
            report(argv[i + 1]);
        } else if (strcmp(verb, "write") == 0) {
            FILE *f = fopen(argv[i + 1], "w");
            if (f) { fputs(argv[i + 2], f); fputc('\n', f); fclose(f); }
            logline("write", f ? 0 : -1, f ? 0 : errno, "%s", argv[i + 1]);
        } else {
            /* Everything else is a datagram; the differences are which
             * credentials go on it and which descriptors ride with it. */
            int creds = 0;
            pid_t pid = 0; uid_t uid = 0; gid_t gid = 0;
            int fds[128];
            size_t fd_count = 0;
            const char *msg;
            int opened = -1;

            if (strcmp(verb, "send") == 0) {
                msg = argv[i + 1];
            } else if (strcmp(verb, "send-nocred") == 0) {
                creds = -1;
                msg = argv[i + 1];
            } else if (strcmp(verb, "send-cred") == 0) {
                creds = 1;
                pid = (pid_t)atol(argv[i + 1]);
                uid = (uid_t)atol(argv[i + 2]);
                gid = (gid_t)atol(argv[i + 3]);
                msg = argv[i + 4];
            } else if (strcmp(verb, "send-fd") == 0) {
                opened = open(argv[i + 1], O_RDONLY | O_CLOEXEC);
                if (opened < 0) { logline(verb, -1, errno, "open %s", argv[i + 1]); i += need; continue; }
                fds[fd_count++] = opened;
                msg = argv[i + 2];
            } else if (strcmp(verb, "send-fds") == 0) {
                size_t n = (size_t)atol(argv[i + 1]);
                if (n > 128) n = 128;
                opened = open(argv[i + 2], O_RDONLY | O_CLOEXEC);
                if (opened < 0) { logline(verb, -1, errno, "open %s", argv[i + 2]); i += need; continue; }
                for (size_t k = 0; k < n; k++) fds[fd_count++] = opened;
                msg = argv[i + 3];
            } else if (strcmp(verb, "send-listener") == 0) {
                int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                struct sockaddr_un a;
                memset(&a, 0, sizeof a);
                a.sun_family = AF_UNIX;
                strncpy(a.sun_path, argv[i + 1], sizeof a.sun_path - 1);
                unlink(argv[i + 1]);
                if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 4) != 0) {
                    logline(verb, -1, errno, "listener %s", argv[i + 1]);
                    if (ls >= 0) close(ls);
                    i += need;
                    continue;
                }
                opened = ls;
                fds[fd_count++] = ls;
                msg = argv[i + 2];
            } else { /* send-pad */
                msg = argv[i + 2];
            }

            size_t len = unescape(msg, payload, sizeof payload);
            if (strcmp(verb, "send-pad") == 0) {
                size_t want = (size_t)atol(argv[i + 1]);
                if (want > sizeof payload) want = sizeof payload;
                while (len < want) payload[len++] = 'x';
            }

            if (!sock) die("pt-notify: no socket: neither NOTIFY_SOCKET nor --socket is set");
            errno = 0;
            long rc = send_datagram(sock, payload, len, creds, pid, uid, gid, fds, fd_count);
            logline(verb, rc, rc < 0 ? errno : 0, "len=%zu fds=%zu", len, fd_count);
            if (opened >= 0) close(opened);
        }
        i += need;
    }
    return 0;
}
