/* pt-jobs — a jobs-socket client that says what came back on the wire.
 *
 * The jobs socket (TRM §10.7) answers with one compact JSON object per
 * request, and a `submit` answered with a running job additionally
 * carries a duplicate of the job's pidfd as SCM_RIGHTS. Nothing else is
 * supposed to carry ancillary data at all.
 *
 * From the guest, that was untestable. `svctl` is the only jobs client
 * the image ships, it receives the descriptor (jobs/client.rs asks for a
 * capacity of one) and it never mentions it -- so a response that
 * carried a handle and one that did not look identical from a shell.
 *
 * This is that program: it connects, sends the requests it is given,
 * and prints, for each answer, the JSON *and* what rode alongside it.
 * The socket is an ordinary SOCK_SEQPACKET Unix socket and the Peios
 * calls on it (`peios_socket_send_message` / `recv_message`) build
 * ordinary control messages -- SCM_RIGHTS at SOL_SOCKET, plus a KACS
 * token at SOL_KACS when one is attached -- so plain sendmsg/recvmsg is
 * a conforming client. Sending no token is the ordinary case: the
 * connection's own identity is what the manager checks.
 *
 * Like pt-notify it is injected into the image rather than packaged. It
 * is test apparatus, and it has no business on a real Peios.
 *
 * Usage:
 *   pt-jobs [--socket PATH] [--log PATH] REQUEST...
 *
 * Each REQUEST is one compact JSON object, sent as one datagram on the
 * one connection, in order -- so a `submit` and the `status` that asks
 * about the job it created can share a connection, which is what the
 * manager expects of a client that submitted something.
 *
 * The socket defaults to /run/services/peinit/jobs.sock.
 *
 * Each answer prints three lines:
 *
 *   reply rc=213 fds=1
 *   reply-fd0 anon_inode:[pidfd]
 *   reply-json {"status":"ok",…}
 *
 * `fds` is how many SCM_RIGHTS descriptors the answer carried, and each
 * one is named by its /proc/self/fd link, which is what tells a pidfd
 * apart from anything else. A test reads those lines and knows what the
 * manager actually attached rather than what a client chose to report.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/services/peinit/jobs.sock"
#define MAX_RESPONSE (1024 * 1024)
/* The manager sends at most one descriptor, but a client that asked for
 * exactly one could not tell "one" from "more than one". Room for eight
 * makes the count evidence rather than an artefact of the ask. */
#define MAX_REPLY_FDS 8

static FILE *logf;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

/* What a descriptor is, as the kernel names it: `anon_inode:[pidfd]` for
 * a process handle, a path for a file, `socket:[…]` for a socket. */
static void describe_fd(int fd, char *out, size_t cap)
{
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, out, cap - 1);
    if (n < 0) {
        snprintf(out, cap, "unreadable: %s", strerror(errno));
        return;
    }
    out[n] = '\0';
}

int main(int argc, char **argv)
{
    logf = stdout;
    const char *sock_path = DEFAULT_SOCKET;

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock_path = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            logf = fopen(argv[++i], "w");
            if (!logf) die("pt-jobs: cannot open log %s: %s", argv[i], strerror(errno));
        } else break;
    }
    if (i >= argc) die("pt-jobs: no requests given");

    int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (s < 0) die("pt-jobs: socket: %s", strerror(errno));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof addr.sun_path)
        die("pt-jobs: socket path too long: %s", sock_path);
    strcpy(addr.sun_path, sock_path);

    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(logf, "connect rc=-1 errno=%d %s\n", errno, strerror(errno));
        fflush(logf);
        return 3;
    }
    fprintf(logf, "connect rc=0 path=%s\n", sock_path);
    fflush(logf);

    static char response[MAX_RESPONSE];

    for (; i < argc; i++) {
        const char *request = argv[i];
        fprintf(logf, "request %s\n", request);

        /* No control message at all: no token, no descriptors. The
         * manager takes the connection's identity for the request's. */
        ssize_t sent = send(s, request, strlen(request), 0);
        if (sent < 0) {
            fprintf(logf, "send rc=-1 errno=%d %s\n", errno, strerror(errno));
            fflush(logf);
            return 4;
        }

        struct iovec iov = { .iov_base = response, .iov_len = sizeof response };
        char control[CMSG_SPACE(MAX_REPLY_FDS * sizeof(int))];
        memset(control, 0, sizeof control);
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof control;

        ssize_t got = recvmsg(s, &msg, 0);
        if (got < 0) {
            fprintf(logf, "reply rc=-1 errno=%d %s\n", errno, strerror(errno));
            fflush(logf);
            return 5;
        }

        int fds[MAX_REPLY_FDS];
        size_t fd_count = 0;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) continue;
            size_t payload = cmsg->cmsg_len - CMSG_LEN(0);
            size_t count = payload / sizeof(int);
            for (size_t k = 0; k < count && fd_count < MAX_REPLY_FDS; k++) {
                int fd;
                memcpy(&fd, CMSG_DATA(cmsg) + k * sizeof(int), sizeof fd);
                fds[fd_count++] = fd;
            }
        }

        fprintf(logf, "reply rc=%zd fds=%zu%s\n", got, fd_count,
                (msg.msg_flags & MSG_CTRUNC) ? " ctruncated" : "");
        for (size_t k = 0; k < fd_count; k++) {
            char what[256];
            describe_fd(fds[k], what, sizeof what);
            fprintf(logf, "reply-fd%zu %s\n", k, what);
            close(fds[k]);
        }
        fprintf(logf, "reply-json %.*s\n", (int)got, response);
        fflush(logf);
    }

    close(s);
    return 0;
}
