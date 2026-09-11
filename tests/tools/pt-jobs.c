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
 *   pt-jobs [--socket PATH] [--log PATH] STEP...
 *
 * The steps run in order on one connection, so a `submit` and the
 * `status` that asks about the job it created can share a connection,
 * which is what the manager expects of a client that submitted
 * something:
 *
 *   send JSON        send one message and read its answer
 *   send-fds N JSON  the same, with N descriptors attached as SCM_RIGHTS
 *   send-only JSON   send and read nothing -- for pipelining
 *   read             read one answer
 *   sleep N          hold the connection open, idle, for N seconds
 *
 * A bare JSON argument is `send JSON`, which is what every caller
 * written before the steps existed passes.
 *
 * The descriptors `send-fds` attaches are dups of /dev/null. What they
 * are does not matter to the two claims they exist for -- the 64 a
 * message may carry, and the `MSG_CTRUNC` that a 65th produces -- and a
 * descriptor the manager might make sense of would muddy both.
 *
 * The socket defaults to /run/services/peinit/jobs.sock.
 *
 * Each answer prints three lines:
 *
 *   reply rc=213 fds=1 at=1.204
 *   reply-fd0 anon_inode:[pidfd]
 *   reply-json {"status":"ok",…}
 *
 * `fds` is how many SCM_RIGHTS descriptors the answer carried, and each
 * one is named by its /proc/self/fd link, which is what tells a pidfd
 * apart from anything else. A test reads those lines and knows what the
 * manager actually attached rather than what a client chose to report.
 * `at` is seconds since the connect, which is how a test tells an answer
 * that came back at once from one that waited for something.
 *
 * `rc=0` with no error is end of file: the manager closed the
 * connection. That is a claim of its own -- only REQUEST_TOO_LARGE
 * closes one -- so it prints as `reply closed at=…` rather than as an
 * empty answer.
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
#include <time.h>
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

static struct timespec started;

/* Seconds since the connect, so a test can tell an answer that came back
 * at once from one that waited for a job to move. */
static double elapsed(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - started.tv_sec)
        + (double)(now.tv_nsec - started.tv_nsec) / 1e9;
}

/* Send one message, with `nfds` descriptors attached when asked for.
 * Returns 0, or the errno that stopped it. */
static int send_message(int s, const char *json, int nfds)
{
    struct iovec iov = { .iov_base = (void *)json, .iov_len = strlen(json) };
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char *control = NULL;
    int *fds = NULL;
    if (nfds > 0) {
        /* Every one a dup of /dev/null: the claims are about how many a
         * message may carry, not about what they point at. */
        fds = calloc((size_t)nfds, sizeof(int));
        if (!fds) return ENOMEM;
        for (int k = 0; k < nfds; k++) {
            fds[k] = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fds[k] < 0) {
                int err = errno;
                for (int j = 0; j < k; j++) close(fds[j]);
                free(fds);
                return err;
            }
        }
        size_t space = CMSG_SPACE((size_t)nfds * sizeof(int));
        control = calloc(1, space);
        if (!control) {
            for (int k = 0; k < nfds; k++) close(fds[k]);
            free(fds);
            return ENOMEM;
        }
        msg.msg_control = control;
        msg.msg_controllen = space;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN((size_t)nfds * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, (size_t)nfds * sizeof(int));
    }

    ssize_t sent = sendmsg(s, &msg, 0);
    int err = sent < 0 ? errno : 0;
    if (fds) {
        for (int k = 0; k < nfds; k++) close(fds[k]);
        free(fds);
    }
    free(control);
    return err;
}

/* Read one answer and print what it was. Returns 0 while the connection
 * is usable, and non-zero once it is not. */
static int read_reply(int s)
{
    static char response[MAX_RESPONSE];
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
        fprintf(logf, "reply rc=-1 errno=%d %s at=%.3f\n",
                errno, strerror(errno), elapsed());
        fflush(logf);
        return 5;
    }
    if (got == 0) {
        /* End of file. Only REQUEST_TOO_LARGE is supposed to produce
         * this, so it is evidence rather than an empty answer. */
        fprintf(logf, "reply closed at=%.3f\n", elapsed());
        fflush(logf);
        return 6;
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

    fprintf(logf, "reply rc=%zd fds=%zu%s at=%.3f\n", got, fd_count,
            (msg.msg_flags & MSG_CTRUNC) ? " ctruncated" : "", elapsed());
    for (size_t k = 0; k < fd_count; k++) {
        char what[256];
        describe_fd(fds[k], what, sizeof what);
        fprintf(logf, "reply-fd%zu %s\n", k, what);
        close(fds[k]);
    }
    fprintf(logf, "reply-json %.*s\n", (int)got, response);
    fflush(logf);
    return 0;
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
    if (i >= argc) die("pt-jobs: no steps given");

    clock_gettime(CLOCK_MONOTONIC, &started);

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

    for (; i < argc; i++) {
        const char *step = argv[i];
        int attach = 0;
        const char *json = NULL;
        int want_reply = 1;

        if (strcmp(step, "sleep") == 0) {
            if (i + 1 >= argc) die("pt-jobs: sleep needs a count");
            int seconds = atoi(argv[++i]);
            fprintf(logf, "sleep %d at=%.3f\n", seconds, elapsed());
            fflush(logf);
            sleep((unsigned)seconds);
            continue;
        }
        if (strcmp(step, "read") == 0) {
            fprintf(logf, "read at=%.3f\n", elapsed());
            fflush(logf);
            int rc = read_reply(s);
            if (rc) return rc == 6 ? 0 : rc;
            continue;
        }
        if (strcmp(step, "send-fds") == 0) {
            if (i + 2 >= argc) die("pt-jobs: send-fds needs a count and a request");
            attach = atoi(argv[++i]);
            json = argv[++i];
        } else if (strcmp(step, "send-only") == 0) {
            if (i + 1 >= argc) die("pt-jobs: send-only needs a request");
            json = argv[++i];
            want_reply = 0;
        } else if (strcmp(step, "send") == 0) {
            if (i + 1 >= argc) die("pt-jobs: send needs a request");
            json = argv[++i];
        } else {
            /* A bare JSON object, which is what callers written before
             * the steps existed pass. */
            json = step;
        }

        fprintf(logf, "request fds=%d bytes=%zu at=%.3f\n",
                attach, strlen(json), elapsed());
        fprintf(logf, "request-json %s\n", json);
        fflush(logf);

        /* With no control message there is no token and no descriptor:
         * the manager takes the connection's identity for the
         * request's. */
        int err = send_message(s, json, attach);
        if (err) {
            fprintf(logf, "send rc=-1 errno=%d %s at=%.3f\n",
                    err, strerror(err), elapsed());
            fflush(logf);
            return 4;
        }
        if (!want_reply) continue;

        int rc = read_reply(s);
        /* A closed connection is an outcome the caller asked to see, not
         * a failure of the tool. */
        if (rc) return rc == 6 ? 0 : rc;
    }

    close(s);
    return 0;
}
