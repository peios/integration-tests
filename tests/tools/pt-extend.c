/* pt-extend — a service that asks for more time, when a test says so.
 *
 * EXTEND_TIMEOUT_USEC (Peinit TRM §6.6) is a notification, so it has to
 * come from the service's own main process: peinit authenticates a
 * notification by its sender's pid (execution/notify/auth.rs). pt-notify
 * can send one, but only on a fixed schedule, and a test about what a
 * shutdown does with an extension needs it sent at a moment the test
 * chooses — after the shutdown has begun and before the service's own
 * stop wave has, say. That moment is only known on the host.
 *
 * So this waits for a file. It reports ready, waits until the file
 * exists, and then sends its extension COUNT times a second apart (0
 * meaning until it is killed). It ignores SIGTERM, since a service that
 * died on the stop signal would make its own deadline irrelevant.
 *
 * Usage:
 *   pt-extend USEC [GO_FILE [COUNT]]
 *
 * With no GO_FILE it starts extending as soon as it is ready. Without a
 * COUNT it extends until killed. Each datagram it sends is logged, with
 * the send's result, on stdout and appended to /run/pt-extend.log — the
 * file is what a test reads, since a service's stdout goes to its log
 * pipe and not to anywhere a test can see during a shutdown:
 *
 *   pid=271 send rc=24 errno=0 EXTEND_TIMEOUT_USEC=60000000
 *
 * Like the suite's other tools it is staged into a guest by a test
 * rather than packaged. It is test apparatus.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static void nap(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* One datagram to NOTIFY_SOCKET, with this process's credentials. */
static void notify(const char *message)
{
    const char *path = getenv("NOTIFY_SOCKET");
    long rc = -1;
    int err = 0;
    if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        err = EINVAL;
    } else {
        int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            err = errno;
        } else {
            int one = 1;
            setsockopt(s, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof addr);
            addr.sun_family = AF_UNIX;
            strcpy(addr.sun_path, path);

            char control[CMSG_SPACE(sizeof(struct ucred))];
            memset(control, 0, sizeof control);
            struct iovec iov = { .iov_base = (void *)message, .iov_len = strlen(message) };
            struct msghdr msg;
            memset(&msg, 0, sizeof msg);
            msg.msg_name = &addr;
            msg.msg_namelen = sizeof addr;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof control;
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_CREDENTIALS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
            struct ucred uc = { .pid = getpid(), .uid = getuid(), .gid = getgid() };
            memcpy(CMSG_DATA(cmsg), &uc, sizeof uc);

            rc = sendmsg(s, &msg, 0);
            if (rc < 0) err = errno;
            close(s);
        }
    }
    char line[160];
    int n = snprintf(line, sizeof line, "pid=%d send rc=%ld errno=%d %s\n", (int)getpid(), rc,
                     err, message);
    fputs(line, stdout);
    fflush(stdout);
    /* One O_APPEND write per line, so two instances never interleave. */
    int log = open("/run/pt-extend.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (log >= 0 && n > 0) {
        if (write(log, line, (size_t)n) < 0) { /* best effort */ }
        close(log);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: pt-extend USEC [GO_FILE [COUNT]]\n");
        return 2;
    }
    const char *usec = argv[1];
    const char *go = argc > 2 ? argv[2] : NULL;
    long count = argc > 3 ? atol(argv[3]) : 0;

    signal(SIGTERM, SIG_IGN);

    /* peinit records the main job when it processes the launch, which is
     * after exec; a datagram sent before then is refused as coming from
     * nobody it knows. A second is the suite's standing margin. */
    nap(1000);
    notify("READY=1");

    if (go) {
        while (access(go, F_OK) != 0) nap(100);
        printf("go %s\n", go);
        fflush(stdout);
    }

    char message[64];
    snprintf(message, sizeof message, "EXTEND_TIMEOUT_USEC=%s", usec);
    for (long sent = 0; count == 0 || sent < count; sent++) {
        notify(message);
        nap(1000);
    }
    for (;;) pause();
}
