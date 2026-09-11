/* pt-jobrace — a submit and a shutdown that PID 1 reads in the same turn.
 *
 * A submitted job is queued for launch only until the end of the turn
 * that accepted it: the work pump drains every queued launch before the
 * turn is over. So a shutdown meets a job that is still queued — the case
 * Peinit TRM §12.2 step 1 says is cancelled with cause `shutdown` — only
 * if PID 1 reads the submit and the shutdown in one turn, the submit
 * first. Order across two sockets is not something a client can ask for.
 * It can arrange it, though, on a machine with one CPU.
 *
 * Running SCHED_FIFO, this process cannot be preempted by PID 1, which is
 * an ordinary SCHED_OTHER task. It connects to the jobs socket, connects
 * to the control socket, sends the submit and then the shutdown, and only
 * then blocks. PID 1 wakes to two listeners ready, jobs first, and
 * accepts both — accepting reads nothing — registering each connection
 * with its data already waiting, so its next wait returns the two in that
 * order and one turn reads the submit and then the shutdown. On more than
 * one CPU none of this holds; the test that uses this boots one.
 *
 * Usage:
 *   pt-jobrace IMAGE_PATH [KIND]
 *
 * KIND defaults to poweroff. Prints each answer as one line:
 *
 *   jobs {"status":"ok",…}
 *   control {"status":"ok"}
 *
 * and `error …` if it could not set itself up, in which case nothing was
 * sent.
 *
 * Like the suite's other tools it is staged into a guest by a test rather
 * than packaged. It is test apparatus.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define JOBS_SOCKET "/run/services/peinit/jobs.sock"
#define CONTROL_SOCKET "/run/services/peinit/control.sock"

static int connect_to(const char *path, int type)
{
    int s = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int saved = errno;
        close(s);
        errno = saved;
        return -1;
    }
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: pt-jobrace IMAGE_PATH [KIND]\n");
        return 2;
    }
    const char *kind = argc > 2 ? argv[2] : "poweroff";
    char submit[512], shutdown[128];
    snprintf(submit, sizeof submit, "{\"command\":\"submit\",\"image_path\":\"%s\"}", argv[1]);
    snprintf(shutdown, sizeof shutdown, "{\"command\":\"shutdown\",\"type\":\"%s\"}\n", kind);

    struct sched_param param = { .sched_priority = 50 };
    if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
        printf("error sched_setscheduler errno=%d\n", errno);
        return 1;
    }

    /* From here to the first blocking read, PID 1 does not run. */
    int jobs = connect_to(JOBS_SOCKET, SOCK_SEQPACKET);
    int control = jobs < 0 ? -1 : connect_to(CONTROL_SOCKET, SOCK_STREAM);
    if (jobs < 0 || control < 0) {
        printf("error connect errno=%d\n", errno);
        return 1;
    }
    if (send(jobs, submit, strlen(submit), 0) < 0
        || send(control, shutdown, strlen(shutdown), 0) < 0) {
        printf("error send errno=%d\n", errno);
        return 1;
    }

    char reply[65536];
    ssize_t n = recv(jobs, reply, sizeof reply - 1, 0);
    reply[n > 0 ? n : 0] = '\0';
    printf("jobs %s\n", reply);
    n = recv(control, reply, sizeof reply - 1, 0);
    reply[n > 0 ? n : 0] = '\0';
    /* The control answer carries its own newline. */
    printf("control %s%s", reply, n > 0 && reply[n - 1] == '\n' ? "" : "\n");
    return 0;
}
