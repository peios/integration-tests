/* pt-pause1 — hold PID 1 still for a while, so that events pile up.
 *
 * TRM §11.3 ranks the sources of peinit's event loop: within one iteration
 * signals come first, the shutdown deadline timer next, everything else
 * after, ties broken by arrival order, and the power button shares the top
 * priority with signals. A ranking is only visible when two sources are
 * ready in the same epoll wait, and an idle PID 1 answers every event the
 * moment it arrives — so on its own no guest ever sees two at once.
 *
 * This makes them coincide. It seizes PID 1 with ptrace and interrupts it,
 * which parks it in a ptrace-stop: it runs no code, but the kernel carries
 * on queueing what would wake it — a pending signal, a readable socket, a
 * key press on an input device — onto its epoll instance's ready list, in
 * the order they happen. When this detaches, PID 1's epoll wait returns
 * all of them in one batch.
 *
 * init cannot be stopped with SIGSTOP and does not live in a cgroup that
 * can be frozen; a ptrace-stop is the one pause the kernel offers, and
 * whether it is available at all is a question of the image's process
 * protection. The tool reports a refused attach rather than failing
 * silently, so a test can tell "PID 1 could not be paused" from "PID 1
 * handled things in the wrong order".
 *
 * Usage:
 *   pt-pause1 OUT SECS
 *
 * Appends to OUT:
 *
 *   paused                     PID 1 is in a ptrace-stop
 *   resumed                    detached; PID 1 is running again
 *   seize rc=-1 errno=1 …      the attach was refused, and nothing else
 *                              happened
 *
 * Like the other pt-* tools it is staged into the guest rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static FILE *out;

static void say(const char *what, long rc)
{
    if (rc < 0)
        fprintf(out, "%s rc=-1 errno=%d %s\n", what, errno, strerror(errno));
    else
        fprintf(out, "%s\n", what);
    fflush(out);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: pt-pause1 OUT SECS\n");
        return 64;
    }
    out = fopen(argv[1], "a");
    if (!out) {
        fprintf(stderr, "pt-pause1: %s: %s\n", argv[1], strerror(errno));
        return 2;
    }
    unsigned secs = (unsigned)atoi(argv[2]);

    /* SEIZE rather than ATTACH: ATTACH stops the tracee with a SIGSTOP,
     * which init would receive as a signal on its signalfd once it is no
     * longer traced. INTERRUPT stops it without a signal. */
    if (ptrace(PTRACE_SEIZE, 1, 0, 0) < 0) { say("seize", -1); return 3; }
    if (ptrace(PTRACE_INTERRUPT, 1, 0, 0) < 0) { say("interrupt", -1); return 3; }
    int status = 0;
    if (waitpid(1, &status, __WALL) < 0) { say("waitpid", -1); return 3; }
    if (!WIFSTOPPED(status)) {
        fprintf(out, "not stopped status=0x%x\n", status);
        fflush(out);
        return 3;
    }
    say("paused", 0);
    sleep(secs);
    if (ptrace(PTRACE_DETACH, 1, 0, 0) < 0) { say("detach", -1); return 3; }
    say("resumed", 0);
    return 0;
}
