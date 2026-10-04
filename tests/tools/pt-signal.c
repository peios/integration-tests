/* pt-signal — send a signal to a process, some number of times, a fixed
 * interval apart, from inside the guest.
 *
 * The image's PID 1, authd and eventd are PIP-signed at the TCB tier, and
 * PIP refuses a non-dominant process every signal to them (PKM §3.7), so
 * the shell's `kill` cannot reach them. Staged with
 * `peinit.tool("pt-signal", {signed = true})`, this one is signed at the
 * same tier and can.
 *
 * It is a guest command rather than a series of agent calls on purpose:
 * a test that signals PID 1 several times a second apart wants all of
 * them sent even after the first has begun a shutdown that takes the
 * agent down with it.
 *
 * Usage:
 *   pt-signal PID SIGNUM [COUNT [INTERVAL_SECS]]
 *
 * Exits 0 when every send succeeded; otherwise prints the failing call
 * and its errno to stderr and exits 1.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: pt-signal PID SIGNUM [COUNT [INTERVAL_SECS]]\n");
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    int sig = atoi(argv[2]);
    int count = argc > 3 ? atoi(argv[3]) : 1;
    unsigned interval = argc > 4 ? (unsigned)atoi(argv[4]) : 1;

    for (int i = 0; i < count; i++) {
        if (i > 0)
            sleep(interval);
        if (kill(pid, sig) != 0) {
            fprintf(stderr, "kill(%d, %d) rc=-1 errno=%d (%s)\n",
                    (int)pid, sig, errno, strerror(errno));
            return 1;
        }
    }
    return 0;
}
