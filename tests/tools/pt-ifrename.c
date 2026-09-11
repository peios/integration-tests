/* pt-ifrename — rename a network interface, taking it down first.
 *
 * TRM §2.3 step 9 says a loopback bring-up failure is a warning that lets
 * Phase 2 proceed. peinit finds the loopback by name — if_nametoindex("lo")
 * — so an interface that is not called `lo` when step 9 runs is a bring-up
 * that fails for a reason nothing else in the boot shares. The image ships
 * no `ip` and nothing else that can rename a link, which is what this is
 * for: an autorun script (Phase 1 step 7) runs it, and step 9 then finds no
 * `lo` to bring up.
 *
 * The kernel refuses to rename an interface that is up (EBUSY), so the
 * interface is brought down first when it is.
 *
 * Usage:
 *   pt-ifrename OLD NEW
 *
 * Prints `pt-ifrename: OLD -> NEW` on success and exits 0; on failure
 * prints the step and errno and exits 1.
 *
 * Like the other pt-* tools it is injected into the image rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *step, const char *name)
{
    fprintf(stderr, "pt-ifrename: %s %s failed: %s (errno %d)\n", step, name,
            strerror(errno), errno);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: pt-ifrename OLD NEW\n");
        return 2;
    }
    const char *old_name = argv[1];
    const char *new_name = argv[2];
    if (strlen(old_name) >= IFNAMSIZ || strlen(new_name) >= IFNAMSIZ) {
        fprintf(stderr, "pt-ifrename: interface names are at most %d bytes\n", IFNAMSIZ - 1);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return fail("socket", "AF_INET");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, old_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) return fail("SIOCGIFFLAGS", old_name);
    if (ifr.ifr_flags & IFF_UP) {
        ifr.ifr_flags &= ~IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) return fail("SIOCSIFFLAGS down", old_name);
    }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, old_name, IFNAMSIZ - 1);
    strncpy(ifr.ifr_newname, new_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCSIFNAME, &ifr) < 0) return fail("SIOCSIFNAME", old_name);

    close(fd);
    printf("pt-ifrename: %s -> %s\n", old_name, new_name);
    return 0;
}
