/* pt-fusehang — a FUSE mount whose daemon never answers.
 *
 * Anything that touches the mounted directory waits for a reply that
 * never comes — killably, as every FUSE request wait is — until the
 * daemon lets go of its descriptor. That makes it the one way a test can
 * hold a process at an exact point it cannot otherwise stop: a service
 * whose WorkingDirectory is inside the mount forks, and its child blocks
 * in chdir(2), after the fork and before exec. From peinit's side that
 * is a start whose job has not reached exec — the state a Starting
 * service's job is in for a moment on every launch, and which a test
 * otherwise cannot keep it in (Peinit TRM §12.2 step 3, "a Starting
 * service whose job never forked").
 *
 * Usage:
 *   pt-fusehang MOUNTPOINT
 *
 * Mounts, then leaves a detached daemon holding /dev/fuse open and reading
 * nothing, and prints `pt-fusehang: mounted MOUNTPOINT daemon=PID` once
 * the mount is in place. Killing the daemon aborts the connection: every
 * waiter then fails with ENOTCONN, and the mount can be unmounted.
 *
 * The superblock's KACS mount policy is set to synthesise SYSTEM-only
 * descriptors, as for any filesystem that carries none; without it KACS
 * would refuse the directory outright instead of letting the request reach
 * the daemon that will not answer.
 *
 * Like the suite's other tools it is staged into a guest by a test rather
 * than packaged. It is test apparatus.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SYS_KACS_SET_MOUNT_POLICY 1027
#define KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3u

struct kacs_mount_policy_args {
    unsigned int policy;
    unsigned int flags;
    unsigned int generation;
    unsigned int pad0;
    unsigned long long template_sd_ptr;
    unsigned int template_sd_len;
    unsigned int pad1;
};

/* O:SYG:SYD:(A;OICI;GA;;;SY), self-relative. */
static const unsigned char system_only_sd[] = {
    0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
};

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: pt-fusehang MOUNTPOINT\n");
        return 2;
    }
    const char *target = argv[1];

    int fuse = open("/dev/fuse", O_RDWR);
    if (fuse < 0) {
        perror("pt-fusehang: open /dev/fuse");
        return 1;
    }
    char options[128];
    snprintf(options, sizeof options,
             "fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other", fuse);
    if (mount("pt-fusehang", target, "fuse", MS_NOSUID | MS_NODEV, options) < 0) {
        perror("pt-fusehang: mount");
        return 1;
    }

    /* O_PATH reaches the mount's root without asking the daemon anything. */
    int root = open(target, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        perror("pt-fusehang: open mount root");
        return 1;
    }
    struct kacs_mount_policy_args args;
    memset(&args, 0, sizeof args);
    args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
    args.template_sd_ptr = (unsigned long long)(unsigned long)system_only_sd;
    args.template_sd_len = sizeof system_only_sd;
    if (syscall(SYS_KACS_SET_MOUNT_POLICY, root, &args, sizeof args) < 0) {
        perror("pt-fusehang: mount policy");
        return 1;
    }
    close(root);

    pid_t daemon = fork();
    if (daemon < 0) {
        perror("pt-fusehang: fork");
        return 1;
    }
    if (daemon == 0) {
        setsid();
        /* Hold the connection and answer nothing, ever. Nothing else is
         * kept open: stdio goes, so the caller's pipes are not held. */
        for (int fd = 0; fd < 1024; fd++) {
            if (fd != fuse) close(fd);
        }
        for (;;) pause();
    }
    close(fuse);
    printf("pt-fusehang: mounted %s daemon=%d\n", target, (int)daemon);
    return 0;
}
