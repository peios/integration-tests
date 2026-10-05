/* pt-mntns — an ordinary program that builds itself a private mount table.
 *
 * PKM §3.13 makes a mount namespace a KACS object: any process may create
 * one without privilege, and what it may then do to its own table is
 * decided by the namespace's descriptor. The claim worth demonstrating is
 * the one a user sees — a program run by an ordinary principal, with no
 * privilege and no user namespace, reshaping its own world — so this is a
 * real executable the test runs under a minted token, not a sequence of
 * syscalls the agent issues on a worker's behalf.
 *
 * Usage:
 *
 *   pt-mntns root DIR
 *       The §3.13 private-root sequence, exactly as the TRM spells it:
 *         unshare(CLONE_NEWNS);
 *         mount(DIR, DIR, NULL, MS_BIND, NULL);
 *         chdir(DIR);
 *         pivot_root(".", ".");
 *         umount2(".", MNT_DETACH);
 *         chdir("/");
 *       then lists `/`. Prints one `step NAME ok` per step, one
 *       `entry NAME` per directory entry of the new `/` (`.` and `..`
 *       left out), and `done`. A refused step prints
 *       `step NAME fail errno=N` and exits 1.
 *
 *   pt-mntns clone FLAGS
 *       clone(2) with FLAGS (hex) | SIGCHLD and no new stack — fork-shaped.
 *       Prints `parent ns=LINK` (its /proc/self/ns/mnt), then either
 *       `clone fail errno=N`, or the child's `child ns=LINK` and
 *       `clone ok status=N`.
 *
 * Output goes through write(2), one line at a time, so nothing a forked
 * child inherits from a stdio buffer is printed twice.
 *
 * Like the other pt-* tools it is staged into the guest rather than
 * packaged (tests/tools/build.sh).
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void say(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int)sizeof(line) - 2)
        n = sizeof(line) - 2;
    line[n++] = '\n';
    if (write(1, line, n) < 0)
        _exit(3);
}

static void step(const char *name, long rc)
{
    if (rc < 0) {
        say("step %s fail errno=%d", name, errno);
        exit(1);
    }
    say("step %s ok", name);
}

static void ns_link(char *buf, size_t len)
{
    ssize_t n = readlink("/proc/self/ns/mnt", buf, len - 1);

    if (n < 0)
        snprintf(buf, len, "?errno=%d", errno);
    else
        buf[n] = '\0';
}

static int private_root(const char *dir)
{
    DIR *d;
    struct dirent *e;

    step("unshare", unshare(CLONE_NEWNS));
    step("bind", mount(dir, dir, NULL, MS_BIND, NULL));
    step("chdir-dir", chdir(dir));
    step("pivot_root", syscall(SYS_pivot_root, ".", "."));
    step("umount", umount2(".", MNT_DETACH));
    step("chdir-root", chdir("/"));

    d = opendir("/");
    if (!d) {
        say("step list fail errno=%d", errno);
        return 1;
    }
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        say("entry %s", e->d_name);
    }
    closedir(d);
    say("done");
    return 0;
}

static int do_clone(const char *hex)
{
    unsigned long flags = strtoul(hex, NULL, 16);
    char link[128];
    long pid;
    int status = 0;

    ns_link(link, sizeof(link));
    say("parent ns=%s", link);
    pid = syscall(SYS_clone, flags | SIGCHLD, 0, 0, 0, 0);
    if (pid < 0) {
        say("clone fail errno=%d", errno);
        return 0;
    }
    if (pid == 0) {
        ns_link(link, sizeof(link));
        say("child ns=%s", link);
        _exit(0);
    }
    if (waitpid(pid, &status, 0) < 0) {
        say("waitpid fail errno=%d", errno);
        return 1;
    }
    say("clone ok status=%d", status);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "root"))
        return private_root(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "clone"))
        return do_clone(argv[2]);
    say("usage: pt-mntns root DIR | pt-mntns clone FLAGS");
    return 2;
}
