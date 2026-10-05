/* pt-shutwatch — watch PID 1's last turn from outside it.
 *
 * The end of a graceful shutdown (Peinit TRM §12.2 steps 6-8, §12.4) is
 * the part of peinit a test has never been able to see. It prints
 * nothing when it works, what it would print is written after a
 * reboot(2) that does not return (PEI-827), and the machine it ran on is
 * gone a moment later. So the seed write, the unmount order, the
 * read-only remounts and the sync were asserted only by their one
 * visible consequence: the kernel's own "reboot: Power down".
 *
 * This is a witness that stands outside PID 1 and reports what it does
 * while it does it, on the console, so the host has the record after the
 * guest is gone. Three sources, all read live:
 *
 *   trace   ftrace syscall events for PID 1 alone — umount2, mount,
 *           rename, fsync, sync, reboot, getrandom, and the write and
 *           close calls that belong to the seed — with their arguments
 *           and results. Syscall events in this kernel carry the
 *           user-space strings their path arguments point at, so a line
 *           names the mount point or file rather than a pointer.
 *   fs      inotify on the seed's directory, and on the seed landing:
 *           its size, its first bytes, its security descriptor, and
 *           which service cgroups still held a process at that moment.
 *   mount   PID 1's own mount table, /proc/1/mountinfo, polled for
 *           changes: which mounts went, which were remounted and how.
 *
 * Standing outside PID 1 without disturbing it is the whole trick, and it
 * is why this runs in a mount namespace of its own. A watcher in PID 1's
 * namespace would change the thing it watches: an open /proc/1/mountinfo
 * would hold /proc busy, so the unmount step's outcomes would not be the
 * ones a real shutdown has. After unshare(CLONE_NEWNS) and a recursive
 * MS_PRIVATE, everything this process holds — its descriptors, its
 * working directory, the tracefs it mounts — belongs to copies of the
 * mounts, not to PID 1's, and no unmount propagates either way. The one
 * thing shared is the filesystems themselves, which is what inotify and
 * the descriptor read need.
 *
 * tracefs needs one more step. It carries no security descriptors, and
 * KACS refuses every file on a filesystem it has no policy for, SYSTEM
 * included. This sets the tracefs superblock's mount policy to synthesise
 * SYSTEM-only descriptors (SeTcb, which the agent's token holds). PID 1
 * has tracefs mounted nowhere, so it sees no difference.
 *
 * Holding the machine up (--hold N)
 *
 * The finalising turn is tens of milliseconds of syscalls ending in
 * reboot(2), and a witness forwarding each one to a console can fall
 * behind it: the kernel powers the machine off with the tail of the
 * record still unwritten. --hold makes the record complete. It disables
 * SeShutdownPrivilege on PID 1's token, which is the KACS privilege
 * behind CAP_SYS_BOOT, so PID 1's reboot(2) fails with EPERM and peinit
 * enters its failed-shutdown state (§12.4) instead of the machine going
 * away. Every step before the reboot is the one a real shutdown takes;
 * only the kernel's answer differs. After the N-th failed reboot(2) the
 * witness re-enables the privilege, so peinit's next once-a-second retry
 * succeeds and the machine goes down as it would have.
 *
 * This process does the adjusting itself, through a handle on PID 1's
 * token opened once when the hold is armed and kept for the release.
 * It cannot hand the job to `token`: PID 1 is PIP-signed at the TCB
 * tier, and opening its token needs a caller that dominates it (PKM
 * §3.7). This binary is staged TCB-signed; `/usr/bin/token`, a fresh
 * exec, is not, and is refused.
 *
 * Usage:
 *   pt-shutwatch [--seed PATH] [--out PATH] [--pid PID] [--hold N]
 *
 * --seed defaults to /var/state/peinit/random-seed and its directory
 * must exist. --out defaults to /dev/console. --pid defaults to 1. --hold
 * defaults to 0, meaning PID 1's privileges are left alone.
 *
 * It detaches at once, so `vm:run` returns, and prints `pt-sw N ready …`
 * once every source is armed. Every line it writes is `pt-sw N …`, N
 * counting up from 1; a test filters the console on that prefix. A
 * source that could not be armed says so (`pt-sw N error …`) and the
 * others carry on.
 *
 * Like the suite's other tools it is staged into the guest by a test
 * rather than packaged. It is test apparatus.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* KACS (pkm/uapi/pkm/syscall.h, file.h, sd.h, token.h): read a security
 * descriptor by path, set a superblock's mount policy, and open and
 * adjust another process's token. */
#define SYS_KACS_OPEN_PROCESS_TOKEN 1001
#define SYS_KACS_GET_SD 1021
#define SYS_KACS_SET_MOUNT_POLICY 1027
#define KACS_TOKEN_ADJUST_PRIVS 0x0020u
#define KACS_PRIVILEGE_ATTR_ENABLED 0x00000002u
#define KACS_SE_SHUTDOWN_PRIVILEGE_BIT 19u
#define KACS_IOC_ADJUST_PRIVS 0x40184B01u /* _IOW('K', 1, struct kacs_adjust_privs_args) */

struct kacs_adjust_privs_args {
    unsigned int count;
    unsigned int pad;
    unsigned long long data_ptr;
    unsigned long long previous_enabled;
};

struct kacs_priv_entry {
    unsigned int luid;
    unsigned int attributes;
};
#define KACS_SECINFO_OWNER 0x1u
#define KACS_SECINFO_GROUP 0x2u
#define KACS_SECINFO_DACL 0x4u
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
    /* owner S-1-5-18 */
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    /* group S-1-5-18 */
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    /* DACL: revision 2, size 0x1c, one ACE */
    0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
    /* ACCESS_ALLOWED, OI|CI, size 0x14, GENERIC_ALL, S-1-5-18 */
    0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
};

/* ---- output ------------------------------------------------------------
 *
 * Lines are gathered and written in one write(2) per batch rather than
 * one per line. Each write to the virtio console is a round trip to the
 * host, and the finalising turn produces dozens of lines in a few
 * milliseconds; per-line writes are what let the record fall behind. */

static int out = -1;
static unsigned long seq;
static char out_buf[32768];
static size_t out_len;

static void flush_out(void)
{
    size_t done = 0;
    while (done < out_len) {
        ssize_t w = write(out, out_buf + done, out_len - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        done += (size_t)w;
    }
    out_len = 0;
}

static void say(const char *fmt, ...)
{
    char line[8192];
    int n = snprintf(line, sizeof line, "pt-sw %lu ", ++seq);
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof line - (size_t)n - 1, fmt, ap);
    va_end(ap);
    if (m < 0) return;
    size_t len = (size_t)n + (size_t)m;
    if (len > sizeof line - 2) len = sizeof line - 2;
    line[len++] = '\n';
    if (out_len + len > sizeof out_buf) flush_out();
    memcpy(out_buf + out_len, line, len);
    out_len += len;
}

static int write_file(const char *path, const char *text, int trunc)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC | (trunc ? O_TRUNC : 0));
    if (fd < 0) return -1;
    ssize_t w = write(fd, text, strlen(text));
    int saved = errno;
    close(fd);
    errno = saved;
    return w < 0 ? -1 : 0;
}

/* ---- holding PID 1's reboot -------------------------------------------- */

static pid_t watched = 1;
static int hold_after;
static int failed_reboots;
static int released;

/* A handle on the watched process's token, with ADJUST_PRIVS: opened
 * when the hold is armed, kept for the release. */
static int watched_token = -1;

/* Open the watched process's token. 0, or the errno that refused it. */
static int open_watched_token(void)
{
    int pidfd = (int)syscall(SYS_pidfd_open, watched, 0);
    if (pidfd < 0) return errno;
    long fd = syscall(SYS_KACS_OPEN_PROCESS_TOKEN, pidfd, KACS_TOKEN_ADJUST_PRIVS);
    int saved = errno;
    close(pidfd);
    if (fd < 0) return saved;
    watched_token = (int)fd;
    return 0;
}

/* Enable or disable SeShutdownPrivilege on the watched process's token,
 * as `token adjust privs SeShutdown=enabled|disabled --pid PID` would.
 * 0, or the errno that refused it. */
static int set_shutdown_privilege(int enabled)
{
    if (watched_token < 0) return EBADF;
    struct kacs_priv_entry entry = {
        .luid = KACS_SE_SHUTDOWN_PRIVILEGE_BIT,
        .attributes = enabled ? KACS_PRIVILEGE_ATTR_ENABLED : 0,
    };
    struct kacs_adjust_privs_args args;
    memset(&args, 0, sizeof args);
    args.count = 1;
    args.data_ptr = (unsigned long long)(unsigned long)&entry;
    return ioctl(watched_token, KACS_IOC_ADJUST_PRIVS, &args) < 0 ? errno : 0;
}

/* ---- the trace source ------------------------------------------------ */

static char tracing[256];

static int find_tracefs(void)
{
    static const char *candidates[] = {
        "/sys/kernel/tracing",
        "/sys/kernel/debug/tracing",
    };
    char probe[320];
    for (size_t i = 0; i < sizeof candidates / sizeof *candidates; i++) {
        snprintf(probe, sizeof probe, "%s/trace_pipe", candidates[i]);
        if (access(probe, F_OK) == 0) {
            snprintf(tracing, sizeof tracing, "%s", candidates[i]);
            return 0;
        }
    }
    /* Not mounted in this namespace. Mounting it here is invisible to
     * PID 1: this namespace is private. */
    if (mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, NULL) < 0) {
        say("error trace mount tracefs errno=%d", errno);
        return -1;
    }
    snprintf(tracing, sizeof tracing, "/sys/kernel/tracing");

    int root = open(tracing, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        say("error trace open tracefs root errno=%d", errno);
        return -1;
    }
    struct kacs_mount_policy_args args;
    memset(&args, 0, sizeof args);
    args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
    args.template_sd_ptr = (unsigned long long)(unsigned long)system_only_sd;
    args.template_sd_len = sizeof system_only_sd;
    long rc = syscall(SYS_KACS_SET_MOUNT_POLICY, root, &args, sizeof args);
    int saved = errno;
    close(root);
    if (rc < 0) {
        say("error trace mount policy errno=%d", saved);
        return -1;
    }
    return 0;
}

static int tracing_write(const char *file, const char *text, int trunc)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", tracing, file);
    if (write_file(path, text, trunc) < 0) {
        say("error trace write %s errno=%d", file, errno);
        return -1;
    }
    return 0;
}

/* The syscalls worth seeing. Enter and exit for each, so a result is on
 * the record beside its call. */
static const char *traced[] = {
    "umount", "mount", "rename", "renameat", "renameat2", "fsync",
    "fdatasync", "sync", "syncfs", "reboot", "getrandom", "write", "close",
};

static int arm_trace(void)
{
    if (find_tracefs() < 0) return -1;
    if (tracing_write("tracing_on", "0", 1) < 0) return -1;
    if (tracing_write("trace", "", 1) < 0) return -1;
    /* Wake a reader on every event, not when the buffer is half full. */
    tracing_write("buffer_percent", "0", 1);
    char text[32];
    snprintf(text, sizeof text, "%d", (int)watched);
    if (tracing_write("set_event_pid", text, 1) < 0) return -1;
    /* Clear, then enable each event on its own write. An event this
     * kernel does not have is reported and skipped, not fatal. */
    if (tracing_write("set_event", "", 1) < 0) return -1;
    for (size_t i = 0; i < sizeof traced / sizeof *traced; i++) {
        char event[96];
        snprintf(event, sizeof event, "syscalls:sys_enter_%s", traced[i]);
        if (tracing_write("set_event", event, 0) < 0) continue;
        snprintf(event, sizeof event, "syscalls:sys_exit_%s", traced[i]);
        tracing_write("set_event", event, 0);
    }
    if (tracing_write("tracing_on", "1", 1) < 0) return -1;

    char path[512];
    snprintf(path, sizeof path, "%s/trace_pipe", tracing);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) say("error trace open trace_pipe errno=%d", errno);
    return fd;
}

static int contains(const char *line, const char *needle)
{
    return strstr(line, needle) != NULL;
}

/* Descriptors a kept line named, so their close is kept too: the fd the
 * seed was written through, and every fd that was flushed. */
#define MAX_TRACKED 16
static char tracked[MAX_TRACKED][24];

/* The value after "(fd: " in an enter line, up to its delimiter. */
static int fd_token(const char *line, char *out_tok, size_t cap)
{
    const char *p = strstr(line, "(fd: ");
    if (!p) return 0;
    p += 5;
    size_t n = 0;
    while (p[n] && p[n] != ',' && p[n] != ')' && n + 1 < cap) n++;
    memcpy(out_tok, p, n);
    out_tok[n] = '\0';
    return n > 0;
}

static void track_fd(const char *line)
{
    char tok[24];
    if (!fd_token(line, tok, sizeof tok)) return;
    for (size_t i = 0; i < MAX_TRACKED; i++) {
        if (strcmp(tracked[i], tok) == 0) return;
    }
    for (size_t i = 0; i < MAX_TRACKED; i++) {
        if (!tracked[i][0]) {
            snprintf(tracked[i], sizeof tracked[i], "%s", tok);
            return;
        }
    }
}

static int untrack_fd(const char *line)
{
    char tok[24];
    if (!fd_token(line, tok, sizeof tok)) return 0;
    for (size_t i = 0; i < MAX_TRACKED; i++) {
        if (tracked[i][0] && strcmp(tracked[i], tok) == 0) {
            tracked[i][0] = '\0';
            return 1;
        }
    }
    return 0;
}

/* Whether a trace line is worth forwarding. Most of what PID 1 writes and
 * closes during a shutdown is cgroup and console traffic; only the calls
 * that belong to the seed or the mount table are kept. `pending` holds
 * the name of an enter line that was kept, so its exit is kept too. */
static int keep_trace_line(const char *line, char *pending, size_t pending_cap)
{
    static const char *always[] = {
        "sys_umount", "sys_mount", "sys_rename", "sys_fdatasync",
        "sys_sync", "sys_syncfs", "sys_reboot", "sys_getrandom",
    };
    for (size_t i = 0; i < sizeof always / sizeof *always; i++) {
        if (contains(line, always[i])) return 1;
    }
    if (contains(line, "sys_fsync(")) {
        track_fd(line);
        return 1;
    }
    if (contains(line, "sys_fsync ->")) return 1;
    if (contains(line, "sys_write(")) {
        /* The seed is the only 512-byte write PID 1 makes. */
        if (contains(line, "count: 0x200")) {
            track_fd(line);
            snprintf(pending, pending_cap, "sys_write ->");
            return 1;
        }
        return 0;
    }
    if (contains(line, "sys_close(")) {
        if (untrack_fd(line)) {
            snprintf(pending, pending_cap, "sys_close ->");
            return 1;
        }
        return 0;
    }
    if (pending[0] && contains(line, pending)) {
        pending[0] = '\0';
        return 1;
    }
    return 0;
}

static char trace_buf[65536];
static size_t trace_len;
static char trace_pending[32];

static void note_reboot_result(const char *line)
{
    if (!hold_after || released || !contains(line, "sys_reboot ->")) return;
    if (contains(line, "-> 0x0")) return;
    if (++failed_reboots < hold_after) return;
    int rc = set_shutdown_privilege(1);
    released = 1;
    say("hold released after=%d rc=%d", failed_reboots, rc);
}

static void drain_trace(int fd)
{
    for (;;) {
        ssize_t r = read(fd, trace_buf + trace_len, sizeof trace_buf - trace_len - 1);
        if (r <= 0) break;
        trace_len += (size_t)r;
        trace_buf[trace_len] = '\0';
        char *start = trace_buf;
        char *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';
            if (keep_trace_line(start, trace_pending, sizeof trace_pending)) {
                /* Trim the task column's leading padding. */
                while (*start == ' ') start++;
                say("trace %s", start);
                note_reboot_result(start);
            }
            start = nl + 1;
        }
        size_t rest = trace_len - (size_t)(start - trace_buf);
        memmove(trace_buf, start, rest);
        trace_len = rest;
        if (trace_len >= sizeof trace_buf - 1) trace_len = 0;
    }
}

/* ---- the mount source ------------------------------------------------ */

#define MAX_MOUNTS 512

struct mount_entry {
    long id;
    char point[256];
    char opts[256];
};

static struct mount_entry mounts[MAX_MOUNTS];
static size_t mount_count;

/* Decode mountinfo's octal escapes (\040 for a space and so on). */
static void unescape_octal(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' && r[2] >= '0' && r[2] <= '7'
            && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 3;
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

static size_t read_mounts(int fd, struct mount_entry *into, size_t cap)
{
    static char text[262144];
    size_t len = 0;
    if (lseek(fd, 0, SEEK_SET) < 0) return 0;
    for (;;) {
        ssize_t r = read(fd, text + len, sizeof text - len - 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        len += (size_t)r;
        if (len >= sizeof text - 1) break;
    }
    text[len] = '\0';

    size_t n = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line && n < cap;
         line = strtok_r(NULL, "\n", &save)) {
        /* id parent major:minor root point opts [optional...] - fstype source superopts */
        char *fields[16];
        size_t f = 0;
        char *fsave = NULL;
        for (char *tok = strtok_r(line, " ", &fsave); tok && f < 16;
             tok = strtok_r(NULL, " ", &fsave)) {
            fields[f++] = tok;
        }
        if (f < 6) continue;
        into[n].id = strtol(fields[0], NULL, 10);
        snprintf(into[n].point, sizeof into[n].point, "%s", fields[4]);
        unescape_octal(into[n].point);
        /* Per-mount options, then the superblock's, so a remount shows
         * whichever of the two it changed. */
        const char *super = "";
        for (size_t i = 6; i + 3 < f; i++) {
            if (strcmp(fields[i], "-") == 0) { super = fields[i + 3]; break; }
        }
        snprintf(into[n].opts, sizeof into[n].opts, "%s|%s", fields[5], super);
        n++;
    }
    return n;
}

static int depth(const char *point)
{
    int d = 0;
    for (const char *p = point; *p; p++) {
        if (*p == '/' && p[1] != '\0' && p[1] != '/') d++;
    }
    return d;
}

static char seed_path[512];
static char seed_dir[512];
static char seed_name[256];
static ino_t seed_inode_at_start;

/* Where the seed stands right now: a new file, the one that was there
 * when this started, or none. */
static const char *seed_state(void)
{
    struct stat st;
    if (stat(seed_path, &st) < 0) return "none";
    return st.st_ino == seed_inode_at_start ? "old" : "new";
}

/* Each read of the table is one batch. Mounts that changed between two
 * reads are reported together under one batch number, in table order —
 * which is NOT the order they changed in. Only the order of batches is
 * the order of events; the trace is the ordered record. */
static unsigned long batch;

static void diff_mounts(int fd)
{
    static struct mount_entry now[MAX_MOUNTS];
    size_t n = read_mounts(fd, now, MAX_MOUNTS);
    batch++;
    for (size_t i = 0; i < mount_count; i++) {
        int found = 0;
        for (size_t j = 0; j < n; j++) {
            if (now[j].id != mounts[i].id) continue;
            found = 1;
            if (strcmp(now[j].opts, mounts[i].opts) != 0) {
                say("mount changed %s batch=%lu depth=%d %s -> %s", mounts[i].point, batch,
                    depth(mounts[i].point), mounts[i].opts, now[j].opts);
            }
            break;
        }
        if (!found) {
            say("mount gone %s batch=%lu depth=%d seed=%s", mounts[i].point, batch,
                depth(mounts[i].point), seed_state());
        }
    }
    for (size_t j = 0; j < n; j++) {
        int found = 0;
        for (size_t i = 0; i < mount_count; i++) {
            if (mounts[i].id == now[j].id) { found = 1; break; }
        }
        if (!found) say("mount new %s batch=%lu %s", now[j].point, batch, now[j].opts);
    }
    memcpy(mounts, now, n * sizeof *now);
    mount_count = n;
}

/* ---- the fs source --------------------------------------------------- */

static void hex(const unsigned char *bytes, size_t len, char *outbuf, size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < len && o + 2 < cap; i++) {
        outbuf[o++] = digits[bytes[i] >> 4];
        outbuf[o++] = digits[bytes[i] & 0xf];
    }
    outbuf[o] = '\0';
}

/* The service cgroups that still hold a process, as a comma-separated
 * list, or "none". A service root's cgroup.events says `populated 1`
 * while anything anywhere beneath it is alive. */
static void populated_services(char *outbuf, size_t cap)
{
    static const char *tree = "/sys/fs/cgroup/peinit";
    outbuf[0] = '\0';
    int dfd = open(tree, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        snprintf(outbuf, cap, "error:%d", errno);
        return;
    }
    char listing[16384];
    size_t used = 0;
    /* getdents64 by hand keeps this to raw syscalls. */
    for (;;) {
        long n = syscall(SYS_getdents64, dfd, listing + used, sizeof listing - used);
        if (n <= 0) break;
        used += (size_t)n;
        if (used >= sizeof listing) break;
    }
    close(dfd);
    size_t o = 0;
    for (size_t pos = 0; pos < used;) {
        unsigned short reclen;
        memcpy(&reclen, listing + pos + 16, sizeof reclen);
        unsigned char type = (unsigned char)listing[pos + 18];
        const char *name = listing + pos + 19;
        pos += reclen;
        if (type != 4 /* DT_DIR */ || name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof path, "%s/%s/cgroup.events", tree, name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char events[256];
        ssize_t r = read(fd, events, sizeof events - 1);
        close(fd);
        if (r <= 0) continue;
        events[r] = '\0';
        if (!strstr(events, "populated 1")) continue;
        int w = snprintf(outbuf + o, cap - o, "%s%s", o ? "," : "", name);
        if (w < 0 || (size_t)w >= cap - o) break;
        o += (size_t)w;
    }
    if (o == 0) snprintf(outbuf, cap, "none");
}

static void report_seed(void)
{
    struct stat st;
    if (stat(seed_path, &st) < 0) {
        say("seed stat errno=%d", errno);
        return;
    }
    unsigned char head[16] = { 0 };
    ssize_t got = -1;
    int fd = open(seed_path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        got = read(fd, head, sizeof head);
        close(fd);
    }
    char head_hex[40];
    hex(head, got > 0 ? (size_t)got : 0, head_hex, sizeof head_hex);

    unsigned char sd[1024];
    long sd_len = syscall(SYS_KACS_GET_SD, AT_FDCWD, seed_path,
                          KACS_SECINFO_OWNER | KACS_SECINFO_GROUP | KACS_SECINFO_DACL,
                          sd, sizeof sd, 0);
    char sd_hex[2 * sizeof sd + 1];
    if (sd_len > 0 && (size_t)sd_len <= sizeof sd) {
        hex(sd, (size_t)sd_len, sd_hex, sizeof sd_hex);
    } else {
        snprintf(sd_hex, sizeof sd_hex, "error:%d", errno);
    }
    char populated[2048];
    populated_services(populated, sizeof populated);
    say("seed landed size=%lld inode=%s head=%s sd=%s populated=%s", (long long)st.st_size,
        st.st_ino == seed_inode_at_start ? "old" : "new", head_hex, sd_hex, populated);
}

static void drain_fs(int fd)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r <= 0) break;
        for (char *p = buf; p < buf + r;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            const char *name = ev->len ? ev->name : "";
            char kinds[128] = "";
            if (ev->mask & IN_OPEN) strcat(kinds, "open,");
            if (ev->mask & IN_CLOSE_NOWRITE) strcat(kinds, "close_nowrite,");
            if (ev->mask & IN_CREATE) strcat(kinds, "create,");
            if (ev->mask & IN_MODIFY) strcat(kinds, "modify,");
            if (ev->mask & IN_CLOSE_WRITE) strcat(kinds, "close_write,");
            if (ev->mask & IN_MOVED_FROM) strcat(kinds, "moved_from,");
            if (ev->mask & IN_MOVED_TO) strcat(kinds, "moved_to,");
            if (ev->mask & IN_DELETE) strcat(kinds, "delete,");
            if (ev->mask & IN_ATTRIB) strcat(kinds, "attrib,");
            size_t kl = strlen(kinds);
            if (kl) kinds[kl - 1] = '\0';
            /* An event on the watched directory itself has no name; say
             * "." so the line has a fixed number of fields. */
            say("fs %s %s cookie=%u", kinds[0] ? kinds : "other", name[0] ? name : ".",
                ev->cookie);
            if ((ev->mask & IN_MOVED_TO) && strcmp(name, seed_name) == 0) report_seed();
            p += sizeof *ev + ev->len;
        }
    }
}

/* ---- setup and the loop ---------------------------------------------- */

static void detach_stdio(void)
{
    /* Whatever was inherited belongs to PID 1's namespace — the agent's
     * shell handed over its /dev/null and its pipes. Drop all of it, so
     * nothing this process holds pins one of PID 1's mounts. */
    for (int fd = 0; fd < 1024; fd++) close(fd);
    int null = open("/dev/null", O_RDWR);
    if (null >= 0 && null != 0) { dup2(null, 0); close(null); }
    dup2(0, 1);
    dup2(0, 2);
}

int main(int argc, char **argv)
{
    const char *seed = "/var/state/peinit/random-seed";
    const char *out_path = "/dev/console";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) seed = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) watched = (pid_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--hold") == 0 && i + 1 < argc) hold_after = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: pt-shutwatch [--seed PATH] [--out PATH] [--pid PID]"
                            " [--hold N]\n");
            return 2;
        }
    }
    snprintf(seed_path, sizeof seed_path, "%s", seed);
    snprintf(seed_dir, sizeof seed_dir, "%s", seed);
    char *slash = strrchr(seed_dir, '/');
    if (!slash || slash == seed_dir) {
        fprintf(stderr, "pt-shutwatch: --seed needs a directory part\n");
        return 2;
    }
    *slash = '\0';
    snprintf(seed_name, sizeof seed_name, "%s", slash + 1);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child > 0) return 0;
    setsid();

    int unshared = unshare(CLONE_NEWNS) == 0 ? 0 : errno;
    int privatised = 0;
    if (!unshared) {
        privatised = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 ? 0 : errno;
    }
    if (chdir("/") < 0) { /* the copy of the root; nothing to do about it */ }
    detach_stdio();
    out = open(out_path, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (out < 0) return 1;
    if (unshared || privatised) {
        /* Refuse to watch from inside PID 1's namespace: the watcher
         * would change what it watches. */
        say("error namespace unshare=%d private=%d", unshared, privatised);
        flush_out();
        return 1;
    }

    struct stat st;
    seed_inode_at_start = stat(seed_path, &st) == 0 ? st.st_ino : 0;

    int trace_fd = arm_trace();

    int fs_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fs_fd >= 0 && inotify_add_watch(fs_fd, seed_dir,
                                         IN_OPEN | IN_CLOSE_NOWRITE | IN_CREATE | IN_MODIFY
                                             | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO
                                             | IN_DELETE | IN_ATTRIB) < 0) {
        say("error fs watch %s errno=%d", seed_dir, errno);
        close(fs_fd);
        fs_fd = -1;
    }

    char mountinfo[64];
    snprintf(mountinfo, sizeof mountinfo, "/proc/%d/mountinfo", (int)watched);
    int mount_fd = open(mountinfo, O_RDONLY | O_CLOEXEC);
    if (mount_fd < 0) {
        say("error mount open %s errno=%d", mountinfo, errno);
    } else {
        mount_count = read_mounts(mount_fd, mounts, MAX_MOUNTS);
        for (size_t i = 0; i < mount_count; i++) {
            say("mount at-start %s depth=%d %s", mounts[i].point, depth(mounts[i].point),
                mounts[i].opts);
        }
    }

    int held = 0;
    if (hold_after > 0) {
        int rc = open_watched_token();
        if (rc != 0) {
            say("error hold open token errno=%d", rc);
        } else {
            rc = set_shutdown_privilege(0);
            if (rc != 0) say("error hold adjust errno=%d", rc);
        }
        held = rc == 0;
    }

    say("ready trace=%d fs=%d mount=%d hold=%d mounts=%zu seed=%s", trace_fd >= 0, fs_fd >= 0,
        mount_fd >= 0, held, mount_count, seed_inode_at_start ? "present" : "absent");
    flush_out();

    for (;;) {
        struct pollfd fds[3] = {
            { .fd = trace_fd, .events = POLLIN },
            { .fd = fs_fd, .events = POLLIN },
            { .fd = mount_fd, .events = POLLPRI },
        };
        int r = poll(fds, 3, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            say("error poll errno=%d", errno);
            flush_out();
            return 1;
        }
        /* The trace first: it is the ordered record, and the other two
         * report state as of the moment they are read. */
        if (trace_fd >= 0 && (fds[0].revents & POLLIN)) drain_trace(trace_fd);
        if (fs_fd >= 0 && (fds[1].revents & POLLIN)) drain_fs(fs_fd);
        if (mount_fd >= 0 && (fds[2].revents & (POLLPRI | POLLERR))) diff_mounts(mount_fd);
        flush_out();
    }
}
