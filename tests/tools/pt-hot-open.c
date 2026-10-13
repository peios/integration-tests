/* PEI-1492: measured open/close contention on a real StrataFS system view.
 * Usage: pt-hot-open PATH WORKERS ITERATIONS
 * Fork and readiness costs are excluded; all workers start at one pipe gate.
 * Timings are evidence, never a hardware-dependent pass/fail threshold.
 * No mount, descriptor, token, privilege or signing policy is changed here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* pkm/kernel/include/linux/kacs_stratafs.h */
#define STRATAFS_MAGIC 0x53545241UL
#define MAX_WORKERS 8
#define DEADLINE_NS (110ULL * 1000000000ULL)

struct result {
    uint64_t attempts, opens, closes, elapsed_ns;
    unsigned worker;
    int error;
};

static pid_t children[MAX_WORKERS];
static unsigned child_count;

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void stop_children(void)
{
    for (unsigned i = 0; i < child_count; ++i)
        if (children[i] > 0)
            kill(children[i], SIGKILL);
    for (unsigned i = 0; i < child_count; ++i)
        if (children[i] > 0)
            while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
}

static void fail(const char *what)
{
    perror(what);
    stop_children();
    exit(1);
}

static unsigned number(const char *text, unsigned max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !*text || *end || !n || n > max) {
        fprintf(stderr, "invalid count: %s (allowed 1..%u)\n", text, max);
        exit(2);
    }
    return (unsigned)n;
}

static int receive(int fd, void *buffer, size_t length, uint64_t deadline)
{
    size_t got = 0;
    while (got < length) {
        uint64_t now = now_ns();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int timeout = (int)((deadline - now + 999999) / 1000000);
        int ready = poll(&p, 1, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (!ready) { errno = ETIMEDOUT; return -1; }
        ssize_t n = read(fd, (char *)buffer + got, length - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EPIPE; return -1; }
        got += (size_t)n;
    }
    return 0;
}

static void worker(const char *path, unsigned id, unsigned iterations,
                   int ready, int gate, int done, uint64_t deadline)
{
    char byte = 1;
    if (write(ready, &byte, 1) != 1 || receive(gate, &byte, 1, deadline))
        _exit(2);
    struct result r = { .worker = id };
    uint64_t start = now_ns();
    for (unsigned i = 0; i < iterations; ++i) {
        ++r.attempts;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { r.error = errno; break; }
        ++r.opens;
        if (close(fd)) { r.error = errno; break; }
        ++r.closes;
    }
    r.elapsed_ns = now_ns() - start;
    /* One PIPE_BUF-sized record cannot interleave with another worker. */
    if (write(done, &r, sizeof r) != (ssize_t)sizeof r) _exit(2);
    _exit(r.error ? 1 : 0);
}

static void json_string(const char *text)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: pt-hot-open PATH WORKERS ITERATIONS\n");
        return 2;
    }
    unsigned workers = number(argv[2], MAX_WORKERS);
    unsigned iterations = number(argv[3], 1000000);
    struct statfs rootfs, targetfs;
    struct stat identity;
    struct utsname kernel;
    if (statfs("/", &rootfs) || uname(&kernel)) fail("root/kernel metadata");
    int probe = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (probe < 0) fail("open target probe");
    if (fstatfs(probe, &targetfs) || fstat(probe, &identity)) fail("target metadata");
    if (close(probe)) fail("close target probe");
    if ((unsigned long)targetfs.f_type != STRATAFS_MAGIC) {
        fprintf(stderr, "target %s is not StrataFS: fstatfs=0x%lx root=0x%lx\n",
                argv[1], (unsigned long)targetfs.f_type, (unsigned long)rootfs.f_type);
        return 1;
    }
    if (!S_ISREG(identity.st_mode)) {
        fprintf(stderr, "target is not a regular file\n");
        return 1;
    }

    int ready[2], gate[2], done[2];
    if (pipe2(ready, O_CLOEXEC) || pipe2(gate, O_CLOEXEC) || pipe2(done, O_CLOEXEC))
        fail("pipe");
    signal(SIGPIPE, SIG_IGN);
    uint64_t deadline = now_ns() + DEADLINE_NS;
    for (unsigned i = 0; i < workers; ++i) {
        pid_t pid = fork();
        if (pid < 0) fail("fork");
        if (!pid) {
            close(ready[0]); close(gate[1]); close(done[0]);
            worker(argv[1], i, iterations, ready[1], gate[0], done[1], deadline);
        }
        children[child_count++] = pid;
    }
    close(ready[1]); close(gate[0]); close(done[1]);
    char bytes[MAX_WORKERS] = {0};
    if (receive(ready[0], bytes, workers, deadline)) fail("workers ready");
    close(ready[0]);
    uint64_t start = now_ns();
    if (write(gate[1], bytes, workers) != (ssize_t)workers) fail("release workers");
    close(gate[1]);
    struct result results[MAX_WORKERS] = {0};
    unsigned completed = 0;
    uint64_t attempts = 0, opens = 0, closes = 0;
    int failed = 0;
    for (unsigned i = 0; i < workers; ++i) {
        struct result r;
        if (receive(done[0], &r, sizeof r, deadline)) fail("worker results");
        if (r.worker >= workers || results[r.worker].attempts) {
            errno = EPROTO; fail("invalid/duplicate worker result");
        }
        results[r.worker] = r;
        attempts += r.attempts; opens += r.opens; closes += r.closes;
        if (!r.error && r.attempts == iterations && r.opens == iterations && r.closes == iterations)
            ++completed;
        else failed = 1;
    }
    uint64_t elapsed = now_ns() - start;
    close(done[0]);
    for (unsigned i = 0; i < workers; ++i) {
        int status;
        pid_t waited;
        do { waited = waitpid(children[i], &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0) fail("waitpid");
        children[i] = 0;
        if (!WIFEXITED(status) || WEXITSTATUS(status)) failed = 1;
    }

    printf("{\"path\":"); json_string(argv[1]);
    printf(",\"kernel\":"); json_string(kernel.release);
    printf(",\"root_fstype\":\"0x%lx\",\"target_fstype\":\"0x%lx\","
           "\"dev\":%ju,\"inode\":%ju,\"workers\":%u,\"iterations\":%u,"
           "\"completed_workers\":%u,\"attempts\":%" PRIu64 ",\"opens\":%" PRIu64 ","
           "\"closes\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"operations_per_second\":%.3f,\"results\":[",
           (unsigned long)rootfs.f_type, (unsigned long)targetfs.f_type,
           (uintmax_t)identity.st_dev, (uintmax_t)identity.st_ino, workers, iterations,
           completed, attempts, opens, closes, elapsed,
           elapsed ? (double)closes * 1000000000.0 / (double)elapsed : 0.0);
    for (unsigned i = 0; i < workers; ++i) {
        const struct result *r = &results[i];
        printf("%s{\"worker\":%u,\"attempts\":%" PRIu64 ",\"opens\":%" PRIu64
               ",\"closes\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"errno\":%d}",
               i ? "," : "", i, r->attempts, r->opens, r->closes, r->elapsed_ns, r->error);
    }
    puts("]}");
    return failed ? 1 : 0;
}
