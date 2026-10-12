/* PEI-746: race descriptor file attributes against closing the last table
 * reference. Run in a disposable KASAN guest; this is test apparatus only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Linux x86-64 file attribute ABI, also used by PKM. */
#define FILE_GETATTR 468
#define FILE_SETATTR 469
#define TARGET_FD 50
struct attributes {
    uint64_t xflags;
    uint32_t extsize, nextents, projid, cowextsize;
};
_Static_assert(sizeof(struct attributes) == 24, "file attribute ABI");

static atomic_int done;
struct result { long call; unsigned long ok, unsupported, badfd, unexpected; };

static int attribute(long call)
{
    struct attributes attr = {0};
    return syscall(call, TARGET_FD, "", &attr, sizeof(attr), AT_EMPTY_PATH);
}

static void *query(void *arg)
{
    struct result *r = arg;
    while (!atomic_load_explicit(&done, memory_order_relaxed)) {
        if (attribute(r->call) == 0) r->ok++;
        else if (errno == EOPNOTSUPP) r->unsupported++;
        else if (errno == EBADF) r->badfd++;
        else {
            if (!r->unexpected) fprintf(stderr, "syscall %ld errno=%d\n", r->call, errno);
            r->unexpected++;
        }
    }
    return NULL;
}

static int replace(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    int ret = dup3(fd, TARGET_FD, O_CLOEXEC);
    close(fd);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (replace(argv[1]) < 0) { perror("open/dup3"); return 1; }
    for (long call = FILE_GETATTR; call <= FILE_SETATTR; call++) {
        if (attribute(call) < 0 && errno != EOPNOTSUPP) {
            fprintf(stderr, "initial syscall %ld errno=%d\n", call, errno);
            return 1;
        }
    }
    struct result results[2] = {{.call = FILE_GETATTR}, {.call = FILE_SETATTR}};
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; i++) {
        int err = pthread_create(&threads[i], NULL, query, &results[i]);
        if (err) { fprintf(stderr, "pthread_create: %d\n", err); return 1; }
    }
    int failed = 0;
    for (unsigned i = 0; i < 30000; i++) {
        close(TARGET_FD);
        if (replace(argv[1]) < 0) { perror("replace"); failed = 1; break; }
        if (!(i % 32)) sched_yield();
    }
    atomic_store_explicit(&done, 1, memory_order_relaxed);
    for (unsigned i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
        struct result *r = &results[i];
        printf("syscall=%ld ok=%lu unsupported=%lu badfd=%lu unexpected=%lu\n",
               r->call, r->ok, r->unsupported, r->badfd, r->unexpected);
        failed |= r->unexpected != 0 || r->ok + r->unsupported == 0;
    }
    close(TARGET_FD);
    return failed;
}
