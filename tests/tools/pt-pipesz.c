/* pt-pipesz — how big is the pipe on this descriptor.
 *
 * TRM §11.3 says `MaxLogBufferPerService` is not a buffer peinit keeps: it
 * is applied as the capacity of the service's own output pipes, through
 * F_SETPIPE_SZ. The capacity is a property of the pipe, and the only way
 * to read it is F_GETPIPE_SZ on a descriptor for it — /proc has no field
 * for it and the image ships nothing that asks.
 *
 * A service holds the write ends, so this runs inside one and asks about
 * its own inherited descriptors.
 *
 * Usage:
 *   pt-pipesz OUT FD...
 *
 * Appends one line per FD to OUT — a file, because the descriptors being
 * asked about are usually this process's stdout and stderr:
 *
 *   fd=1 pipe_size=65536
 *   fd=2 errno=9 Bad file descriptor
 *
 * Like the other pt-* tools it is staged into the guest rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: pt-pipesz OUT FD...\n");
        return 64;
    }
    FILE *out = fopen(argv[1], "a");
    if (!out) {
        fprintf(stderr, "pt-pipesz: %s: %s\n", argv[1], strerror(errno));
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        int fd = atoi(argv[i]);
        int size = fcntl(fd, F_GETPIPE_SZ);
        if (size < 0)
            fprintf(out, "fd=%d errno=%d %s\n", fd, errno, strerror(errno));
        else
            fprintf(out, "fd=%d pipe_size=%d\n", fd, size);
    }
    return fclose(out) == 0 ? 0 : 2;
}
