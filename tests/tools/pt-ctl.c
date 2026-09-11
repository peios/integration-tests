/* pt-ctl — a control-socket client that says what came back, and when.
 *
 * The control socket (TRM §10.1, PSPU §4.5) is a Unix stream socket
 * carrying one compact JSON object per newline-terminated frame, in both
 * directions. svctl is the only client the image ships, and it is a
 * well-behaved one: one request per connection, answered before the next,
 * never oversized. Every claim about the socket's limits is about a client
 * that is not that — one that holds a connection idle, sends a frame past
 * MaxRequestSize, or pipelines a request behind a wait — so this is that
 * client.
 *
 * The step language is pt-jobs's, less what a stream cannot carry:
 *
 *   send JSON        send one frame and read its answer
 *   send-only JSON   send one frame and read nothing -- for pipelining
 *   send-raw TEXT    write TEXT in one send(2), `\n` meaning a newline,
 *                    and read nothing -- for bytes no well-formed frame
 *                    would carry, or several frames that must arrive in
 *                    a single read on the far side
 *   read             read one answer
 *   sleep N          hold the connection open, idle, for N seconds
 *
 * A bare JSON argument is `send JSON`. The newline that ends a frame is
 * added here; a JSON argument must not contain one.
 *
 * The socket defaults to /run/services/peinit/control.sock.
 *
 * Each answer prints two lines:
 *
 *   reply rc=213 at=1.204
 *   reply-json {"status":"ok",…}
 *
 * `rc` is the frame's length without its newline, and `at` is seconds
 * since the connect. End of file where an answer was expected prints
 * `reply closed at=…`; a send refused because the far end has gone prints
 * `send rc=-1 errno=…`. Either is the manager having closed the
 * connection, which is itself a claim several of the socket's rules make.
 *
 * Framing is by byte, as PSPU §4.5 requires of the manager: everything up
 * to a newline is one answer, and what follows it stays buffered for the
 * next `read`. Two answers can arrive in one read(2) — a pipelined pair
 * always can — and reading line by line without that buffer would drop
 * the second.
 *
 * Like pt-notify and pt-jobs it is injected into the image rather than
 * packaged. It is test apparatus, and it has no business on a real Peios.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/services/peinit/control.sock"
#define MAX_FRAME (1024 * 1024)

static FILE *logf;
static struct timespec started;

static char buffer[MAX_FRAME];
static size_t buffered;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static double elapsed(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - started.tv_sec)
        + (double)(now.tv_nsec - started.tv_nsec) / 1e9;
}

/* Write all of `len` bytes, or return the errno that stopped it. */
static int write_all(int s, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t n = send(s, data, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_frame(int s, const char *json)
{
    if (strchr(json, '\n')) die("pt-ctl: a frame may not contain a newline");
    fprintf(logf, "request bytes=%zu at=%.3f\n", strlen(json), elapsed());
    fprintf(logf, "request-json %s\n", json);
    fflush(logf);
    int err = write_all(s, json, strlen(json));
    if (!err) err = write_all(s, "\n", 1);
    if (err) {
        fprintf(logf, "send rc=-1 errno=%d %s at=%.3f\n", err, strerror(err), elapsed());
        fflush(logf);
        return 4;
    }
    return 0;
}

static int read_answer(int s);

/* After a send the far end refused: collect every answer it had already
 * queued before it went, then stop.
 *
 * This is not politeness, it is the frame-level rule working as written.
 * Past MaxRequestSize the manager answers REQUEST_TOO_LARGE and closes as
 * soon as it has read the bound — which is before a client writing the
 * whole oversized frame has finished. The client's tail bytes then meet
 * EPIPE, and the answer sits unread in its receive queue. Stopping at the
 * send error would report "no answer" for a manager that gave one, which
 * is what this tool did in about two runs out of three until it drained. */
static void drain_after_refused_send(int s)
{
    while (read_answer(s) == 0) {}
}

/* Read one newline-terminated answer, keeping whatever follows it.
 * Returns 0 while the connection is usable, and non-zero once it is not. */
static int read_answer(int s)
{
    for (;;) {
        char *nl = memchr(buffer, '\n', buffered);
        if (nl) {
            size_t len = (size_t)(nl - buffer);
            fprintf(logf, "reply rc=%zu at=%.3f\n", len, elapsed());
            fprintf(logf, "reply-json %.*s\n", (int)len, buffer);
            fflush(logf);
            buffered -= len + 1;
            memmove(buffer, nl + 1, buffered);
            return 0;
        }
        if (buffered == sizeof buffer) die("pt-ctl: an answer longer than %d bytes", MAX_FRAME);
        ssize_t n = recv(s, buffer + buffered, sizeof buffer - buffered, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* A reset is the peer closing with our data unread, which is
             * what a close after a frame-level error looks like from here. */
            if (errno == ECONNRESET) {
                fprintf(logf, "reply closed at=%.3f reset\n", elapsed());
                fflush(logf);
                return 6;
            }
            fprintf(logf, "reply rc=-1 errno=%d %s at=%.3f\n", errno, strerror(errno), elapsed());
            fflush(logf);
            return 5;
        }
        if (n == 0) {
            fprintf(logf, "reply closed at=%.3f\n", elapsed());
            fflush(logf);
            return 6;
        }
        buffered += (size_t)n;
    }
}

int main(int argc, char **argv)
{
    logf = stdout;
    const char *sock_path = DEFAULT_SOCKET;

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock_path = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            logf = fopen(argv[++i], "w");
            if (!logf) die("pt-ctl: cannot open log %s: %s", argv[i], strerror(errno));
        } else break;
    }
    if (i >= argc) die("pt-ctl: no steps given");

    clock_gettime(CLOCK_MONOTONIC, &started);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) die("pt-ctl: socket: %s", strerror(errno));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof addr.sun_path)
        die("pt-ctl: socket path too long: %s", sock_path);
    strcpy(addr.sun_path, sock_path);

    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(logf, "connect rc=-1 errno=%d %s\n", errno, strerror(errno));
        fflush(logf);
        return 3;
    }
    fprintf(logf, "connect rc=0 path=%s\n", sock_path);
    fflush(logf);

    for (; i < argc; i++) {
        const char *step = argv[i];

        if (strcmp(step, "sleep") == 0) {
            if (i + 1 >= argc) die("pt-ctl: sleep needs a count");
            int seconds = atoi(argv[++i]);
            fprintf(logf, "sleep %d at=%.3f\n", seconds, elapsed());
            fflush(logf);
            sleep((unsigned)seconds);
            continue;
        }
        if (strcmp(step, "read") == 0) {
            fprintf(logf, "read at=%.3f\n", elapsed());
            fflush(logf);
            int rc = read_answer(s);
            if (rc) return rc == 6 ? 0 : rc;
            continue;
        }

        if (strcmp(step, "send-raw") == 0) {
            if (i + 1 >= argc) die("pt-ctl: send-raw needs some text");
            const char *text = argv[++i];
            /* One buffer, one send: several frames written this way reach
             * the manager together rather than a syscall apart. */
            size_t cap = strlen(text) + 1, len = 0;
            char *raw = malloc(cap);
            if (!raw) die("pt-ctl: out of memory");
            for (const char *p = text; *p; p++) {
                if (p[0] == '\\' && p[1] == 'n') { raw[len++] = '\n'; p++; }
                else raw[len++] = *p;
            }
            fprintf(logf, "request-raw bytes=%zu at=%.3f\n", len, elapsed());
            fflush(logf);
            int err = write_all(s, raw, len);
            free(raw);
            if (err) {
                fprintf(logf, "send rc=-1 errno=%d %s at=%.3f\n", err, strerror(err), elapsed());
                fflush(logf);
                drain_after_refused_send(s);
                return 0;
            }
            continue;
        }

        const char *json;
        int want_answer = 1;
        if (strcmp(step, "send-only") == 0) {
            if (i + 1 >= argc) die("pt-ctl: send-only needs a request");
            json = argv[++i];
            want_answer = 0;
        } else if (strcmp(step, "send") == 0) {
            if (i + 1 >= argc) die("pt-ctl: send needs a request");
            json = argv[++i];
        } else {
            json = step;
        }

        /* A refused send is the manager having gone, which a caller asked
         * to see rather than a failure of the tool — but it may have
         * answered on its way out, so collect that first. */
        if (send_frame(s, json)) {
            drain_after_refused_send(s);
            return 0;
        }
        if (!want_answer) continue;
        int rc = read_answer(s);
        if (rc) return rc == 6 ? 0 : rc;
    }

    close(s);
    return 0;
}
