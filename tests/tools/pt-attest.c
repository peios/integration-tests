/* pt-attest — send a PGSS Logon ServiceAttest and print the authority's answer.
 *
 * TRM §4.3 and PGSS Logon §2.19: peinit obtains a service token by sending a
 * `ServiceAttest` on /run/logon.sock, and the authority honours it only when
 * the peer is SYSTEM *and* PID 1. Nothing in peinit enforces the PID-1 half —
 * it is authd's, established from the connection's peer credentials. This tool
 * exists to send the request from a process that is SYSTEM but NOT PID 1 (an
 * ordinary guest process), so the refusal that half produces is observable.
 *
 * The wire format is PGSS Logon §2.6: a 12-byte header (magic "PGSL", u16
 * version=1, u16 msg_type, u32 total_len) followed by a single length-framed
 * body struct. ServiceAttest (msg_type 0x0020) carries two strings, identity
 * then service, each a u32 byte count and that many bytes. The authority
 * answers with AccessGranted (0x8002) or AccessDenied (0x8003); AccessDenied's
 * body is a u32 denial code and a reason string, and PermissionDenied is 3.
 *
 * Usage:
 *   pt-attest PATH IDENTITY SERVICE
 *
 * Prints one line to stdout:
 *   granted
 *   denied denial=<n> reason=<text>
 *   error <what>            (to stderr, exit 1)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAGIC "PGSL"
#define VERSION 1
#define MSG_SERVICE_ATTEST 0x0020
#define MSG_ACCESS_GRANTED 0x8002
#define MSG_ACCESS_DENIED 0x8003
#define HEADER_BYTES 12

static void put_u16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void put_u32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static uint32_t get_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t get_u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: pt-attest PATH IDENTITY SERVICE\n");
        return 2;
    }
    const char *path = argv[1];
    const char *identity = argv[2];
    const char *service = argv[3];

    size_t id_len = strlen(identity);
    size_t svc_len = strlen(service);
    uint32_t struct_len = (uint32_t)(4 + id_len + 4 + svc_len);
    uint32_t total_len = (uint32_t)(HEADER_BYTES + 4 + struct_len);

    unsigned char msg[65536];
    if (total_len > sizeof msg) {
        fprintf(stderr, "error message too large\n");
        return 1;
    }
    memcpy(msg, MAGIC, 4);
    put_u16(msg + 4, VERSION);
    put_u16(msg + 6, MSG_SERVICE_ATTEST);
    put_u32(msg + 8, total_len);
    put_u32(msg + 12, struct_len);
    put_u32(msg + 16, (uint32_t)id_len);
    memcpy(msg + 20, identity, id_len);
    put_u32(msg + 20 + id_len, (uint32_t)svc_len);
    memcpy(msg + 24 + id_len, service, svc_len);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error socket: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr.sun_path) {
        fprintf(stderr, "error path too long\n");
        return 1;
    }
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        fprintf(stderr, "error connect: %s\n", strerror(errno));
        return 1;
    }

    if (write_all(fd, msg, total_len) < 0) {
        fprintf(stderr, "error write: %s\n", strerror(errno));
        return 1;
    }

    unsigned char reply[65536];
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fd, reply + got, sizeof reply - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "error read: %s\n", strerror(errno));
            return 1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
        if (got >= HEADER_BYTES) {
            uint32_t want = get_u32(reply + 8);
            if (want <= got || want > sizeof reply)
                break;
        }
        if (got == sizeof reply)
            break;
    }

    if (got < HEADER_BYTES) {
        fprintf(stderr, "error short reply (%zu bytes)\n", got);
        return 1;
    }
    if (memcmp(reply, MAGIC, 4) != 0) {
        fprintf(stderr, "error bad magic in reply\n");
        return 1;
    }
    uint16_t msg_type = get_u16(reply + 6);
    if (msg_type == MSG_ACCESS_GRANTED) {
        printf("granted\n");
        return 0;
    }
    if (msg_type == MSG_ACCESS_DENIED) {
        /* body: struct_len u32, denial u32, reason string */
        if (got < HEADER_BYTES + 8) {
            fprintf(stderr, "error truncated denial\n");
            return 1;
        }
        uint32_t denial = get_u32(reply + HEADER_BYTES + 4);
        char reason[513];
        reason[0] = '\0';
        size_t reason_off = HEADER_BYTES + 4 + 4;
        if (got >= reason_off + 4) {
            uint32_t rlen = get_u32(reply + reason_off);
            if (rlen > sizeof reason - 1)
                rlen = sizeof reason - 1;
            if (got >= reason_off + 4 + rlen) {
                memcpy(reason, reply + reason_off + 4, rlen);
                reason[rlen] = '\0';
            }
        }
        printf("denied denial=%u reason=%s\n", (unsigned)denial, reason);
        return 0;
    }
    fprintf(stderr, "error unexpected reply type 0x%04x\n", (unsigned)msg_type);
    return 1;
}
