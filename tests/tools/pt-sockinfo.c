/* pt-sockinfo — what the kernel knows about a listening Unix socket.
 *
 * TRM §10.1 and §10.7 each state a listener's flags and backlog — created
 * SOCK_CLOEXEC | SOCK_NONBLOCK, listening with a backlog of 32. The flags
 * are readable from /proc/<pid>/fdinfo. The backlog is not in /proc at
 * all: /proc/net/unix has no column for it, and the image ships no `ss`.
 * It is in sock_diag, which is where `ss` gets it — for a listening Unix
 * socket, UNIX_DIAG_RQLEN carries the accept queue's current length and,
 * in the field that means "write queue" for every other socket, the
 * listen backlog (sk_max_ack_backlog).
 *
 * Usage:
 *   pt-sockinfo PATH...
 *
 * One line per PATH, from the netlink dump of every listening Unix socket:
 *
 *   socket path=/run/services/peinit/control.sock inode=1234 backlog=32 queued=0
 *
 * or `socket path=… missing` when no listening socket is bound there.
 * The inode is what ties the line to a descriptor in /proc/<pid>/fd.
 *
 * unix_diag is a module in this kernel. The first sock_diag request for
 * AF_UNIX asks the kernel to load it; if that fails the dump answers
 * ENOENT, and this tool says so rather than reporting every socket
 * missing.
 *
 * Like the other pt-* tools it is injected into the image rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SOCKETS 4096

struct listener {
    char path[108];
    unsigned int inode;
    unsigned int backlog;
    unsigned int queued;
    int have_rqlen;
};

static struct listener found[MAX_SOCKETS];
static size_t found_count;

static void record(const struct unix_diag_msg *msg, size_t len)
{
    if (found_count == MAX_SOCKETS) return;
    struct listener *l = &found[found_count];
    memset(l, 0, sizeof *l);
    l->inode = msg->udiag_ino;

    struct rtattr *attr = (struct rtattr *)(msg + 1);
    size_t remaining = len - NLMSG_ALIGN(sizeof *msg);
    for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
        if (attr->rta_type == UNIX_DIAG_NAME) {
            size_t n = RTA_PAYLOAD(attr);
            if (n >= sizeof l->path) n = sizeof l->path - 1;
            memcpy(l->path, RTA_DATA(attr), n);
            l->path[n] = '\0';
        } else if (attr->rta_type == UNIX_DIAG_RQLEN
                   && RTA_PAYLOAD(attr) >= sizeof(struct unix_diag_rqlen)) {
            struct unix_diag_rqlen rq;
            memcpy(&rq, RTA_DATA(attr), sizeof rq);
            l->queued = rq.udiag_rqueue;
            l->backlog = rq.udiag_wqueue;
            l->have_rqlen = 1;
        }
    }
    found_count++;
}

/* Dump every listening Unix socket. Returns 0, or the errno that stopped
 * the dump. */
static int dump_listeners(void)
{
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (s < 0) return errno;

    struct {
        struct nlmsghdr nlh;
        struct unix_diag_req req;
    } request;
    memset(&request, 0, sizeof request);
    request.nlh.nlmsg_len = sizeof request;
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.req.sdiag_family = AF_UNIX;
    /* TCP_LISTEN's state number is the one Unix sockets use for a
     * listener too. */
    request.req.udiag_states = 1 << 10;
    request.req.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_RQLEN;

    if (send(s, &request, sizeof request, 0) < 0) {
        int err = errno;
        close(s);
        return err;
    }

    static char buffer[64 * 1024];
    for (;;) {
        ssize_t got = recv(s, buffer, sizeof buffer, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            int err = errno;
            close(s);
            return err;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buffer; NLMSG_OK(h, (size_t)got);
             h = NLMSG_NEXT(h, got)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                close(s);
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                close(s);
                return e->error ? -e->error : EPROTO;
            }
            record(NLMSG_DATA(h), h->nlmsg_len - NLMSG_HDRLEN);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: pt-sockinfo PATH...\n");
        return 2;
    }
    int err = dump_listeners();
    if (err) {
        printf("dump failed errno=%d %s\n", err, strerror(err));
        return 3;
    }
    for (int i = 1; i < argc; i++) {
        const struct listener *hit = NULL;
        for (size_t k = 0; k < found_count; k++) {
            if (strcmp(found[k].path, argv[i]) == 0) {
                hit = &found[k];
                break;
            }
        }
        if (!hit) {
            printf("socket path=%s missing\n", argv[i]);
        } else if (!hit->have_rqlen) {
            printf("socket path=%s inode=%u no-rqlen\n", argv[i], hit->inode);
        } else {
            printf("socket path=%s inode=%u backlog=%u queued=%u\n",
                   argv[i], hit->inode, hit->backlog, hit->queued);
        }
    }
    return 0;
}
