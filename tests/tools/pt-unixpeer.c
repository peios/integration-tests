/* pt-unixpeer — who a process's Unix sockets are connected to.
 *
 * TRM §7.5 says peinit never connects to a readiness publisher's own
 * socket: a level arrives on the notification socket and nowhere else.
 * The negative half of that is a statement about PID 1's descriptors,
 * and /proc cannot answer it: /proc/net/unix names a socket's own inode
 * and path but never its peer, and the image ships no `ss`. sock_diag
 * does — UNIX_DIAG_PEER is the inode of the other end of a connected
 * Unix socket — so this asks it, then walks /proc/<pid>/fd for every
 * process to learn which processes hold each inode.
 *
 * Usage:
 *   pt-unixpeer PID...
 *
 * One line per Unix socket each PID holds:
 *
 *   socket pid=1 fd=7 inode=1234 state=1 peer=1235 peer_pids=412 path=
 *
 * `state` is the kernel's TCP-style state number (1 established, 7
 * unconnected, 10 listening). `peer` is 0 for a socket with no peer, and
 * `peer_pids` lists every process holding the peer inode (empty when no
 * process does — a socket whose other end is only in flight). `path` is
 * the socket's own bound name, if any. A trailing `done` line says the
 * walk finished, so a reader can tell "no sockets" from "no answer".
 *
 * Like the other pt-* tools it is injected into the image rather than
 * packaged.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
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

#define MAX_SOCKETS 8192
#define MAX_HOLDERS 65536

struct unix_socket {
    unsigned int inode;
    unsigned int peer;
    unsigned int state;
    char path[108];
};

struct holder {
    unsigned int inode;
    int pid;
};

static struct unix_socket sockets[MAX_SOCKETS];
static size_t socket_count;
static struct holder holders[MAX_HOLDERS];
static size_t holder_count;

static void record(const struct unix_diag_msg *msg, size_t len)
{
    if (socket_count == MAX_SOCKETS) return;
    struct unix_socket *s = &sockets[socket_count];
    memset(s, 0, sizeof *s);
    s->inode = msg->udiag_ino;
    s->state = msg->udiag_state;

    struct rtattr *attr = (struct rtattr *)(msg + 1);
    size_t remaining = len - NLMSG_ALIGN(sizeof *msg);
    for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
        if (attr->rta_type == UNIX_DIAG_NAME) {
            size_t n = RTA_PAYLOAD(attr);
            if (n >= sizeof s->path) n = sizeof s->path - 1;
            memcpy(s->path, RTA_DATA(attr), n);
            s->path[n] = '\0';
            /* An abstract name starts with a NUL; show it as '@'. */
            if (n > 0 && s->path[0] == '\0') s->path[0] = '@';
        } else if (attr->rta_type == UNIX_DIAG_PEER
                   && RTA_PAYLOAD(attr) >= sizeof(unsigned int)) {
            memcpy(&s->peer, RTA_DATA(attr), sizeof s->peer);
        }
    }
    socket_count++;
}

/* Dump every Unix socket, in every state. Returns 0, or the errno that
 * stopped the dump. */
static int dump_sockets(void)
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
    request.req.udiag_states = 0xffffffffu;
    request.req.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER;

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

/* The socket inode an fd link names, or 0. */
static unsigned int socket_inode(const char *link)
{
    unsigned int inode = 0;
    if (sscanf(link, "socket:[%u]", &inode) != 1) return 0;
    return inode;
}

/* Visit every descriptor of `pid` that is a socket. */
static void each_socket_fd(int pid, void (*visit)(int pid, int fd, unsigned int inode))
{
    char dir_path[64];
    snprintf(dir_path, sizeof dir_path, "/proc/%d/fd", pid);
    DIR *dir = opendir(dir_path);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        char link_path[sizeof dir_path + sizeof entry->d_name + 2];
        char link[128];
        snprintf(link_path, sizeof link_path, "%s/%s", dir_path, entry->d_name);
        ssize_t n = readlink(link_path, link, sizeof link - 1);
        if (n <= 0) continue;
        link[n] = '\0';
        unsigned int inode = socket_inode(link);
        if (inode) visit(pid, atoi(entry->d_name), inode);
    }
    closedir(dir);
}

static void remember_holder(int pid, int fd, unsigned int inode)
{
    (void)fd;
    if (holder_count == MAX_HOLDERS) return;
    for (size_t k = 0; k < holder_count; k++) {
        if (holders[k].inode == inode && holders[k].pid == pid) return;
    }
    holders[holder_count].inode = inode;
    holders[holder_count].pid = pid;
    holder_count++;
}

static void collect_holders(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        each_socket_fd(atoi(entry->d_name), remember_holder);
    }
    closedir(proc);
}

static const struct unix_socket *find_socket(unsigned int inode)
{
    for (size_t k = 0; k < socket_count; k++) {
        if (sockets[k].inode == inode) return &sockets[k];
    }
    return NULL;
}

static void report(int pid, int fd, unsigned int inode)
{
    const struct unix_socket *s = find_socket(inode);
    if (!s) return; /* not a Unix socket */
    printf("socket pid=%d fd=%d inode=%u state=%u peer=%u peer_pids=", pid, fd, inode,
           s->state, s->peer);
    int first = 1;
    if (s->peer) {
        for (size_t k = 0; k < holder_count; k++) {
            if (holders[k].inode != s->peer) continue;
            printf(first ? "%d" : ",%d", holders[k].pid);
            first = 0;
        }
    }
    printf(" path=%s\n", s->path);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: pt-unixpeer PID...\n");
        return 2;
    }
    int err = dump_sockets();
    if (err) {
        printf("dump failed errno=%d %s\n", err, strerror(err));
        return 3;
    }
    collect_holders();
    for (int i = 1; i < argc; i++) each_socket_fd(atoi(argv[i]), report);
    printf("done\n");
    return 0;
}
