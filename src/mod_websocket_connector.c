/**
 * $Id$
 * a part of mod_websocket
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include "mod_websocket.h"

int
mod_websocket_tcp_server_connect(const char *host, const char *service) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai = NULL;
    struct fdlist {
        int fd;
        struct fdlist *next;
    };
    struct fdlist *head = NULL, *p, *pn, *fde = NULL;
    int flags, fd, maxfd = -1, connfd = -1, sockret = -1;
    socklen_t socklen = sizeof(sockret);
    fd_set fds;
    struct timeval tv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    if (getaddrinfo(host, service, &hints, &res) != 0) {
        return -1;
    }
    FD_ZERO(&fds);
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            goto go_out;
        }
        if ((flags = fcntl(fd, F_GETFL, 0)) < 0 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            goto go_out;
        }
        fde = (struct fdlist *)malloc(sizeof(struct fdlist));
        if (!fde) {
            close(fd);
            goto go_out;
        }
        fde->fd = fd;
        fde->next = head;
        head = fde;
        if (fde->fd > maxfd) {
            maxfd = fde->fd;
        }
        FD_SET(fde->fd, &fds);
        if (connect(fde->fd, ai->ai_addr, ai->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                goto go_out;
            }
        }
    }
    /* connect timeout is to set 5 secs */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(maxfd + 1, NULL, &fds, NULL, &tv) == 0) {
        goto go_out;
    } else {
        for (p = head; p; p = p->next) {
            if (!FD_ISSET(p->fd, &fds)) {
                continue;
            }
            if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR,
                           &sockret, &socklen) == 0 &&
                sockret == 0) {
                connfd = p->fd;
                break;
            }
        }
    }

 go_out:
    p = head;
    while (p) {
        if (p->fd != connfd) {
            close(p->fd);
        }
        pn = p->next;
        free(p);
        p = pn;
    }
    freeaddrinfo(res);
    return connfd;
}

void
mod_websocket_tcp_server_disconnect(int sockfd) {
    close(sockfd);
    return;
}

/* EOF */
