/*
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>

#include "mod_websocket_socket.h"

int mod_websocket_connect(const char *host, const char *service) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai = NULL;
    int flags, fd = -1, sockret = -1;
    socklen_t socklen = sizeof(sockret);
    struct pollfd pollfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    if (getaddrinfo(host, service, &hints, &res) != 0) {
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            break;
        }
        if ((flags = fcntl(fd, F_GETFL, 0)) < 0 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        pollfd.fd = fd;
        pollfd.events = POLLOUT;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0 &&
            errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (poll(&pollfd, 1, 5000) == 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if ((pollfd.revents & POLLOUT) &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockret, &socklen) == 0 &&
            sockret == 0 ) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

void mod_websocket_disconnect(int fd) {
    close(fd);
}

static void store_sockinfo(struct sockaddr_storage *sa, mod_websocket_addrinfo_t *info) {
    assert(sa != NULL && info != NULL);
    if (sa->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)sa;
        info->port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, info->addr, sizeof(info->addr));
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)sa;
        info->port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, info->addr, sizeof(info->addr));
    }
}

int mod_websocket_getsockinfo(int fd, mod_websocket_sockinfo_t *info) {
    socklen_t len;
    struct sockaddr_storage sa;

    if (info == NULL) {
        return -1;
    }
    len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr*)&sa, &len) == -1) {
        return -1;
    }
    store_sockinfo(&sa, &info->self);
    if (getpeername(fd, (struct sockaddr*)&sa, &len) == -1) {
        return -1;
    }
    store_sockinfo(&sa, &info->peer);
    return 0;
}
