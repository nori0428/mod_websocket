/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <ev.h>

#define BACKLOG 5

struct chat_client {
    int fd;
    struct chat_client *next;
};

struct chat_client *gHead_client = NULL;

static int
tcp_listen(const char *service) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai = NULL;
    int sockfd;
    int on = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, service, &hints, &res) != 0) {
        return -1;
    }
    ai = res;
    sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sockfd < 0) {
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        return -1;
    }
    if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
        return -1;
    }
    if (listen(sockfd, BACKLOG) < 0) {
        return -1;
    }
    freeaddrinfo(res);
    return sockfd;
}

static void
read_handler(EV_P_ struct ev_io *w, int revents) {
    ssize_t siz;
    char buf[4096];
    struct chat_client *c = NULL;
    struct chat_client *prev = gHead_client;

    memset(buf, 0 ,sizeof(buf));
    if ((siz = read(w->fd, buf, sizeof(buf))) <= 0 ) {
        close(w->fd);
        ev_io_stop(EV_A_ w);
        for (c = gHead_client; c ; c = c->next) {
            if (w->fd == c->fd) {
                break;
            }
            prev = c;
        }
        if (c == gHead_client) {
            gHead_client = c->next;
        } else {
            prev->next = c->next;
        }
        fprintf(stdout, "finished fd = [%d]\n", w->fd);
        free(c);
    } else {
        fprintf(stdout, "send to clients\n");
        for (c = gHead_client; c ; c = c->next) {
            write(c->fd, buf, siz);
        }
    }
}

static void
accept_handler(EV_P_ struct ev_io *w, int revents) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    struct ev_loop *l;
    struct ev_io *watcher;
    struct chat_client *new_client;
    int fd, flags;

    fd = accept(w->fd, (struct sockaddr *)&sa, &len);
    if ((flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      close(fd);
      return;
    }

    new_client = malloc(sizeof(struct chat_client));
    new_client->fd = fd;
    new_client->next = gHead_client;
    gHead_client = new_client;

    watcher = calloc(1, sizeof(struct ev_io));
    l = w->data;
    ev_io_init(watcher, read_handler, new_client->fd, EV_READ);
    ev_io_start(l, watcher);
    fprintf(stdout, "accepted = %d\n", new_client->fd);
    return;
}

int
main(int argc, char *argv[]) {
    int fd;
    struct ev_loop *loop;
    ev_io watcher;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    fd = tcp_listen(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "Usage: %s portnum\n", argv[0]);
        return -1;
    }
    fprintf(stdout, "listen on %s\n", argv[1]);
    loop = ev_default_loop(0);
    watcher.data = loop;
    ev_io_init(&watcher, accept_handler, fd, EV_READ);
    ev_io_start(loop, &watcher);
    ev_loop(loop, 0);
    return 0;
}

/* EOF */
