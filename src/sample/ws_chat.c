/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <event.h>

#define BACKLOG 5

struct chat_client {
    int fd;
    struct event ev;
    struct chat_client *next;
};

struct chat_client *gHead_client = NULL;

int
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
read_handler(int fd, short event, void *arg) {
    ssize_t i, siz;
    char buf[4096];
    struct chat_client *c = (struct chat_client *)arg;
    struct chat_client *prev = gHead_client;

	if (event & EV_READ) {
        memset(buf, 0 ,sizeof(buf));
		if ((siz = read(fd, buf, sizeof(buf))) <= 0 ) {
			event_del(&c->ev);
            for (c = gHead_client; c ; c = c->next) {
                if (fd == c->fd) {
                    break;
                }
                prev = c;
            }
            if (c == gHead_client) {
                gHead_client = c->next;
            } else {
                prev->next = c->next;
            }
			fprintf(stdout, "finished fd = [%d]\n", fd);
			close(fd);
            free(c);
		} else{
            fprintf(stdout, "send to clients = \n[");
            for (i = 0; i < siz; i++) {
                fprintf(stdout, "0x%02x = '%c', ", buf[i] & 0x0ff, buf[i]);
            }
            fprintf(stdout, "]\n");
            for (c = gHead_client; c ; c = c->next) {
                write(c->fd, buf, siz);
            }
		}
	}
}

static void
accept_handler(int fd, short event, void *arg) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    struct chat_client *new_client;
    struct chat_client *p = gHead_client;

	if (event & EV_READ) {
        new_client = malloc(sizeof(struct chat_client));
        new_client->fd = accept(fd, (struct sockaddr *)&sa, &len);
        new_client->next = NULL;
        if (!p) {
            gHead_client = new_client;
        } else {
            for (; p->next; p = p->next) {
                ;
            }
            p->next = new_client;
        }
		event_set(&new_client->ev, new_client->fd,
                  EV_READ|EV_PERSIST, read_handler, new_client);
		event_add(&new_client->ev, NULL);
        fprintf(stdout, "accepted = %d\n", new_client->fd);
	}
}

int
main(int argc, char *argv[]) {
    int fd;
    struct event ev;

    fd = tcp_listen(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "Usage: %s portnum\n", argv[0]);
        exit(1);
    }
    fprintf(stdout, "listen on %s\n", argv[1]);

    event_init();
	event_set(&ev, fd, EV_READ|EV_PERSIST, accept_handler, &ev);
	event_add(&ev, NULL);
	event_dispatch();
}

/* EOF */
