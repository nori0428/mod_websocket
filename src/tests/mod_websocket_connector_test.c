/**
 * $Id$
 **/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <ev.h>
#include <signal.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket_connector.h"

#define BACKLOG 5

extern int errno;

int
tcp_listen(const char *service) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai = NULL;
    int sockfd;
    int on = 1;
    int flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, service, &hints, &res) != 0) {
        goto go_out;
    }
    ai = res;
    sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sockfd < 0) {
        goto go_out;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        close(sockfd);
        sockfd = -1;
        goto go_out;
    }
    if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
        close(sockfd);
        sockfd = -1;
        goto go_out;
    }
    if (listen(sockfd, BACKLOG) < 0) {
        close(sockfd);
        sockfd = -1;
        goto go_out;
    }
    if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0 ||
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sockfd);
        sockfd = -1;
    }

 go_out:
    freeaddrinfo(res);
    return sockfd;
}

static void
read_handler(EV_P_ struct ev_io *w, int revents) {
    ssize_t siz;
    char buf[4096];

    memset(buf, 0 ,sizeof(buf));
    if ((siz = read(w->fd, buf, sizeof(buf))) <= 0 ) {
        close(w->fd);
        ev_io_stop(EV_A_ w);
        free(w);
    } else{
        fprintf(stderr, "do echo back: %s\n", buf);
        write(w->fd, buf, siz);
    }
}

static void
accept_handler(EV_P_ struct ev_io *w, int revents) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    struct ev_loop *l;
    ev_io *watcher;
    int new_fd, flags;

    if ((new_fd = accept(w->fd, (struct sockaddr *)&sa, &len)) < 0) {
        if (EINTR == errno) {
            return;
        }
        abort();
    }
    if ((flags = fcntl(new_fd, F_GETFL, 0)) < 0 ||
        fcntl(new_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(new_fd);
        abort();
    }
    watcher = calloc(1, sizeof(ev_io));
    l = w->data;
    ev_io_init(watcher, read_handler, new_fd, EV_READ);
    ev_io_start(loop, watcher);
    fprintf(stdout, "accepted = %d\n", new_fd);
}

CU_TestFunc
mod_websocket_connector_test() {
    int sockfd = -1;
    const char *msg = "Hello";
    char buf[256];
    ssize_t r;

    sockfd = mod_websocket_tcp_server_connect("127.0.0.1", "9001");
    CU_ASSERT_EQUAL(sockfd, -1);

    fprintf(stderr, "check: IPv4\n");
    sockfd = mod_websocket_tcp_server_connect("127.0.0.1", "9000");
    CU_ASSERT_NOT_EQUAL(sockfd, -1);
    write(sockfd, msg, strlen(msg));
    memset(buf, 0, sizeof(buf));
    r = read(sockfd, buf, sizeof(buf));
    fprintf(stderr, "recv echo: %s\n", buf);
    CU_ASSERT_EQUAL(r, strlen(msg));
    CU_ASSERT_EQUAL(memcmp(msg, buf, strlen(msg)), 0);
    mod_websocket_tcp_server_disconnect(sockfd);
    CU_ASSERT_EQUAL(write(sockfd, msg, strlen(msg)), -1);
    CU_ASSERT_EQUAL(errno, EBADF);

    fprintf(stderr, "check: IPv6\n");
    sockfd = mod_websocket_tcp_server_connect("::1", "9000");
    CU_ASSERT_NOT_EQUAL(sockfd, -1);
    write(sockfd, msg, strlen(msg));
    memset(buf, 0, sizeof(buf));
    r = read(sockfd, buf, sizeof(buf));
    fprintf(stderr, "recv echo: %s\n", buf);
    CU_ASSERT_EQUAL(r, strlen(msg));
    CU_ASSERT_EQUAL(memcmp(msg, buf, strlen(msg)), 0);
    mod_websocket_tcp_server_disconnect(sockfd);

    CU_ASSERT_EQUAL(write(sockfd, msg, strlen(msg)), -1);
    CU_ASSERT_EQUAL(errno, EBADF);
    return 0;
}

int
main() {
    pid_t pid;
    CU_ErrorCode ret;
    CU_pSuite suite;
    int fd;
    struct ev_loop *loop;
    ev_io watcher;

    fd = tcp_listen("9000");
    loop = ev_default_loop(0);
    watcher.data = loop;
    ev_io_init(&watcher, accept_handler, fd, EV_READ);
    ev_io_start(loop, &watcher);

    pid = fork();
    switch (pid) {
    case 0:
        ev_loop(loop, 0);
        break;
    default:
        close(fd);
        ev_io_stop(EV_A_ &watcher);
        ret = CU_initialize_registry();
        if (ret != CUE_SUCCESS) {
            return -1;
        }
        CU_basic_set_mode(CU_BRM_SILENT);
        suite = CU_add_suite("mod_websocket_connector_suite", NULL, NULL);
        CU_ADD_TEST(suite, mod_websocket_connector_test);
        CU_basic_run_tests();
        ret = CU_get_number_of_failures();
        if (ret != 0) {
            CU_basic_show_failures(CU_get_failure_list());
            fprintf(stderr, "\n");
        }
        kill(pid, SIGKILL);
        break;
    }
    return ret;
}

/* EOF */
