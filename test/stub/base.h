#ifndef	_BASE_H_
#define	_BASE_H_

typedef struct {
    int is_ssl;
} server_socket;

typedef struct {
    int dummy;
} server;

typedef struct {
    buffer *request;
    buffer *uri;
    array  *headers;
} request_t;

typedef struct {
    buffer *path;
} request_uri;

typedef struct {
    int fd;
    chunkqueue *read_queue;
    request_t request;
    server_socket *srv_socket;
    request_uri uri;
} connection;

#endif	/* _BASE_H_ */
