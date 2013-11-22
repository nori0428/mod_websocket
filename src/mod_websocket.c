/*
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 */

#include <string.h>
#include <errno.h>

#include "connections.h"
#include "fdevent.h"
#include "joblist.h"
#include "log.h"

#include "mod_websocket.h"
#include "mod_websocket_socket.h"

#ifdef	HAVE_PCRE_H
# include <pcre.h>
#endif	/* HAVE_PCRE_H */

#if defined (LIGHTTPD_VERSION_ID) && (LIGHTTPD_VERSION_ID >= (1 << 16 | 4 << 8 | 30))
# define	NETWORK_SSL_BACKEND_WRITE(a,b,c,d) \
    network_ssl_backend_write(a, b, c, d, MAX_WRITE_LIMIT)
# define	NETWORK_BACKEND_WRITE(a,b,c,d) \
    network_backend_write(a, b, c, d, MAX_WRITE_LIMIT)
#else
# define	NETWORK_SSL_BACKEND_WRITE(a,b,c,d) \
    network_ssl_backend_write(a, b, c, d)
# define	NETWORK_BACKEND_WRITE(a,b,c,d) \
    network_backend_write(a, b, c, d)
#endif

/* prototypes */
static int connect_backend(handler_ctx *);
static void disconnect_backend(handler_ctx *);
static void prepare_disconnect_client(handler_ctx *);
static handler_t handle_backend(server *, void *, int);
static handler_t mod_websocket_handle_subrequest(server *, connection *, void *);

/* OK */
static handler_ctx *handler_ctx_init(void) {
    handler_ctx *hctx = calloc(1, sizeof(handler_ctx));

    if (!hctx) {
        return NULL;
    }
    hctx->state = MOD_WEBSOCKET_STATE_INIT;
    hctx->mode = MOD_WEBSOCKET_TCP_PROXY;

    hctx->handshake.host = NULL;
    hctx->handshake.origin = NULL;
    hctx->handshake.version = -1;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    hctx->handshake.key1 = NULL;
    hctx->handshake.key2 = NULL;
    hctx->handshake.key3 = buffer_init();
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_RFC_6455_
    hctx->handshake.key = NULL;
#endif	/* _MOD_WEBSOCKET_RFC_6455_ */

    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx->frame.ctl.siz = 0;
    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx->frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx->frame.payload = buffer_init();
    hctx->tosrv = chunkqueue_init();

    hctx->fd = -1;
    hctx->fd_idx = -1;

    hctx->srv = NULL;
    hctx->con = NULL;
    hctx->ext = NULL;
    hctx->pd = NULL;
    hctx->fromcli = NULL;
    hctx->tocli = NULL;

    return hctx;
}

/* OK */
static void handler_ctx_free(handler_ctx *hctx) {
    if (!hctx) {
        return;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx->handshake.key3);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    buffer_free(hctx->frame.payload);
    chunkqueue_free(hctx->tosrv);
    free(hctx);
    return;
}

/* OK */
int connect_backend(handler_ctx *hctx) {
    data_unset *du;
    buffer *host = NULL;
    buffer *port = NULL;

    du = array_get_element(hctx->ext->value, "host");
    if (!du || du->type != TYPE_STRING) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "host section is invalid");
        hctx->con->http_status = 500;
        hctx->con->mode = DIRECT;
        return -1;
    }
    host = ((data_string *)du)->value;
    if (buffer_is_empty(host)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "host section is invalid");
        hctx->con->http_status = 500;
        hctx->con->mode = DIRECT;
        return -1;
    }
    du = array_get_element(hctx->ext->value, "port");
    if (!du) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "port section is invalid");
        hctx->con->http_status = 500;
        hctx->con->mode = DIRECT;
        return -1;
    }
    port = buffer_init();
    if (du->type == TYPE_INTEGER) {
        if (buffer_copy_long(port, ((data_integer *)du)->value) != 0) {
            buffer_free(port);
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            hctx->con->http_status = 500;
            hctx->con->mode = DIRECT;
            return -1;
        }
    } else if (du->type == TYPE_STRING && !buffer_is_empty(((data_string *)du)->value)) {
        if (buffer_copy_string_buffer(port, ((data_string *)du)->value) != 0) {
            buffer_free(port);
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            hctx->con->http_status = 500;
            hctx->con->mode = DIRECT;
            return -1;
        }
    } else {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "port section is invalid");
        buffer_free(port);
        hctx->con->http_status = 500;
        hctx->con->mode = DIRECT;
        return -1;
    }
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "ssss",
              "try to connect backend ->", host->ptr, ":", port->ptr);
    hctx->fd = mod_websocket_connect(host->ptr, port->ptr);
    if (hctx->fd < 0) {
        buffer_free(port);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "s", "fail to connect");
        hctx->con->http_status = 503;
        hctx->con->mode = DIRECT;
        return -1;
    }
    int flag = 1;
    if (setsockopt(hctx->fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "s", "fail to set TCP_NODELAY for backend");
    }
    if (setsockopt(hctx->con->fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "s", "fail to set TCP_NODELAY for client");
    }
    hctx->fd_idx = -1;
    hctx->srv->cur_fds++;
    fdevent_register(hctx->srv->ev, hctx->fd, handle_backend, hctx);
    fdevent_event_set(hctx->srv->ev, &(hctx->fd_idx), hctx->fd, FDEVENT_IN);

    // for logging remote ipaddr and port
    if (hctx->pd->conf.debug >= MOD_WEBSOCKET_LOG_INFO) {
        mod_websocket_sockinfo_t info;
        if (mod_websocket_getsockinfo(hctx->con->fd, &info) == 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sssdsdsssssds",
                      "connected",
                      info.peer.addr, ":", info.peer.port, "( fd =", hctx->con->fd, ") ->",
                      host->ptr, ":", port->ptr, "( fd =", hctx->fd, ")");
        } else {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "ss", "connected");
        }
    }
    buffer_free(port);
    return 0;
}

/* OK */
void disconnect_backend(handler_ctx *hctx) {
    if (hctx && hctx->srv && hctx->fd > 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds", "disconnect backend ( fd =", hctx->fd, ")");
        fdevent_event_del(hctx->srv->ev, &(hctx->fd_idx), hctx->fd);
        fdevent_unregister(hctx->srv->ev, hctx->fd);
        mod_websocket_disconnect(hctx->fd);
        hctx->srv->cur_fds--;
        hctx->fd = -1;
    }
}

void prepare_disconnect_client(handler_ctx *hctx) {
    if (hctx && hctx->con && hctx->con->fd > 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds", "disconnect client ( fd =", hctx->con->fd, ")");
    }
    if (hctx && hctx->srv && hctx->fd > 0) {
        fdevent_event_del(hctx->srv->ev, &(hctx->fd_idx), hctx->fd);
        fdevent_unregister(hctx->srv->ev, hctx->fd);
        mod_websocket_disconnect(hctx->fd);
        hctx->srv->cur_fds--;
        hctx->fd = -1;
    }
}

/* OK */
handler_t handle_backend(server *srv, void *ctx, int revents) {
    handler_ctx *hctx = (handler_ctx *)ctx;
    char readbuf[UINT16_MAX];
    ssize_t siz;

    if (revents & FDEVENT_NVAL || revents & FDEVENT_HUP || revents & FDEVENT_ERR) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                  "disconnected from backend ( fd =", hctx->fd, ")");
        prepare_disconnect_client(hctx);
    } else if (revents & FDEVENT_IN) {
        errno = 0;
        memset(readbuf, 0, sizeof(readbuf));
        siz = read(hctx->fd, readbuf, sizeof(readbuf));
        if (siz == 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                      "disconnected from backend ( fd =", hctx->fd, ")");
            prepare_disconnect_client(hctx);
        } else if (siz > 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                      "recv data from backend ( fd =", hctx->fd, "), size =", siz);
            if (mod_websocket_frame_send(hctx, hctx->frame.type, readbuf, (size_t)siz) < 0) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "fail to send data to client");
                chunkqueue_reset(hctx->tocli);
            }
        } else if (errno != EAGAIN && errno != EINTR) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "sdss",
                      "recv error from backend ( fd =", hctx->fd, "),", strerror(errno));
            prepare_disconnect_client(hctx);
        }
    }
    return mod_websocket_handle_subrequest(srv, hctx->con, hctx->pd);
}

/* OK */
static int mod_websocket_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s;

    if (!p) {
        return -1;
    }
    s = p->config_storage[0];

#define PATCH(x) do { p->conf.x = s->x; } while (0)

    PATCH(exts);
    PATCH(debug);
    PATCH(timeout);

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    PATCH(ping_interval);
#endif	/* _MOD_WEBSOCKET_RFC_6455_ */

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) {
            continue;
        }
        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN(MOD_WEBSOCKET_CONFIG_SERVER))) {
                PATCH(exts);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN(MOD_WEBSOCKET_CONFIG_DEBUG))) {
                PATCH(debug);
            }
        }
    }
#undef PATCH
    if (!p->conf.exts) {
        return -1;
    }
    return 0;
}

/* OK */
static handler_t mod_websocket_check_extension(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;
    size_t i;
    data_array *ext = NULL;
    handler_ctx *hctx = NULL;

#ifdef	HAVE_PCRE_H
    pcre *re = NULL;
    int rc;
    const char* err_str;
    int err_off;
# define	N	(10)
    int ovec[N * 3];
#endif	/* HAVE_PCRE_H */

    if (con->request.http_method != HTTP_METHOD_GET) {
        return HANDLER_GO_ON;
    }
    if (mod_websocket_patch_connection(srv, con, p) < 0) {
        return HANDLER_GO_ON;
    }
    for (i = p->conf.exts->used; i > 0; i--) {
        ext = (data_array *)p->conf.exts->data[i - 1];

#ifdef	HAVE_PCRE_H
        re = pcre_compile(ext->key->ptr, 0, &err_str, &err_off, NULL);
        rc = pcre_exec(re, NULL, con->uri.path->ptr, con->uri.path->size, 0, PCRE_ANCHORED, ovec, N);
        free(re);
        if (rc > 0) {
            break;
        }
# undef	N
#else
        if (buffer_is_equal(con->uri.path, ext->key)) {
            break;
        }
#endif	/* HAVE_PCRE_H */

        ext = NULL;
    }
    if (!ext) {
        return HANDLER_GO_ON;
    }
    if (p->conf.debug >= MOD_WEBSOCKET_LOG_INFO) {
        log_error_write(srv, __FILE__, __LINE__, "sss",
                        con->uri.path->ptr, "is match WebSocket extension:", ext->key->ptr);
    }
    /* init handler-context */
    hctx = handler_ctx_init();
    if (!hctx) {
        if (p->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "s", "no memory.");
        }
        return HANDLER_ERROR;
    }
    con->plugin_ctx[p->id] = hctx;
    con->mode = p->id;
    hctx->srv = srv;
    hctx->con = con;
    hctx->ext = ext;
    hctx->pd = p;
    hctx->fromcli = con->read_queue;
    hctx->tocli = con->write_queue;
    return HANDLER_GO_ON;
}

/* OK */
INIT_FUNC(mod_websocket_init) {
    plugin_data *p;
    p = calloc(1, sizeof(*p));
    return p;
}

/* OK */
FREE_FUNC(mod_websocket_free) {
    size_t i;
    plugin_data *p = p_d;
    plugin_config *s = NULL;

    if (p->config_storage) {
        for (i = 0; i < srv->config_context->used; i++) {
            s = p->config_storage[i];
            if (s) {
                array_free(s->exts);
                free(s);
            }
        }
        free(p->config_storage);
    }
    free(p);
    return HANDLER_GO_ON;
}

/* OK */
SETDEFAULTS_FUNC(mod_websocket_set_defaults) {
    size_t i, j;
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { MOD_WEBSOCKET_CONFIG_SERVER,        NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
        { MOD_WEBSOCKET_CONFIG_TIMEOUT,       NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
        { MOD_WEBSOCKET_CONFIG_DEBUG,         NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        { MOD_WEBSOCKET_CONFIG_PING_INTERVAL, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

        { NULL,                      NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) {
        return HANDLER_ERROR;
    }
    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
    if (!p->config_storage) {
        log_error_write(srv, __FILE__, __LINE__, "s", "no memory.");
        return HANDLER_ERROR;
    }
    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *s = NULL;
        array *ca = NULL;
        data_unset *du = NULL;
        data_array *da = NULL;
        data_array *ext = NULL;

        s = calloc(1, sizeof(plugin_config));
        if (!s) { /* p->config_storage is freed at FREE_FUNC */
            log_error_write(srv, __FILE__, __LINE__, "s", "no memory");
            return HANDLER_ERROR;
        }
        s->exts = array_init();
        cv[0].destination = s->exts;
        s->timeout = 30; // default timeout == 30 sec
        cv[1].destination = &(s->timeout);
        s->debug = MOD_WEBSOCKET_LOG_NONE;
        cv[2].destination = &(s->debug);

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        s->ping_interval = 0; // not send ping
        cv[3].destination = &(s->ping_interval);
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

        p->config_storage[i] = s;

        ca = ((data_config *)(srv->config_context->data[i]))->value;
        if (config_insert_values_global(srv, ca, cv) != 0) {
            log_error_write(srv, __FILE__, __LINE__, "s", "no memory.");
            return HANDLER_ERROR;
        }
        if ((du = array_get_element(ca, MOD_WEBSOCKET_CONFIG_SERVER)) == NULL) {
            continue;
        }
        if (du->type != TYPE_ARRAY) {
            log_error_write(srv, __FILE__, __LINE__, "s", "invalid configuration");
            return HANDLER_ERROR;
        }
        da = (data_array *)du;
        for (j = 0; j < da->value->used; j++) {
            if (da->value->data[j]->type != TYPE_ARRAY) {
                log_error_write(srv, __FILE__, __LINE__, "s", "invalid configuration");
                return HANDLER_ERROR;
            }
            ext = data_array_init();
            buffer_copy_string_buffer(ext->key, ((data_array *)(da->value->data[j]))->key);
            ext->value = array_init_array(((data_array *)(da->value->data[j]))->value);
            ext->is_index_key = ((data_array *)(da->value->data[j]))->is_index_key;
            array_insert_unique(s->exts, (data_unset *)ext);
        }
    }
    return HANDLER_GO_ON;
}

SUBREQUEST_FUNC(mod_websocket_handle_subrequest) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    int ret;
    mod_websocket_errno_t err;
    data_unset *du;
    data_string *proto = NULL;

    /* not my job */
    if (!hctx || con->mode != p->id) {
        return HANDLER_GO_ON;
    }
    switch (hctx->state) {
    case MOD_WEBSOCKET_STATE_INIT:
        /* check request */
        err = mod_websocket_handshake_check_request(hctx);
        /* not my job */
        if (err == MOD_WEBSOCKET_PRECONDITION_FAILED) {
            return HANDLER_GO_ON;
        } else if (err != MOD_WEBSOCKET_OK) {
            hctx->con->http_status = err;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        /* select mode */
        du = array_get_element(hctx->ext->value, "proto");
        if (du != NULL && du->type == TYPE_STRING) {
            proto = (data_string *)du;
            if (!buffer_is_empty(proto->value) && strcasecmp(proto->value->ptr, "websocket") == 0) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "works as WebSocket Proxy");
                hctx->mode = MOD_WEBSOCKET_WEBSOCKET_PROXY;
            } else {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "works as WebSocket-TCP Proxy");
                hctx->mode = MOD_WEBSOCKET_TCP_PROXY;
            }
        } else {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "works as WebSocket-TCP Proxy");
            hctx->mode = MOD_WEBSOCKET_TCP_PROXY;
        }
        if (hctx->mode == MOD_WEBSOCKET_TCP_PROXY) {
            if (hctx->handshake.version == 0) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "WebSocket Version = hybi-00");
            } else {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sd", "WebSocket Version =", hctx->handshake.version);
            }
        }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        if (hctx->handshake.version == 0 && hctx->mode == MOD_WEBSOCKET_TCP_PROXY) {
            du = array_get_element(hctx->ext->value, "base64");
            if (du == NULL) {
                hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
            } else {
                if (du->type == TYPE_STRING) {
                    data_string *base64 = (data_string *)du;
                    if (!buffer_is_empty(base64->value) &&
                        (strncasecmp(base64->value->ptr, "true", strlen("true")) == 0 ||
                         strncmp(base64->value->ptr, "1", strlen("1")) == 0)) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "base64 endecoder enabled");
                        hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                    } else {
                        hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                    }
                } else if (du->type == TYPE_INTEGER) {
                    data_integer *base64 = (data_integer *)du;
                    if (base64->value == 1) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "base64 endecoder enabled");
                        hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                    } else {
                        hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                    }
                } else {
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                }
            }
        } else {
            hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
        }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

        /* connect to backend server */
        if (connect_backend(hctx) < 0) {
            return HANDLER_FINISHED;
        }
        if (hctx->mode == MOD_WEBSOCKET_WEBSOCKET_PROXY) {
            err = mod_websocket_handshake_forward_request(hctx);
            if (err != MOD_WEBSOCKET_OK) {
                disconnect_backend(hctx);
                hctx->con->http_status = err;
                hctx->con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
            do {
                ret = srv->NETWORK_BACKEND_WRITE(srv, con, hctx->fd, hctx->tosrv);
                if (0 <= ret) {
                    chunkqueue_remove_finished_chunks(hctx->tosrv);
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "ss",
                              "forward handshake error,", strerror(errno));
                    hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
                    hctx->con->mode = DIRECT;
                    return HANDLER_FINISHED;
                }
            } while (!chunkqueue_is_empty(hctx->tosrv));
        } else if (hctx->mode == MOD_WEBSOCKET_TCP_PROXY) {
            /* send handshake response */
            err = mod_websocket_handshake_create_response(hctx);
            if (err != MOD_WEBSOCKET_OK) {
                disconnect_backend(hctx);
                hctx->con->http_status = err;
                hctx->con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
            do {
                if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                    ret = srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#else	/* SSL is not available */
                    ret = -1;
#endif	/* USE_OPENSSL */

                } else {
                    ret = srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
                }
                if (ret >= 0) {
                    chunkqueue_remove_finished_chunks(hctx->tocli);
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "ss",
                              "send handshake response error,", strerror(errno));
                    hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
                    hctx->con->mode = DIRECT;
                    return HANDLER_FINISHED;
                }
            } while (!chunkqueue_is_empty(hctx->tocli));
        }
        hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
        hctx->timeout_cnt = 0;

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        hctx->ping_ts = srv->cur_ts;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

        chunkqueue_reset(hctx->fromcli);
        fdevent_event_del(srv->ev, &(hctx->fd_idx), hctx->fd);
        fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
        fdevent_event_set(srv->ev, &(hctx->fd_idx), hctx->fd, FDEVENT_IN);
        fdevent_event_set(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
        connection_set_state(srv, hctx->con, CON_STATE_READ_CONTINUOUS);
        return HANDLER_WAIT_FOR_EVENT;

    case MOD_WEBSOCKET_STATE_CONNECTED:
        if (hctx->con->fd < 0) {
            break;
        } else {
            if (!chunkqueue_is_empty(hctx->fromcli)) {
                hctx->timeout_cnt = 0;
                if (mod_websocket_frame_recv(hctx) < 0) {
                    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                                  "disconnected from client ( fd =", hctx->con->ssl, ")");
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sds",
                                  "send close response to client ( fd =", hctx->con->ssl, ")");
                        mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                                 (char *)"1000", strlen("1000"));
                        srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#endif	/* USE_OPENSSL */

                    } else {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                                  "disconnected from client ( fd =", hctx->con->fd, ")");
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sds",
                                  "send close response to client ( fd =", hctx->con->fd, ")");
                        mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                                 (char *)"1000", strlen("1000"));
                        srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
                    }
                    break;
                }
            }
            if (!chunkqueue_is_empty(hctx->tosrv)) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                          "send data to backend ( fd =", hctx->fd,
                          "), size =", chunkqueue_length(hctx->tosrv));
                ret = srv->NETWORK_BACKEND_WRITE(srv, con, hctx->fd, hctx->tosrv);
                if (0 <= ret) {
                    chunkqueue_remove_finished_chunks(hctx->tosrv);
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "ss",
                              "fail to send data to backend:", strerror(errno));
                    chunkqueue_reset(hctx->tosrv);
                }
            }
        }
        if (hctx->fd < 0) {
            chunkqueue_reset(hctx->tocli);
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sds",
                          "send close request to client ( fd =", hctx->con->ssl, ")");
                mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, (char *)"1001", strlen("1001"));
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sds",
                          "send close request to client ( fd =", hctx->con->fd, ")");
                mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, (char *)"1001", strlen("1001"));
                srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
            }
            break;
        } else {
            if (!chunkqueue_is_empty(hctx->tocli)) {
                if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                              "send data to client ( fd =", hctx->con->ssl,
                              "), size =", chunkqueue_length(hctx->tocli));
                    ret = srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#else	/* SSL is not available */
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "SSL is not available");
                    ret = -1;
#endif	/* USE_OPENSSL */

                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                              "send data to client ( fd =", hctx->con->fd,
                              "), size =", chunkqueue_length(hctx->tocli));
                    ret = srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
                }
                if (ret >= 0) {
                    chunkqueue_remove_finished_chunks(hctx->tocli);
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "ss",
                              "fail to send data to client:", strerror(errno));
                    chunkqueue_reset(hctx->tocli);
                }
            }
        }
        fdevent_event_del(srv->ev, &(hctx->fd_idx), hctx->fd);
        fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
        if (!chunkqueue_is_empty(hctx->tosrv)) {
            fdevent_event_set(srv->ev, &(hctx->fd_idx), hctx->fd, FDEVENT_OUT);
        } else {
            fdevent_event_set(srv->ev, &(hctx->fd_idx), hctx->fd, FDEVENT_IN);
        }
        if (!chunkqueue_is_empty(hctx->tocli)) {
            fdevent_event_set(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_OUT);
        } else {
            fdevent_event_set(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
        }
        connection_set_state(srv, hctx->con, CON_STATE_READ_CONTINUOUS);
        return HANDLER_WAIT_FOR_EVENT;
    }
    disconnect_backend(hctx);
    handler_ctx_free(hctx);
    connection_set_state(srv, con, CON_STATE_CLOSE);
    con->plugin_ctx[p->id] = NULL;
    return HANDLER_FINISHED;
}

TRIGGER_FUNC(mod_websocket_handle_trigger) {
    connection *con;
    handler_ctx *hctx;
    plugin_data *p = p_d;
    size_t i;

    for (i = 0; i < srv->conns->used; i++) {
        con = srv->conns->ptr[i];
        if (con->mode != p->id) {
            continue;
        }
        hctx = con->plugin_ctx[p->id];
        if (!hctx || hctx->mode != MOD_WEBSOCKET_TCP_PROXY) {
            continue;
        }

        if (hctx->handshake.version != 0 &&
            p->conf.ping_interval > 0 &&
            p->conf.ping_interval < (unsigned int)difftime(srv->cur_ts, hctx->ping_ts)) {
            mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_PING, (char *)"ping", strlen("ping"));
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                          "send data to client ( fd =", hctx->con->ssl,
                          "), size =", chunkqueue_length(hctx->tocli));
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#else	/* SSL is not available */
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "SSL is not available");
                chunkqueue_reset(hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
                          "send data to client ( fd =", hctx->con->fd,
                          "), size =", chunkqueue_length(hctx->tocli));
                srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
            }
            hctx->ping_ts = srv->cur_ts;
            chunkqueue_remove_finished_chunks(hctx->tocli);
        }
        hctx->timeout_cnt += 1;
        if (p->conf.timeout > 0 && hctx->timeout_cnt >= p->conf.timeout) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds", "timeout client ( fd =", con->fd, ")");
            mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, NULL, 0);
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con, hctx->con->ssl, hctx->tocli);
#else	/* SSL is not available */
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "SSL is not available");
                chunkqueue_reset(hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd, hctx->tocli);
            }
            disconnect_backend(hctx);
            handler_ctx_free(hctx);
            connection_set_state(srv, con, CON_STATE_CLOSE);
            con->plugin_ctx[p->id] = NULL;
        }
    }
    return HANDLER_GO_ON;
}

/* OK */
static handler_t mod_websocket_disconnected_from_client(server *srv, connection *con, void *pd) {
    plugin_data *p = (plugin_data *)pd;
    handler_ctx *hctx = con->plugin_ctx[p->id];

    UNUSED(srv);

    if (con->plugin_ctx[p->id]) {
        if ((server_socket *)(con->srv_socket) && ((server_socket *)(con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds", "disconnected from client ( fd =", con->ssl, ")");
#else	/* SSL is not available */
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "SSL is not available");
#endif	/* USE_OPENSSL */

        } else if (hctx) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds", "disconnected from client ( fd =", con->fd, ")");
        }
        disconnect_backend(hctx);
        handler_ctx_free(hctx);
        con->plugin_ctx[p->id] = NULL;
    }
    return HANDLER_GO_ON;
}

int mod_websocket_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name = buffer_init_string("mod_websocket");
    p->init = mod_websocket_init;
    p->cleanup = mod_websocket_free;
    p->set_defaults = mod_websocket_set_defaults;
    p->connection_reset = mod_websocket_disconnected_from_client;
    p->handle_connection_close = mod_websocket_disconnected_from_client;
    p->handle_uri_clean = mod_websocket_check_extension;
    p->handle_subrequest = mod_websocket_handle_subrequest;
    p->read_continuous = mod_websocket_handle_subrequest;
    p->handle_trigger = mod_websocket_handle_trigger;
    p->data = NULL;
    return 0;
}

/* EOF */
