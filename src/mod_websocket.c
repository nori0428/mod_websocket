/*
 * $Id$
 *
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the 'incremental' nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <errno.h>

#include "connections.h"
#include "fdevent.h"
#include "joblist.h"
#include "log.h"

#include "mod_websocket.h"

#ifdef	HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif	/* HAVE_SYS_FILIO_H */

/* prototypes */
static handler_ctx *_handler_ctx_init(void);
static void _handler_ctx_free(handler_ctx *);
static int _set_subproto_extension(data_array *, const data_array *);
static int _set_extension(data_array *, const data_array *);
static int _tcp_server_connect(handler_ctx *);
static void _tcp_server_disconnect(handler_ctx *);
static handler_t _handle_fdevent(server *, void *, int);
static int _dispatch_request(server *, connection *, plugin_data *);
static handler_t _check_request(server *, connection *, void *);
static handler_t _disconnect(server *, connection *, void *);
static handler_t _handle_subrequest(server *, connection *, void *);

handler_ctx *_handler_ctx_init(void) {
    handler_ctx *hctx = calloc(1, sizeof(*hctx));

    if (!hctx) {
        return NULL;
    }
    hctx->state = MOD_WEBSOCKET_STATE_INIT;

    hctx->handshake.host = NULL;
    hctx->handshake.origin = NULL;
    hctx->handshake.subproto = NULL;

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

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx->cnv = NULL;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

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

void _handler_ctx_free(handler_ctx *hctx) {
    if (!hctx) {
        return;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx->handshake.key3);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    buffer_free(hctx->frame.payload);
    chunkqueue_free(hctx->tosrv);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx->cnv);
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    _tcp_server_disconnect(hctx);
    free(hctx);
    return;
}

int _set_subproto_extension(data_array *dst, const data_array *src) {
    size_t i, j;
    data_unset *data = NULL;
    data_string *host = NULL;
    data_string *port = NULL;
    data_array *da_origins = NULL;
    data_array *origins = NULL;
    data_string *origin = NULL;
    data_string *type = NULL;
    buffer *key = NULL;
#define	PORTSTRLEN_MAX	(5)
    char portstr[PORTSTRLEN_MAX + 1];

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    data_string *locale = NULL;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    for (i = src->value->used; i > 0; i--) {
        data = src->value->data[i - 1];
        key = data->key;
        if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_HOST) ) {
            host = data_string_init();
            buffer_copy_string_buffer(host->key, key);
            buffer_copy_string_buffer(host->value,
                                      ((data_string *)data)->value);
            array_insert_unique(dst->value, (data_unset *)host);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_PORT) ) {
            port = data_string_init();
            buffer_copy_string_buffer(port->key, key);
            if (data->type == TYPE_STRING) {
                buffer_copy_string_buffer(port->value,
                                          ((data_string *)data)->value);
            } else if (data->type == TYPE_INTEGER) {
                memset(portstr, 0, PORTSTRLEN_MAX + 1);
                snprintf(portstr, PORTSTRLEN_MAX + 1, "%d", ((data_string *)data)->value);
                buffer_copy_string(port->value, portstr);
#undef	PORTSTRLEN_MAX
            }
            array_insert_unique(dst->value, (data_unset *)port);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_SUBPROTO) ) {
            buffer_copy_string_buffer(dst->key, ((data_string *)data)->value);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_ORIGINS) ) {
            origins = data_array_init();
            buffer_copy_string_len(origins->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_CONFIG_ORIGINS));
            if (data->type == TYPE_STRING) {
                origin = data_string_init();
                buffer_copy_string_buffer(origin->value,
                                          ((data_string *)data)->value);
                array_insert_unique(origins->value, (data_unset *)origin);
            } else if (data->type == TYPE_ARRAY) {
                da_origins = (data_array *)data;
                for (j = da_origins->value->used; j > 0; j--) {
                    origin = data_string_init();
                    buffer_copy_string_buffer(origin->value,
                                              ((data_string *)da_origins->value->data[j - 1])->value);
                    array_insert_unique(origins->value, (data_unset *)origin);
                }
            }
            array_insert_unique(dst->value, (data_unset *)origins);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_LOCALE) ) {
            locale = data_string_init();
            buffer_copy_string_buffer(locale->key, key);
            buffer_copy_string_buffer(locale->value,
                                      ((data_string *)data)->value);
            array_insert_unique(dst->value, (data_unset *)locale);
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_TYPE) ) {
            type = data_string_init();
            buffer_copy_string_buffer(type->key, key);
            buffer_copy_string_buffer(type->value,
                                      ((data_string *)data)->value);
            array_insert_unique(dst->value, (data_unset *)type);
        }
    }
    if (!host || !port) {
        return -1;
    }
    return 0;
}

int _set_extension(data_array *dst, const data_array *src) {
    int ret = -1;
    size_t i;
    data_array *subproto;

    if (!dst || !src) {
        return ret;
    }
    buffer_copy_string_buffer(dst->key, src->key);
    if (src->value->data[0]->type == TYPE_STRING) {
        subproto = data_array_init();
        buffer_reset(subproto->key);
        ret = _set_subproto_extension(subproto, src);
        array_insert_unique(dst->value, (data_unset *)subproto);
    } else if (src->value->data[0]->type == TYPE_ARRAY) {
        for (i = src->value->used; i > 0; i--) {
            data_array *da_src = (data_array *)src->value->data[i - 1];

            subproto = data_array_init();
            buffer_reset(subproto->key);
            ret = _set_subproto_extension(subproto, da_src);
            if (subproto->key->ptr &&
                array_get_element(dst->value, subproto->key->ptr)) {
                ret = -1;
            }
            if (!subproto->key->ptr && dst->value->used) {
                ret = -1;
            }
            array_insert_unique(dst->value, (data_unset *)subproto);
            if (0 != ret) {
                break;
            }
        }
    }
    return ret;
}

int _tcp_server_connect(handler_ctx *hctx) {
    data_unset *du;
    buffer *host = NULL;
    buffer *port = NULL;
    int flag = 1;

    // for logging remote ipaddr and port
    char logstr[4096];
    socklen_t len;
    struct sockaddr_storage caddr;
    int cport, ret;
#ifndef INET6_ADDRSTRLEN
# define	INET6_ADDRSTRLEN	(46)
#endif
    char ipstr[INET6_ADDRSTRLEN];
    // ends here

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    char *locale = NULL;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_HOST);
    if (!du) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid config");
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return -1;
    }
    host = ((data_string *)du)->value;
    if (!host) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid config");
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return -1;
    }
    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_PORT);
    if (!du) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid config");
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return -1;
    }
    port = ((data_string *)du)->value;
    if (!port) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid config");
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return -1;
    }
    snprintf(logstr, sizeof(logstr),
             "try to connect backend server: %s:%s", host->ptr, port->ptr);
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", logstr);
    hctx->fd = mod_websocket_tcp_server_connect(host->ptr, port->ptr);
    if (hctx->fd < 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARNING,
                  "s", "fail to connect backend server");
        hctx->con->http_status = MOD_WEBSOCKET_SERVICE_UNAVAILABLE;
        hctx->con->mode = DIRECT;
        return -1;
    }
    if (setsockopt(hctx->fd, IPPROTO_TCP, TCP_NODELAY,
                   &flag, sizeof(flag)) == -1) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "fail to set TCP_NODELAY");
        _tcp_server_disconnect(hctx);
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return HANDLER_FINISHED;
    }
    if (setsockopt(hctx->con->fd, IPPROTO_TCP, TCP_NODELAY,
                   &flag, sizeof(flag)) == -1) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "fail to set TCP_NODELAY");
        _tcp_server_disconnect(hctx);
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return HANDLER_FINISHED;
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_LOCALE);
    if (!du) {
        locale = MOD_WEBSOCKET_UTF8_STR;
    } else {
        locale = (((data_string *)du)->value) ?
            ((data_string *)du)->value->ptr : MOD_WEBSOCKET_UTF8_STR;
    }
    hctx->cnv = mod_websocket_conv_init(locale);
    if (!hctx->cnv) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        _tcp_server_disconnect(hctx);
        hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
        hctx->con->mode = DIRECT;
        return HANDLER_FINISHED;
    }
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    hctx->fd_idx = -1;
    hctx->srv->cur_fds++;
    fdevent_register(hctx->srv->ev, hctx->fd, _handle_fdevent, hctx);
    fdevent_event_set(hctx->srv->ev, &(hctx->fd_idx), hctx->fd, FDEVENT_IN);

    // for logging remote ipaddr and port
    if (hctx->pd->conf.debug > MOD_WEBSOCKET_LOG_INFO) {
        len = sizeof(caddr);
        ret = getpeername(hctx->con->fd, (struct sockaddr*)&caddr, &len);
        if (ret != -1) {
            if (caddr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&caddr;
                cport = ntohs(s->sin_port);
                inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&caddr;
                cport = ntohs(s->sin6_port);
                inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
            }
        } else {
            snprintf(ipstr, INET6_ADDRSTRLEN, "failed getpeername");
            cport = -1;
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        // connected client fd: num(addr:port,UTF-8) -> server fd: num(addr:port,locale)
        snprintf(logstr, sizeof(logstr),
                 "connected client fd: %d (%s:%d) -> server fd: %d (%s:%s,%s)",
                 hctx->con->fd, ipstr, cport, hctx->fd, host->ptr, port->ptr, locale);
#else
        // connected client fd: num(addr:port,UTF-8) -> server fd: num(addr:port,UTF-8)
        snprintf(logstr, sizeof(logstr),
                 "connected client fd: %d (%s:%d) -> server fd: %d (%s:%s)",
                 hctx->con->fd, ipstr, cport, hctx->fd, host->ptr, port->ptr);
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", logstr);
    }

    return 0;
}

void _tcp_server_disconnect(handler_ctx *hctx) {
    if (hctx->fd > 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "sd", "disconnect server fd:", hctx->fd);
        fdevent_event_del(hctx->srv->ev, &(hctx->fd_idx), hctx->fd);
        fdevent_unregister(hctx->srv->ev, hctx->fd);
        mod_websocket_tcp_server_disconnect(hctx->fd);
        hctx->srv->cur_fds--;
        hctx->fd = -1;
    }
}

handler_t _handle_fdevent(server *srv, void *ctx, int revents) {
    handler_ctx *hctx = (handler_ctx *)ctx;
    mod_websocket_frame_type_t frame_type;
    char readbuf[UINT16_MAX];
    ssize_t siz;
    data_string *type;

    if (revents & FDEVENT_NVAL) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "sdsd",
                  "recv NVAL event: fd(srv) =", hctx->fd,
                  "fd(cli) =", hctx->con->fd);
        _tcp_server_disconnect(hctx);
    } else if (revents & FDEVENT_HUP || revents & FDEVENT_ERR) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "sdsd",
                  "recv HUP or ERR event: fd(srv) =", hctx->fd,
                  "fd(cli) =", hctx->con->fd);
        _tcp_server_disconnect(hctx);
    } else if (revents & FDEVENT_IN) {
        errno = 0;
        memset(readbuf, 0, sizeof(readbuf));
        siz = read(hctx->fd, readbuf, UINT16_MAX - 1);
        if (siz == 0) {
            _tcp_server_disconnect(hctx);
        } else if (siz > 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                      "sdsx",
                      "recv from server fd:", hctx->fd,
                      ", size:", siz);
            if (hctx->state == MOD_WEBSOCKET_STATE_CONNECTED) {
                type = (data_string *)
                    array_get_element(hctx->ext->value,
                                      MOD_WEBSOCKET_CONFIG_TYPE);

                if (type &&
                    0 == strcasecmp(type->value->ptr, MOD_WEBSOCKET_BIN_STR)) {
                    frame_type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                } else {
                    frame_type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                }
                if (mod_websocket_frame_send(hctx, frame_type,
                                             readbuf, (size_t)siz) < 0) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                              "sd", "failed to send frame:", hctx->fd);
                    _tcp_server_disconnect(hctx);
                }
            }
        } else if (errno != EAGAIN && errno != EINTR) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                      "ss", "can't read from server:", strerror(errno));
            _tcp_server_disconnect(hctx);
        } else {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                      "s", strerror(errno));
        }
    }
    return _handle_subrequest(srv, hctx->con, hctx->pd);
}

int _dispatch_request(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

#define PATCH(x) do { p->conf.x = s->x; } while (0)

    PATCH(exts);
    PATCH(debug);
    PATCH(timeout);

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    PATCH(ping);
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

handler_t _check_request(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;
    size_t i;
    data_array *ext = NULL;
    handler_ctx *hctx = NULL;

    if (con->request.http_method != HTTP_METHOD_GET) {
        return HANDLER_GO_ON;
    }
    if (_dispatch_request(srv, con, p) < 0) {
        return HANDLER_GO_ON;
    }
    for (i = p->conf.exts->used; i > 0; i--) {
        ext = (data_array *)p->conf.exts->data[i - 1];
        if (0 == strcmp(con->uri.path->ptr, ext->key->ptr)) {
            break;
        }
        ext = NULL;
    }
    if (!ext) {
        return HANDLER_GO_ON;
    }
    if (p->conf.debug > MOD_WEBSOCKET_LOG_INFO) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "found extension:", ext->key->ptr);
    }
    /* init handler-context */
    hctx = _handler_ctx_init();
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

handler_t _disconnect(server *srv, connection *con, void *pd) {
    plugin_data *p = (plugin_data *)pd;
    handler_ctx *hctx = con->plugin_ctx[p->id];

    srv = srv; // suppress warning
    if (con->plugin_ctx[p->id]) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "sd", "disconnect client fd:", hctx->con->fd);
        if (hctx->fd > 0) {
            _tcp_server_disconnect(hctx);
        }
        _handler_ctx_free(hctx);
        con->plugin_ctx[p->id] = NULL;
    }
    return HANDLER_GO_ON;
}

INIT_FUNC(_init) {
    plugin_data *p = NULL;

    p = calloc(1, sizeof(*p));
    return p;
}

FREE_FUNC(_free) {
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

SETDEFAULTS_FUNC(_set_defaults) {
    plugin_data *p = p_d;
    size_t i, j;
    array *cfg_ctx = srv->config_context;

    p->config_storage = calloc(1, cfg_ctx->used * sizeof(specific_config *));
    if (!p->config_storage) {
        log_error_write(srv, __FILE__, __LINE__, "s", "no memory.");
        return HANDLER_ERROR;
    }
    for (i = 0; i < cfg_ctx->used; i++) {
        plugin_config *s = NULL;
        array *ca = NULL;
        data_unset *du = NULL;
        data_array *da = NULL;
        data_array *ext = NULL;
        config_values_t cv[] = {
            { MOD_WEBSOCKET_CONFIG_SERVER, NULL,
              T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
            { MOD_WEBSOCKET_CONFIG_TIMEOUT,  NULL,
              T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
            { MOD_WEBSOCKET_CONFIG_DEBUG,  NULL,
              T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
            { MOD_WEBSOCKET_CONFIG_PING_INTERVAL,  NULL,
              T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

            { NULL,                        NULL,
              T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
        };

        s = malloc(sizeof(plugin_config));
        if (!s) { /* p->config_storage is freed in FREE_FUNC */
            log_error_write(srv, __FILE__, __LINE__, "s", "no memory");
            return HANDLER_ERROR;
        }
        s->exts = array_init();
        s->timeout = MOD_WEBSOCKET_DEFAULT_TIMEOUT_SEC;
        s->debug = 0;

        cv[0].destination = s->exts;
        cv[1].destination = &(s->timeout);
        cv[2].destination = &(s->debug);

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        s->ping = 0;
        cv[3].destination = &(s->ping);
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

        p->config_storage[i] = s;

        ca = ((data_config *)(cfg_ctx->data[i]))->value;
        if (config_insert_values_global(srv, ca, cv)) {
            return HANDLER_ERROR;
        }
        du = array_get_element(ca, MOD_WEBSOCKET_CONFIG_SERVER);
        if (!du) {
            continue;
        }
        if (du->type != TYPE_ARRAY) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            MOD_WEBSOCKET_CONFIG_SERVER,
                            "must be array");
            return HANDLER_ERROR;
        }

        da = (data_array *)du;
        for (j = 0; j < da->value->used; j++) {
            int ret;
            data_array *da_src = (data_array *)da->value->data[j];

            if (da_src->type != TYPE_ARRAY) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                da_src->key->ptr,
                                "must be array");
                return HANDLER_ERROR;
            }
            ext = data_array_init();
            ret = _set_extension(ext, da_src);
            array_insert_unique(s->exts, (data_unset *)ext);
            if (0 != ret) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "configuration error:",
                                da_src->key->ptr);
                return HANDLER_ERROR;
            }
        }
    }
    return HANDLER_GO_ON;
}

SUBREQUEST_FUNC(_handle_subrequest) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    int ret;
    mod_websocket_errno_t wsret;
    data_string *type = NULL;

    if (!hctx) {
        return HANDLER_GO_ON;
    }
    /* not my job */
    if (con->mode != p->id) {
        return HANDLER_GO_ON;
    }

    switch (hctx->state) {
    case MOD_WEBSOCKET_STATE_INIT:
        /* check request */
        wsret = mod_websocket_handshake_check_request(hctx);
        if (wsret == MOD_WEBSOCKET_NOT_WEBSOCKET) {
            return HANDLER_GO_ON;
        } else if (wsret != MOD_WEBSOCKET_OK) {
            hctx->con->http_status = wsret;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        /* auto base64 {encode, decode} for hybi-00 */
        if (hctx->handshake.version == 0) {
            type = (data_string *)
                array_get_element(hctx->ext->value,
                                  MOD_WEBSOCKET_CONFIG_TYPE);
            if (type &&
                0 == strcasecmp(type->value->ptr, MOD_WEBSOCKET_BIN_STR)) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                          "s", "specified binary type on hybi-00 spec.");
                hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
            } else {
                hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
            }
        }
        /* connect to backend server */
        if (_tcp_server_connect(hctx) < 0) {
            return HANDLER_FINISHED;
        }
        /* create response */
        wsret = mod_websocket_handshake_create_response(hctx);
        if (wsret != MOD_WEBSOCKET_OK) {
            _tcp_server_disconnect(hctx);
            hctx->con->http_status = wsret;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        hctx->state = MOD_WEBSOCKET_STATE_SEND_RESPONSE;

        /* fall through */

    case MOD_WEBSOCKET_STATE_SEND_RESPONSE:
        if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
            ret = srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                                 hctx->con->ssl, hctx->tocli);
#else	/* SSL is not available */
            ret = -1;
#endif	/* USE_OPENSSL */

        } else {
            ret = srv->NETWORK_BACKEND_WRITE(srv, con,
                                             hctx->con->fd, hctx->tocli);
        }
        if (0 <= ret) {
            chunkqueue_remove_finished_chunks(hctx->tocli);
        } else {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                      "ss", "send handshake response error:",
                      strerror(errno));
            _tcp_server_disconnect(hctx);
            chunkqueue_reset(hctx->tocli);
            hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (chunkqueue_is_empty(hctx->tocli)) {
            chunkqueue_reset(hctx->fromcli);
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
        }
        connection_set_state(srv, hctx->con, CON_STATE_READ_CONTINUOUS);
        hctx->last_access = srv->cur_ts;

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        hctx->ping_ts = srv->cur_ts;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

        return HANDLER_WAIT_FOR_EVENT;
        break;

    case MOD_WEBSOCKET_STATE_CONNECTED:
        if (hctx->con->fd < 0) {
            break;
        } else {
            if (!chunkqueue_is_empty(hctx->fromcli)) {
                hctx->last_access = srv->cur_ts;
                if (mod_websocket_frame_recv(hctx) < 0) {
                    mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                             "1000", 0); // NORMAL
                    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                        srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                                       hctx->con->ssl, hctx->tocli);
#endif	/* USE_OPENSSL */

                    } else {
                        srv->NETWORK_BACKEND_WRITE(srv, con,
                                                   hctx->con->fd, hctx->tocli);
                    }
                    break;
                }
                if (!chunkqueue_is_empty(hctx->tosrv)) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sdsx", "send to server fd:", hctx->fd,
                              ", size:", chunkqueue_length(hctx->tosrv));
                    ret = srv->NETWORK_BACKEND_WRITE(srv, con,
                                                     hctx->fd, hctx->tosrv);
                    if (0 <= ret) {
                        chunkqueue_remove_finished_chunks(hctx->tosrv);
                    } else {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                                  "ss", "can't send data to server:",
                                  strerror(errno));
                        break;
                    }
                }
            }
        }
        if (hctx->fd < 0) {
            mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                     "1001", 0); // GOAWAY
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                               hctx->con->ssl, hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                srv->NETWORK_BACKEND_WRITE(srv, con,
                                           hctx->con->fd, hctx->tocli);
            }
            chunkqueue_reset(hctx->tocli);
            break;
        } else {
            if (!chunkqueue_is_empty(hctx->tocli)) {
                if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sdsx",
                              "[SSL]send to client fd:", hctx->con->ssl,
                              ", size:", chunkqueue_length(hctx->tocli));
                    ret = srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                                         hctx->con->ssl,
                                                         hctx->tocli);
#else	/* SSL is not available */
                    ret = -1;
#endif	/* USE_OPENSSL */

                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sdsx", "send to client fd:", hctx->con->fd,
                              ", size:", chunkqueue_length(hctx->tocli));
                    ret = srv->NETWORK_BACKEND_WRITE(srv, con,
                                                     hctx->con->fd,
                                                     hctx->tocli);
                }
                if (0 <= ret) {
                    chunkqueue_remove_finished_chunks(hctx->tocli);
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                              "ss", "can't send data to client:",
                              strerror(errno));
                    _tcp_server_disconnect(hctx);
                    break;
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
        break;
    }
    chunkqueue_reset(hctx->tosrv);
    chunkqueue_reset(hctx->fromcli);
    chunkqueue_reset(hctx->tocli);
    DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
              "sd", "disconnect client fd:", hctx->con->fd);
    connection_set_state(srv, con, CON_STATE_CLOSE);
    _handler_ctx_free(hctx);
    con->plugin_ctx[p->id] = NULL;
    return HANDLER_FINISHED;
}

TRIGGER_FUNC(_handle_trigger) {
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
        if (!hctx) {
            continue;
        }
        if (p->conf.ping == 0 || hctx->handshake.version == 0) {
            continue;
        }
        if (srv->cur_ts - hctx->ping_ts >= (time_t)p->conf.ping) {
            mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_PING,
                                     MOD_WEBSOCKET_PING_STR,
                                     strlen(MOD_WEBSOCKET_PING_STR));
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                          "sdsx",
                          "[SSL]send to client fd:", hctx->con->ssl,
                          ", size:", chunkqueue_length(hctx->tocli));
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                               hctx->con->ssl,
                                               hctx->tocli);
                hctx->ping_ts = srv->cur_ts;
                chunkqueue_remove_finished_chunks(hctx->tocli);
#else	/* SSL is not available */
                chunkqueue_reset(hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                          "sdsx", "send to client fd:", hctx->con->fd,
                          ", size:", chunkqueue_length(hctx->tocli));
                srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd,
                                           hctx->tocli);
                hctx->ping_ts = srv->cur_ts;
                chunkqueue_remove_finished_chunks(hctx->tocli);
            }
        }

        if (p->conf.timeout != 0 &&
            srv->cur_ts - hctx->last_access >= (time_t)p->conf.timeout) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                      "sd", "timeout client:", con->fd);
            mod_websocket_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                     NULL, 0);
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                srv->NETWORK_SSL_BACKEND_WRITE(srv, con,
                                               hctx->con->ssl,
                                               hctx->tocli);
#endif	/* USE_OPENSSL */

            } else {
                srv->NETWORK_BACKEND_WRITE(srv, con, hctx->con->fd,
                                           hctx->tocli);
            }
            _tcp_server_disconnect(hctx);
            chunkqueue_remove_finished_chunks(hctx->tocli);
            chunkqueue_reset(hctx->tosrv);
            connection_set_state(srv, con, CON_STATE_CLOSE);
            _handler_ctx_free(hctx);
            con->plugin_ctx[p->id] = NULL;
        }
    }
    return HANDLER_GO_ON;
}

int mod_websocket_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name = buffer_init_string("mod_websocket");
    p->init = _init;
    p->cleanup = _free;
    p->set_defaults = _set_defaults;
    p->connection_reset = _disconnect;
    p->handle_connection_close = _disconnect;
    p->handle_uri_clean = _check_request;
    p->handle_subrequest = _handle_subrequest;
    p->read_continuous = _handle_subrequest;
    p->handle_trigger = _handle_trigger;
    p->data = NULL;
    return 0;
}

/* EOF */
