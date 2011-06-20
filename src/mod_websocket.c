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
#include <locale.h>
#include <langinfo.h>
#include <errno.h>

#include "connections.h"
#include "fdevent.h"
#include "joblist.h"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# include "md5.h"
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
# include "sha1.h"
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

#include "log.h"

#include "mod_websocket.h"

/* prototypes */
static handler_ctx *handler_ctx_init(void);
static void handler_ctx_free(handler_ctx *);
static int set_subproto_extension(data_array *, const data_array *);
static int set_extension(data_array *, const data_array *);
static int tcp_server_connect(server *, handler_ctx *);
static void tcp_server_disconnect(server *, handler_ctx *);
static buffer *get_header_value(const array *, const char *);
static mod_websocket_bool_t check_const_headers(const array *);
static int get_subproto_field(buffer *, const array *);
static data_array *get_subproto_extension(const array *, buffer *);
static int get_origin_field(buffer *, const array *);
static mod_websocket_bool_t is_allowed_origin(const array *, const buffer *);
static int get_host_field(buffer *, const array *);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
static int get_key1_field(buffer *, const array *);
static int get_key2_field(buffer *, const array *);
static int get_key3_field(buffer *, const handler_ctx *);
static uint32_t count_spc(const buffer *);
static int get_key_number(uint32_t *, const buffer *);
static int create_MD5_sum(handler_ctx *);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
static void b64_encode(unsigned char *, const unsigned char *, size_t);
static int get_key_field(buffer *, const array *);
static int create_Accept(handler_ctx *);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

static int create_handshake_response(handler_ctx *);
static int websocket_handle_frame(handler_ctx *);
static int websocket_create_frame(handler_ctx *, char, char *, size_t);
static void websocket_send_closing_frame(server *, handler_ctx *);
static int encode_to(iconv_t, char *, size_t *, char *, size_t);
static handler_t websocket_handle_fdevent(server *, void *, int);
static int websocket_dispatch(server *, connection *, plugin_data *);
static handler_t websocket_check(server *, connection *, void *);
static handler_t websocket_disconnect(server *, connection *, void *);

handler_ctx *handler_ctx_init(void) {
    handler_ctx *hctx = calloc(1, sizeof(*hctx));

    if (!hctx) {
        return NULL;
    }
    hctx->state = MOD_WEBSOCKET_STATE_INIT;
    hctx->client_closed = MOD_WEBSOCKET_TRUE;
    hctx->server_closed = MOD_WEBSOCKET_TRUE;

    hctx->handshake.send = MOD_WEBSOCKET_FALSE;
    hctx->handshake.host = buffer_init();
    hctx->handshake.origin = buffer_init();
    hctx->handshake.subproto = buffer_init();

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    hctx->handshake.md5sum = buffer_init();
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    hctx->handshake.accept = buffer_init();
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx->frame.payload.data = buffer_init();

    hctx->inbuf = NULL;
    hctx->outbuf = chunkqueue_init();
    hctx->cds = (iconv_t)-1;
    hctx->cdc = (iconv_t)-1;
    hctx->fd = -1;
    hctx->fde_ndx = -1;
    hctx->ext = NULL;
    hctx->con = NULL;
    hctx->pd = NULL;

    return hctx;
}

void handler_ctx_free(handler_ctx *hctx) {
    if (!hctx) {
        return;
    }
    buffer_free(hctx->handshake.host);
    buffer_free(hctx->handshake.origin);
    buffer_free(hctx->handshake.subproto);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx->handshake.md5sum);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    buffer_free(hctx->handshake.accept);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    buffer_free(hctx->frame.payload.data);
    if (hctx->inbuf) {
        buffer_free(hctx->inbuf);
    }
    chunkqueue_free(hctx->outbuf);

    if (hctx->cds != (iconv_t)-1) {
        iconv_close(hctx->cds);
        hctx->cds = (iconv_t)-1;
    }
    if (hctx->cdc != (iconv_t)-1) {
        iconv_close(hctx->cdc);
        hctx->cdc = (iconv_t)-1;
    }
    if (0 < hctx->fd) {
        close(hctx->fd);
        hctx->fd = -1;
    }
    free(hctx);
    return;
}

INIT_FUNC(mod_websocket_init) {
    plugin_data *p = NULL;

    p = calloc(1, sizeof(*p));
    return p;
}

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

int set_subproto_extension(data_array *dst, const data_array *src) {
    size_t i, j;
    data_unset *data = NULL;
    data_string *host = NULL;
    data_integer *port = NULL;
    data_array *da_origins = NULL;
    data_array *origins = NULL;
    data_string *origin = NULL;
    data_string *locale = NULL;
    data_string *type = NULL;
    buffer *key = NULL;

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
            port = data_integer_init();
            buffer_copy_string_buffer(port->key, key);
            port->value = ((data_integer *)data)->value;
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
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_LOCALE) ) {
            locale = data_string_init();
            buffer_copy_string_buffer(locale->key, key);
            buffer_copy_string_buffer(locale->value,
                                      ((data_string *)data)->value);
            array_insert_unique(dst->value, (data_unset *)locale);
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

int set_extension(data_array *dst, const data_array *src) {
    int ret = -1;
    size_t i;
    data_array *subproto;

    if (!dst || !src) {
        return ret;
    }
    buffer_copy_string_buffer(dst->key, src->key);
    if (src->value->data[0]->type == TYPE_STRING) {
        subproto = data_array_init();
        ret = set_subproto_extension(subproto, src);
        array_insert_unique(dst->value, (data_unset *)subproto);
    } else if (src->value->data[0]->type == TYPE_ARRAY) {
        for (i = src->value->used; i > 0; i--) {
            data_array *da_src = (data_array *)src->value->data[i - 1];

            subproto = data_array_init();
            ret = set_subproto_extension(subproto, da_src);
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

SETDEFAULTS_FUNC(mod_websocket_set_defaults) {
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
            { MOD_WEBSOCKET_CONFIG_DEBUG,  NULL,
              T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
            { NULL,                        NULL,
              T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
        };

        s = malloc(sizeof(plugin_config));
        if (!s) { /* p->config_storage is freed in FREE_FUNC */
            log_error_write(srv, __FILE__, __LINE__, "s", "no memory");
            return HANDLER_ERROR;
        }
        s->exts = array_init();
        s->debug = 0;
        cv[0].destination = s->exts;
        cv[1].destination = &(s->debug);
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
            ret = set_extension(ext, da_src);
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

int tcp_server_connect(server *srv, handler_ctx *hctx) {
    struct sockaddr *addr;
    struct sockaddr_in addr_in;

#if defined (HAVE_IPV6) && defined (HAVE_INET_PTON)
    struct sockaddr_in6 addr_in6;
#endif

    socklen_t servlen;
    data_unset *du;
    buffer *host = NULL;
    int port = 0;

    if (!srv || !hctx) {
        return -1;
    }
    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_HOST);
    if (!du) {
        return -1;
    }
    host = ((data_string *)du)->value;
    if (!host) {
        return -1;
    }
    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_PORT);
    if (!du) {
        return -1;
    }
    port = ((data_integer *)du)->value;
    if (!port) {
        return -1;
    }

#if defined (HAVE_IPV6) && defined (HAVE_INET_PTON)
    if (strstr(host->ptr, ":")) {
        if (-1 == (hctx->fd = socket(AF_INET6, SOCK_STREAM, 0))) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "socket failed:", strerror(errno));
            return -1;
        }
        memset(&addr_in6, 0, sizeof(addr_in6));
        addr_in6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, host->ptr, (char *)&addr_in6.sin6_addr);
        addr_in6.sin6_port = htons(port);
        servlen = sizeof(addr_in6);
        addr = (struct sockaddr *) &addr_in6;
    } else {
#endif
        if (-1 == (hctx->fd = socket(AF_INET, SOCK_STREAM, 0))) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "socket failed:", strerror(errno));
            return -1;
        }
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = inet_addr(host->ptr);
        addr_in.sin_port = htons(port);
        servlen = sizeof(addr_in);
        addr = (struct sockaddr *) &addr_in;

#if defined (HAVE_IPV6) && defined (HAVE_INET_PTON)
    }
#endif

    hctx->fde_ndx = -1;
    srv->cur_fds++;
    fdevent_register(srv->ev, hctx->fd, websocket_handle_fdevent, hctx);
    if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "setting event failed:", strerror(errno));
        return -1;
    }
    if (-1 == connect(hctx->fd, addr, servlen)) {
        if (errno == EINPROGRESS || errno == EALREADY) {
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTING;
            if (hctx->pd->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                                "connect - delayed: fd =",
                                hctx->fd, ",", host->ptr, ":", port);
            }
            return 1;
        } else {
            if (hctx->pd->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                                "connect - failed: fd =",
                                hctx->fd, ",", host->ptr, ":", port);
            }
            return -1;
        }
    }
    if (hctx->pd->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                        "connect - success: fd =",
                        hctx->fd, ",", host->ptr, ":", port);
    }
    return 0;
}

void tcp_server_disconnect(server *srv, handler_ctx *hctx) {
    connection *con = NULL;
    plugin_data *p = NULL;

    if (!srv || !hctx) {
        return;
    }
    con = hctx->con;
    p = hctx->pd;
    if (0 < hctx->fd) {
        if (p->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "close: fd =", hctx->fd);
        }
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        fdevent_unregister(srv->ev, hctx->fd);
        close(hctx->fd);
        hctx->fd = -1;
        srv->cur_fds--;
    }
    handler_ctx_free(hctx);
    con->plugin_ctx[p->id] = NULL;
    return;
}

buffer *get_header_value(const array *headers, const char *key) {
    size_t i;
    data_string *header = NULL;

    if (!headers || !key) {
        return NULL;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            continue;
        }
        if ( buffer_is_equal_string(header->key, key, strlen(key)) ) {
            return header->value;
        }
    }
    return NULL;
}

mod_websocket_bool_t check_const_headers(const array *headers) {
    buffer *val;

    if (!headers) {
        return MOD_WEBSOCKET_FALSE;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_CONNECTION_STR);
    if (!val) {
        return MOD_WEBSOCKET_FALSE;
    }
    if ( strstr(val->ptr, MOD_WEBSOCKET_UPGRADE_STR) == NULL ) {
        return MOD_WEBSOCKET_FALSE;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_UPGRADE_STR);
    if (!val) {
        return MOD_WEBSOCKET_FALSE;
    }
    if ( buffer_is_equal_string(val,
                                CONST_STR_LEN(MOD_WEBSOCKET_WEBSOCKET_STR)) ) {
        return MOD_WEBSOCKET_TRUE;
    }
    return MOD_WEBSOCKET_FALSE;
}

int get_subproto_field(buffer *subproto, const array *headers) {
    buffer *val;

    if (!subproto || !headers) {
        return -1;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_SEC_WEBSOCKET_PROTOCOL_STR);
    if (!val) {
        return 0;
    }
    return buffer_copy_string_buffer(subproto, val);
}

data_array *get_subproto_extension(const array *subprotos, buffer *subproto) {
    size_t i;
    data_array *da_subproto = NULL;
    data_array *ext = NULL;

    if (!subprotos || !subproto) {
        return NULL;
    }
    if (buffer_is_empty(subproto) && subprotos->used == 1) {
        ext = (data_array *)subprotos->data[0];
        return ext;
    }
    for (i = subprotos->used; i > 0; i--) {
        da_subproto = (data_array *)subprotos->data[i - 1];
        if (strstr(subproto->ptr, da_subproto->key->ptr) != NULL) {
            ext = (data_array *)da_subproto;
            break;
        }
    }
    return ext;
}

int get_origin_field(buffer *origin, const array *headers) {
    buffer *val;

    if (!origin || !headers) {
        return -1;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    val = get_header_value(headers, MOD_WEBSOCKET_ORIGIN_STR);
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    val = get_header_value(headers, MOD_WEBSOCKET_SEC_WEBSOCKET_ORIGIN_STR);
#endif

    return buffer_copy_string_buffer(origin, val);
}

mod_websocket_bool_t is_allowed_origin(const array *allowed_origins,
                                       const buffer *origin) {
    size_t i;
    data_string *allowed_origin = NULL;

    if (!allowed_origins || !allowed_origins->used) {
        return MOD_WEBSOCKET_TRUE;
    }
    if (!origin) {
        return MOD_WEBSOCKET_FALSE;
    }
    for (i = allowed_origins->used; i > 0; i--) {
        allowed_origin = (data_string *)allowed_origins->data[i - 1];
        if (NULL != strstr(origin->ptr, allowed_origin->value->ptr)) {
            return MOD_WEBSOCKET_TRUE;
        }
    }
    return MOD_WEBSOCKET_FALSE;
}

int get_host_field(buffer *host, const array *headers) {
    buffer *val;

    if (!host || !headers) {
        return -1;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_HOST_STR);
    return buffer_copy_string_buffer(host, val);
}

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
int get_key1_field(buffer *key, const array *headers) {
    buffer *val;

    if (!key || !headers) {
        return -1;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_SEC_WEBSOCKET_KEY1_STR);
    return buffer_copy_string_buffer(key, val);
}

int get_key2_field(buffer *key, const array *headers) {
    buffer *val;

    if (!key || !headers) {
        return -1;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_SEC_WEBSOCKET_KEY2_STR);
    return buffer_copy_string_buffer(key, val);
}

int get_key3_field(buffer *key, const handler_ctx *hctx) {
    const char *body = NULL;
    char key3buf[MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN];
    int ret;
    struct pollfd pfd;
    int timeout = 100; /* poll timeout = 100ms */

    if (!key || !hctx) {
        return -1;
    }
    /* key3 is in separated packet */
    if (!hctx->con->read_queue->first ||
        hctx->con->read_queue->first != hctx->con->read_queue->last) {
        pfd.fd = hctx->con->fd;
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, timeout);
        if (ret > 0 && pfd.revents & POLLIN) {
            if ( read(hctx->con->fd, key3buf,
                      MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN) !=
                 MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN ) {
                return -1;
            }
            ret = buffer_copy_string_len(key, key3buf,
                                         MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN);
        } else {
            ret = -1;
        }
    } else {
        body = &hctx->con->read_queue->first->mem->ptr[hctx->con->read_queue->first->offset];
        ret = buffer_copy_string_len(key, body,
                                     MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN);
    }
    return ret;
}

uint32_t count_spc(const buffer *b) {
    size_t i;
    uint32_t c = 0;

    if (!b || !b->used) {
        return 0;
    }
    for (i = b->used; i > 0; i--) {
        c += (b->ptr[i - 1] == 0x20);
    }
    return c;
}

int get_key_number(uint32_t *ret, const buffer *b) {
#define	UINT32_MAX_STRLEN	(10)
    char tmp[UINT32_MAX_STRLEN + 1];
    size_t i, j = 0;
    unsigned long n;
    uint32_t s;

    if (!b || !b->used) {
        return -1;
    }
    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < b->used; i++) {
        if (isdigit((int)b->ptr[i])) {
            tmp[j] = b->ptr[i];
            j++;
        }
        if (UINT32_MAX_STRLEN < j) {
            return -1;
        }
    }
    n = strtoul(tmp, NULL, 10);
    if (UINT32_MAX < n) {
        return -1;
    }
    s = count_spc(b);
    if (s == 0) {
        return -1;
    }
    *ret = (uint32_t)(n / s);
    return 0;
#undef	UINT32_MAX_STRLEN
}

int create_MD5_sum(handler_ctx *hctx) {
#define MD5SUM_STRLEN	(16)
    unsigned char final[MD5SUM_STRLEN];
    unsigned char buf[MD5SUM_STRLEN];
    buffer *key1 = buffer_init();
    buffer *key2 = buffer_init();
    buffer *key3 = buffer_init();
    uint32_t k1 = 0, k2 = 0;
    MD5_CTX ctx;

    if (!hctx) {
        return -1;
    }
    if (get_key1_field(key1, hctx->con->request.headers) < 0) {
        goto err_out;
    }
    if (get_key2_field(key2, hctx->con->request.headers) < 0) {
        goto err_out;
    }
    if (get_key3_field(key3, hctx) < 0) {
        goto err_out;
    }
    if (get_key_number(&k1, key1) < 0) {
        return -1;
    }
    if (get_key_number(&k2, key2) < 0) {
        return -1;
    }
    buf[0] = k1 >> 24;
    buf[1] = k1 >> 16;
    buf[2] = k1 >> 8;
    buf[3] = k1;
    buf[4] = k2 >> 24;
    buf[5] = k2 >> 16;
    buf[6] = k2 >> 8;
    buf[7] = k2;
    memcpy(&buf[MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN], key3->ptr,
           MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN);
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, sizeof(buf));
    MD5_Final(final, &ctx);
    buffer_free(key1);
    buffer_free(key2);
    buffer_free(key3);
    return buffer_copy_string_len(hctx->handshake.md5sum,
                                  (char *)final, MD5SUM_STRLEN);

 err_out:
    buffer_free(key1);
    buffer_free(key2);
    buffer_free(key3);
    return -1;
#undef	MD5SUM_STRLEN
}
#endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
void b64_encode(unsigned char *dst, const unsigned char *src, size_t siz) {
    const unsigned char *base64 = (const unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char *p = (unsigned char *)src;
    unsigned long x = 0UL;
    int i = 0, l = 0;

    for (; siz > 0; p++, siz--) {
        x = x << 8 | *p;
        for (l += 8; l >= 6; l -= 6) {
            dst[i++] = base64[(x >> (l - 6)) & 0x3f];
        }
    }
    if (l > 0) {
        x <<= 6 - l;
        dst[i++] = base64[x & 0x3f];
    }
    for (; i % 4;) {
        dst[i++] = '=';
    }
    return;
}

int get_key_field(buffer *key, const array *headers) {
    buffer *val;

    if (!key || !headers) {
        return -1;
    }
    val = get_header_value(headers, MOD_WEBSOCKET_SEC_WEBSOCKET_KEY_STR);
    return buffer_copy_string_buffer(key, val);
}

int create_Accept(handler_ctx *hctx) {
    SHA1Context sha;
    uint8_t md[MOD_WEBSOCKET_MESSAGE_DIGEST_LEN];
    buffer *key = buffer_init();
    unsigned char buf[32];

    if (!hctx) {
        return -1;
    }
    if (get_key_field(key, hctx->con->request.headers) < 0) {
        goto err_out;
    }
    if (buffer_append_string(key, MOD_WEBSOCKET_GUID_STR) < 0) {
        goto err_out;
    }

    /* get SHA1 hash of key */
    if (SHA1Reset(&sha)) {
        goto err_out;
    }
    if (SHA1Input(&sha, (uint8_t *)key->ptr, key->used - 1)) {
        goto err_out;
    }
    if (SHA1Result(&sha, md)) {
        goto err_out;
    }
    /* get base64 encoded SHA1 hash */
    memset(buf, 0, 32);
    b64_encode(buf, md, MOD_WEBSOCKET_MESSAGE_DIGEST_LEN);
    buffer_free(key);
    return buffer_copy_string(hctx->handshake.accept, (char *)buf);

 err_out:
    buffer_free(key);
    return -1;
}
#endif /* _MOD_WEBSOCKET_SPEC_IETF_08_ */

int create_handshake_response(handler_ctx *hctx) {
    size_t i;
    struct {
        const char *b;
    } const_hdrs[] = {
#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        { "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" },
        { "Upgrade: WebSocket\r\n" },
#endif
#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
        { "HTTP/1.1 101 Switching Protocols\r\n" },
        { "Upgrade: websocket\r\n" },
#endif
        { "Connection: Upgrade\r\n" },
    };
    buffer *resp = NULL;

    if (!hctx) {
        return -1;
    }
    resp = chunkqueue_get_append_buffer(hctx->outbuf);

    for (i = 0; i < (sizeof(const_hdrs) / sizeof(const_hdrs[0])); i++) {
        buffer_append_string(resp, const_hdrs[i].b);
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    /* Sec-WebSocket-Origin header */
    buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_ORIGIN_STR);
    buffer_append_string(resp, ": ");
    buffer_append_string_buffer(resp, hctx->handshake.origin);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);

    /* Sec-WebSocket-Location header */
    buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_LOCATION_STR);
    buffer_append_string(resp, ": ");

    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

# ifdef	USE_OPENSSL
        buffer_append_string(resp, MOD_WEBSOCKET_SCHEME_WSS);
# else	/* SSL is not available */
        return -1;
# endif	/* USE_OPENSSL */

    } else {
        buffer_append_string(resp, MOD_WEBSOCKET_SCHEME_WS);
    }
    buffer_append_string_buffer(resp, hctx->handshake.host);
    buffer_append_string_buffer(resp, hctx->con->uri.path);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    if (!buffer_is_empty(hctx->handshake.subproto)) {
        buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_PROTOCOL_STR);
        buffer_append_string(resp, ": ");

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        buffer_append_string_buffer(resp, hctx->handshake.subproto);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
        buffer_append_string_buffer(resp, hctx->ext->key);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

        buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_ACCEPT_STR);
    buffer_append_string(resp, ": ");
    buffer_append_string_buffer(resp, hctx->handshake.accept);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_append_string_buffer(resp, hctx->handshake.md5sum);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    return 0;
}

SUBREQUEST_FUNC(mod_websocket_handle_subrequest) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    data_array *origins = NULL;
    data_string *locale = NULL;
    char *nlinfo = NULL;
    int ret;
    int sockret;
    socklen_t socklen = sizeof(sockret);

    if (!hctx) {
        return HANDLER_GO_ON;
    }
    /* not my job */
    if (con->mode != p->id) {
        return HANDLER_GO_ON;
    }

    switch (hctx->state) {
    case MOD_WEBSOCKET_STATE_INIT:
        if (!check_const_headers(con->request.headers)) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found some mandatory headers");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        ret = get_subproto_field(hctx->handshake.subproto,
                                 con->request.headers);
        if (0 != ret) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "recv invalid sub protocol");
            }
            con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        hctx->ext = get_subproto_extension(hctx->ext->value,
                                           hctx->handshake.subproto);
        if (hctx->ext == NULL) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "not found specified sub protocol:",
                                hctx->handshake.subproto->ptr);
            }
            con->http_status = MOD_WEBSOCKET_NOT_FOUND;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        ret = get_origin_field(hctx->handshake.origin, con->request.headers);
        if (0 != ret) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found origin header");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        origins = (data_array *)array_get_element(hctx->ext->value,
                                                  MOD_WEBSOCKET_CONFIG_ORIGINS);
        if (origins) {
            if (!is_allowed_origin(origins->value, hctx->handshake.origin)) {
                if (p->conf.debug) {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                                    "not allowed origin:",
                                    hctx->handshake.origin->ptr);
                }
                con->http_status = MOD_WEBSOCKET_FORBIDDEN;
                con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
        }
        ret = get_host_field(hctx->handshake.host, con->request.headers);
        if (0 != ret) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found host headers");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        ret = create_MD5_sum(hctx);
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
        ret = create_Accept(hctx);
#endif

        if (ret < 0) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "fail to verify Sec-WebSocket-Key");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        /* pass to check headers in request */

        /* next connect to application server */
        switch (tcp_server_connect(srv, hctx)) {
        case 0: /* connected */
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
            break;
        case 1: /* connecting */
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTING;
            fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
            return HANDLER_WAIT_FOR_EVENT;
            break;
        default: /* could not connect */
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "sd",
                                "connect - failed: fd =", hctx->fd);
            }
            hctx->con->http_status = MOD_WEBSOCKET_SERVICE_UNAVAILABLE;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
            break;
        }

        /* fall through */

    case MOD_WEBSOCKET_STATE_CONNECTING:
        if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR,
                            &sockret, &socklen)) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "getsockopt failed:", strerror(errno));
            fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
            joblist_append(srv, hctx->con);
            tcp_server_disconnect(srv, hctx);
            hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (0 != sockret) {
            fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
            joblist_append(srv, hctx->con);
            tcp_server_disconnect(srv, hctx);
            hctx->con->http_status = MOD_WEBSOCKET_SERVICE_UNAVAILABLE;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (hctx->state == MOD_WEBSOCKET_STATE_CONNECTING && p->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__,  "sd",
                            "connect - delayed success: fd =", hctx->fd);
        }
        hctx->state = MOD_WEBSOCKET_STATE_SEND_RESPONSE;
        hctx->server_closed = MOD_WEBSOCKET_FALSE;
        hctx->client_closed = MOD_WEBSOCKET_FALSE;

        /* ok, prepare descripter for iconv */
        locale = (data_string *)array_get_element(hctx->ext->value,
                                                  MOD_WEBSOCKET_CONFIG_LOCALE);
        if (locale) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "specified locale:", locale->value->ptr);
            }
            hctx->cds = iconv_open(locale->value->ptr,
                                   MOD_WEBSOCKET_UTF8_STR);
            hctx->cdc = iconv_open(MOD_WEBSOCKET_UTF8_STR,
                                   locale->value->ptr);
        } else {
            setlocale(LC_ALL, "");
            nlinfo = nl_langinfo(CODESET);
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "use default locale:", nlinfo);
            }
            hctx->cds = iconv_open(nlinfo, MOD_WEBSOCKET_UTF8_STR);
            hctx->cdc = iconv_open(MOD_WEBSOCKET_UTF8_STR, nlinfo);
        }
        if ((iconv_t) -1 == hctx->cds || (iconv_t) -1 == hctx->cdc) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "iconv_open failed.");
            fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
            joblist_append(srv, hctx->con);
            tcp_server_disconnect(srv, hctx);
            hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
            hctx->con->mode = DIRECT;
            return HANDLER_FINISHED;
        }

        /* fall through */

    case MOD_WEBSOCKET_STATE_SEND_RESPONSE:
        if (!hctx->handshake.send) {
            ret = create_handshake_response(hctx);
            if (ret < 0) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "create handshake response error");
                fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
                joblist_append(srv, hctx->con);
                tcp_server_disconnect(srv, hctx);
                hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
                hctx->con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                ret = srv->network_ssl_backend_write(srv, con,
                                                     hctx->con->ssl,
                                                     hctx->outbuf);
#else	/* SSL is not available */
                ret = -1;
#endif	/* USE_OPENSSL */

            } else {
                ret = srv->network_backend_write(srv, con,
                                                 hctx->con->fd,
                                                 hctx->outbuf);
            }
            if (0 <= ret) {
                chunkqueue_remove_finished_chunks(hctx->outbuf);
            } else {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "send handshake response error:",
                                strerror(errno));
                fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
                joblist_append(srv, hctx->con);
                tcp_server_disconnect(srv, hctx);
                hctx->con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
                hctx->con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
            connection_set_state(srv, hctx->con, CON_STATE_READ_CONTINUOUS);
            hctx->handshake.send = MOD_WEBSOCKET_TRUE;
            return HANDLER_WAIT_FOR_EVENT;
        } else {
            if (chunkqueue_is_empty(hctx->outbuf)) {
                hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
                chunkqueue_reset(hctx->con->read_queue);
                return HANDLER_WAIT_FOR_EVENT;
            } else {
                if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                    ret = srv->network_ssl_backend_write(srv, con,
                                                         hctx->con->ssl,
                                                         hctx->outbuf);
#else	/* SSL is not available */
                    ret = -1;
#endif	/* USE_OPENSSL */

                } else {
                    ret = srv->network_backend_write(srv, con,
                                                     hctx->con->fd,
                                                     hctx->outbuf);
                }
                if (0 <= ret) {
                    chunkqueue_remove_finished_chunks(hctx->outbuf);
                } else {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                                    "send handshake response error:",
                                    strerror(errno));
                    tcp_server_disconnect(srv, hctx);
                    connection_set_state(srv, con, CON_STATE_CLOSE);
                    return HANDLER_FINISHED;
                }
                return HANDLER_WAIT_FOR_EVENT;
            }
        }
        /* never reach */
        log_error_write(srv, __FILE__, __LINE__, "s", "invalid state");
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        joblist_append(srv, hctx->con);
        tcp_server_disconnect(srv, hctx);
        connection_set_state(srv, con, CON_STATE_CLOSE);
        return HANDLER_FINISHED;
        break;

    case MOD_WEBSOCKET_STATE_CONNECTED:
        if (hctx->server_closed) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "disconnected from server");
            }
            if (!hctx->client_closed) {
                websocket_send_closing_frame(srv, hctx);
            }
            break;
        } else {
            if (websocket_handle_frame(hctx) < 0) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "recv closing frame or invalid frame");
                break;
            }
            ret = srv->network_backend_write(srv, con, hctx->fd,
                                             con->read_queue);
            if (0 <= ret) {
                chunkqueue_remove_finished_chunks(con->read_queue);
            } else {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "write error(server):", strerror(errno));
                break;
            }
        }
        if (hctx->client_closed) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "disconnected from client");
            }
            break;
        } else {
            if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
                ret = srv->network_ssl_backend_write(srv, con,
                                                     hctx->con->ssl,
                                                     hctx->outbuf);
#else	/* SSL is not available */
                ret = -1;
#endif	/* USE_OPENSSL */

            } else {
                ret = srv->network_backend_write(srv, con,
                                                 hctx->con->fd,
                                                 hctx->outbuf);
            }
            if (0 <= ret) {
                chunkqueue_remove_finished_chunks(hctx->outbuf);
            } else {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "write error(client):", strerror(errno));
                break;
            }
        }
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
        if (!chunkqueue_is_empty(con->read_queue)) {
            fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
        } else {
            fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
        }
        if (!chunkqueue_is_empty(hctx->outbuf)) {
            fdevent_event_set(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_OUT);
        } else {
            fdevent_event_set(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
        }
        return HANDLER_WAIT_FOR_EVENT;
        break;
    }
    chunkqueue_reset(hctx->outbuf);
    chunkqueue_reset(hctx->con->read_queue);
    connection_set_state(srv, con, CON_STATE_CLOSE);
    fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
    tcp_server_disconnect(srv, hctx);
    return HANDLER_FINISHED;
}

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
int websocket_handle_frame(handler_ctx *hctx) {
    chunk *c = NULL;
    char *pdata = NULL;
    char *writebuf = NULL;
    size_t i, len = 0;

    if (!hctx->con || !hctx->con->read_queue) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->con->read_queue)) {
        return 0;
    }
    /* serialize data */
    for (c = hctx->con->read_queue->first; c; c = c->next) {
        if (NULL == hctx->inbuf) {
            hctx->inbuf = buffer_init_buffer(c->mem);
        } else {
            buffer_append_memory(hctx->inbuf, c->mem->ptr, c->mem->used);
        }
    }
    chunkqueue_reset(hctx->con->read_queue);
    pdata = hctx->inbuf->ptr;
    for (i = 0; i < hctx->inbuf->used; pdata++, i++) {
        switch (hctx->frame.state) {
        case MOD_WEBSOCKET_FRAME_STATE_INIT:
            if (0x00 == *pdata) {
                hctx->frame.payload.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
            } else {
                hctx->frame.payload.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
            }
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
            break;
        case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
            if (buffer_is_empty(hctx->frame.payload.data)) {
                buffer_copy_memory(hctx->frame.payload.data, pdata,
                                   hctx->inbuf->used - i - 1);
            } else {
                buffer_append_memory(hctx->frame.payload.data, pdata,
                                     hctx->inbuf->used - i - 1);
            }
            i = hctx->inbuf->used;
            break;
        }
    }
    buffer_reset(hctx->inbuf);
    /* no browsers can handle binary data in IETF-00 SPEC */
    if (hctx->frame.payload.type == MOD_WEBSOCKET_FRAME_TYPE_BIN) {
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        buffer_reset(hctx->frame.payload.data);
        return -1;
    }
    if (hctx->frame.payload.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT &&
        hctx->frame.payload.data->ptr[hctx->frame.payload.data->used - 1]
        == -1) {
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        len = hctx->frame.payload.data->used - 1;
        writebuf = (char *)malloc(len + 1);
        if (!writebuf) {
            buffer_reset(hctx->frame.payload.data);
            return -1;
        }
        if (encode_to(hctx->cds, writebuf, &len,
                      hctx->frame.payload.data->ptr, len) < 0) {
            free(writebuf);
            writebuf = NULL;
            buffer_reset(hctx->frame.payload.data);
            return -1;
        }
        chunkqueue_append_mem(hctx->con->read_queue,
                              writebuf, strlen(writebuf) + 1);
        buffer_reset(hctx->frame.payload.data);
        free(writebuf);
        writebuf = NULL;
    }
    return 0;
}

int websocket_create_frame(handler_ctx *hctx,
                           char type, char *data, size_t siz) {
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    buffer *buf;
    char *enc;
    size_t encsiz;

    buf = chunkqueue_get_append_buffer(hctx->outbuf);
    if (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
        buffer_append_memory(buf, (const char *)&head, 1);
        encsiz = siz + 1;
        enc = (char *)malloc(encsiz);
        if (!enc) {
            buffer_reset(buf);
            return -1;
        }
        if (0 <= encode_to(hctx->cdc, enc, &encsiz, data, siz)) {
            buffer_append_memory(buf, enc, strlen(enc));
        } else {
            buffer_reset(buf);
            return -1;
        }
        buffer_append_memory(buf, (const char *)&tail, 1);
    } else {
        return -1; /* browser follows IETF-00 SPEC can't handle binary data */
    }
    buffer_append_memory(buf, (const char *)&head, 1);
    return 0;
}

void websocket_send_closing_frame(server *srv, handler_ctx *hctx) {
    buffer *buf;
    const unsigned char closing_frame[3] = { 0xff, 0x00, 0x00 };

    buf = chunkqueue_get_append_buffer(hctx->outbuf);
    buffer_append_memory(buf,
                         (const char *)closing_frame, sizeof(closing_frame));
    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

# ifdef	USE_OPENSSL
        srv->network_ssl_backend_write(srv, hctx->con,
                                       hctx->con->ssl, hctx->outbuf);
# endif	/* USE_OPENSSL */

    } else {
        srv->network_backend_write(srv, hctx->con,
                                   hctx->con->fd, hctx->outbuf);
    }
    chunkqueue_remove_finished_chunks(hctx->outbuf);
    return;
}
#endif /* 	_MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
void unmask_payload(mod_websocket_frame_t *frame) {
    size_t i;

    for (i = 0; i < frame->payload.data->used; i++) {
        frame->payload.data->ptr[i] =
            frame->payload.data->ptr[i] ^ frame->ctl.mask[i % 4];
    }
    return;
}

int websocket_handle_frame(handler_ctx *hctx) {
    chunk *c = NULL;
    char *pdata = NULL;
    char *writebuf = NULL;
    size_t i, cnt = 0, len = 0;
    int ret;

    if (!hctx->con || !hctx->con->read_queue) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->con->read_queue)) {
        return 0;
    }
    /* serialize data */
    for (c = hctx->con->read_queue->first; c; c = c->next) {
        if (NULL == hctx->inbuf) {
            hctx->inbuf = buffer_init_buffer(c->mem);
        } else {
            buffer_append_memory(hctx->inbuf, c->mem->ptr, c->mem->used);
        }
    }
    chunkqueue_reset(hctx->con->read_queue);
    pdata = hctx->inbuf->ptr;
    for (i = 0; i < hctx->inbuf->used; pdata++, i++) {
        switch (hctx->frame.state) {
        case MOD_WEBSOCKET_FRAME_STATE_INIT:
            hctx->frame.ctl.fin = ((*pdata & 0x80) == 0x80);
            hctx->frame.ctl.rsv = *pdata & 0x70;
            hctx->frame.ctl.opcode = *pdata & 0x0f;
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH;
            break;
        case MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH:
            hctx->frame.ctl.mask_flag = ((*pdata & 0x80) == 0x80);
            hctx->frame.ctl.siz = *pdata & 0x7f;
            if (hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN16 ||
                hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN63) {
                hctx->frame.payload.siz = 0;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
            } else if (hctx->frame.ctl.siz == 0) {
                break;
            } else {
                hctx->frame.ctl.mask_cnt = 0;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
            }
            break;
        case MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH:
            hctx->frame.payload.siz =
                hctx->frame.payload.siz * 256 + (*pdata & 0x0ff);
            cnt++;
            if ((cnt >= MOD_WEBSOCKET_FRAME_LEN16_CNT &&
                 hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN16) ||
                (cnt >= MOD_WEBSOCKET_FRAME_LEN63_CNT &&
                 hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN63)) {
                hctx->frame.ctl.siz = hctx->frame.payload.siz;
                hctx->frame.ctl.mask_cnt = 0;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
            }
            break;
        case MOD_WEBSOCKET_FRAME_STATE_READ_MASK:
            hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt] = *pdata;
            hctx->frame.ctl.mask_cnt++;
            if (hctx->frame.ctl.mask_cnt >= MOD_WEBSOCKET_MASK_CNT) {
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
            }
            break;
        case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
            if (buffer_is_empty(hctx->frame.payload.data)) {
                buffer_copy_memory(hctx->frame.payload.data, pdata,
                                   hctx->inbuf->used - i - 1);
            } else {
                buffer_append_memory(hctx->frame.payload.data, pdata,
                                     hctx->inbuf->used - i - 1);
            }
            i = hctx->inbuf->used;
            break;
        }
    }
    buffer_reset(hctx->inbuf);
    if (hctx->frame.ctl.rsv != 0 || !hctx->frame.ctl.mask_flag) {
        return -1;
    }
    switch (hctx->frame.ctl.opcode) {
    case MOD_WEBSOCKET_OPCODE_CONT:
        break;
    case MOD_WEBSOCKET_OPCODE_TEXT:
        hctx->frame.payload.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
        break;
    case MOD_WEBSOCKET_OPCODE_BIN:
        hctx->frame.payload.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
        break;
    case MOD_WEBSOCKET_OPCODE_PING:
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        unmask_payload(&hctx->frame);
        ret = websocket_create_frame(hctx, MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                     hctx->frame.payload.data->ptr,
                                     hctx->frame.ctl.siz);
        buffer_reset(hctx->frame.payload.data);
        return ret;
        break;
    case MOD_WEBSOCKET_OPCODE_PONG:
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        buffer_reset(hctx->frame.payload.data);
        return 0;
        break;
    case MOD_WEBSOCKET_OPCODE_CLOSE:
    default:
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        buffer_reset(hctx->frame.payload.data);
        return -1;
        break;
    }
    if (hctx->frame.payload.data->used >= hctx->frame.ctl.siz &&
        (hctx->frame.payload.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
         hctx->frame.payload.type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        unmask_payload(&hctx->frame);
        if (hctx->frame.payload.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
            hctx->frame.payload.data->ptr[hctx->frame.ctl.siz] = 0;
            len = hctx->frame.ctl.siz;
            writebuf = (char *)malloc(len + 1);
            if (!writebuf) {
                buffer_reset(hctx->frame.payload.data);
                return -1;
            }
            if (encode_to(hctx->cds, writebuf, &len,
                          hctx->frame.payload.data->ptr,
                          hctx->frame.ctl.siz) < 0) {
                free(writebuf);
                writebuf = NULL;
                buffer_reset(hctx->frame.payload.data);
                return -1;
            }
            chunkqueue_append_mem(hctx->con->read_queue,
                                  writebuf, strlen(writebuf) + 1);
            buffer_reset(hctx->frame.payload.data);
            free(writebuf);
            writebuf = NULL;
        }
        if (hctx->frame.ctl.opcode == MOD_WEBSOCKET_OPCODE_BIN) {
            chunkqueue_append_buffer(hctx->con->read_queue,
                                     hctx->frame.payload.data);
            buffer_reset(hctx->frame.payload.data);
        }
    }
    return 0;
}

int websocket_create_frame(handler_ctx *hctx,
                           char type, char *data, size_t siz) {
    buffer *buf;
    char c;
    char *enc;
    size_t encsiz;

    buf = chunkqueue_get_append_buffer(hctx->outbuf);
    if (type == MOD_WEBSOCKET_FRAME_TYPE_BIN) {
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_BIN);
    } else if (type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_PONG);
    } else {
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_TEXT);
    }
    buffer_append_memory(buf, &c, 1);
    if (siz < MOD_WEBSOCKET_FRAME_LEN16) {
        c = siz;
        buffer_append_memory(buf, &c, 1);
    } else {
        c = MOD_WEBSOCKET_FRAME_LEN16;
        buffer_append_memory(buf, &c, 1);
        c = (siz & 0x0ff00) >> 8;
        buffer_append_memory(buf, &c, 1);
        c = siz & 0x0ff;
        buffer_append_memory(buf, &c, 1);
    }
    if (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
        encsiz = siz + 1;
        enc = (char *)malloc(encsiz);
        if (!enc) {
            buffer_reset(buf);
            return -1;
        }
        if (0 <= encode_to(hctx->cdc, enc, &encsiz, data, siz)) {
            buffer_append_memory(buf, enc, strlen(enc));
        } else {
            buffer_reset(buf);
            return -1;
        }
    } else {
        buffer_append_memory(buf, data, siz);
    }
    c = 0;
    buffer_append_memory(buf, &c, 1);
    return 0;
}

void websocket_send_closing_frame(server *srv, handler_ctx *hctx) {
    buffer *buf;
    char c;

    buf = chunkqueue_get_append_buffer(hctx->outbuf);
    c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_CLOSE);
    buffer_append_memory(buf, &c, 1);

    c = 0; /* not contain any closing status code */
    buffer_append_memory(buf, &c, 1);
    buffer_append_memory(buf, &c, 1); /* tail */

    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

# ifdef	USE_OPENSSL
        srv->network_ssl_backend_write(srv, hctx->con,
                                       hctx->con->ssl, hctx->outbuf);
# endif	/* USE_OPENSSL */

    } else {
        srv->network_backend_write(srv, hctx->con,
                                   hctx->con->fd, hctx->outbuf);
    }
    chunkqueue_remove_finished_chunks(hctx->outbuf);
    return;
}
#endif /* _MOD_WEBSOCKET_SPEC_IETF_08_ */

int encode_to(iconv_t cd, char *dst, size_t *dstlen,
              char *src, size_t srclen) {
    size_t r;

    if ((iconv_t) -1 == cd) {
        return 0;
    }
    if (!dst || !dstlen || !(*dstlen) || !src) {
        return -1;
    }
    memset(dst, 0, *dstlen);
    r = iconv(cd, &src, &srclen, &dst, dstlen);
    if (r == (size_t)-1) {
        return -1;
    }
    *dst = '\0';
    return 0;
}

handler_t websocket_handle_fdevent(server *srv, void *ctx, int revents) {
    int b = 0;
    handler_ctx *hctx = (handler_ctx *)ctx;
    ssize_t r;
    data_string *type;
    char t;
    char readbuf[UINT16_MAX + 1];

    if (revents & FDEVENT_NVAL) {
        if (hctx->pd->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "sdsd",
                            "fd is not open(NVAL): fd(srv) =", hctx->fd,
                            "fd(cli) =", hctx->con->fd);
        }
        hctx->server_closed = MOD_WEBSOCKET_TRUE;
        return mod_websocket_handle_subrequest(srv, hctx->con, hctx->pd);
    }
    if (revents & FDEVENT_IN) {
        if (hctx->state == MOD_WEBSOCKET_STATE_CONNECTED) {
            /* check how much we have to read */
            if (ioctl(hctx->fd, FIONREAD, &b)) {
                log_error_write(srv, __FILE__, __LINE__, "sd",
                                "ioctl failed:", hctx->fd);
                hctx->server_closed = MOD_WEBSOCKET_TRUE;
                return mod_websocket_handle_subrequest(srv, hctx->con, hctx->pd);
            }
            if (!b || b > (int)sizeof(readbuf)) {
                b = sizeof(readbuf);
            }
            errno = 0;
            r = read(hctx->fd, readbuf, b);
            if (0 < r) {
                type = (data_string *)array_get_element(hctx->ext->value,
                                                        MOD_WEBSOCKET_CONFIG_TYPE);
                if ( type &&
                     0 == strcasecmp(type->value->ptr,
                                     MOD_WEBSOCKET_BIN_STR) ) {
                    t = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                } else {
                    t = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                }
                if (websocket_create_frame(hctx, t, readbuf, r) < 0) {
                    log_error_write(srv, __FILE__, __LINE__, "sd",
                                    "create websocket frame failed: fd =",
                                    hctx->fd);
                    hctx->server_closed = MOD_WEBSOCKET_TRUE;
                }
            } else if (errno != EAGAIN) {
                hctx->server_closed = MOD_WEBSOCKET_TRUE;
            }
        }
        return mod_websocket_handle_subrequest(srv, hctx->con, hctx->pd);
    }
    if (revents & FDEVENT_HUP) {
        if (hctx->pd->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "connect - failed(HUP): fd =", hctx->fd);
        }
        hctx->server_closed = MOD_WEBSOCKET_TRUE;
    } else if (revents & FDEVENT_ERR) {
        log_error_write(srv, __FILE__, __LINE__, "sd",
                        "connect - failed(ERR): fd =", hctx->fd);
        hctx->server_closed = MOD_WEBSOCKET_TRUE;
    }
    return mod_websocket_handle_subrequest(srv, hctx->con, hctx->pd);
}

int websocket_dispatch(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

#define PATCH(x) do { p->conf.x = s->x; } while (0)

    PATCH(exts);
    PATCH(debug);

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

handler_t websocket_check(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;
    size_t i;
    data_array *ext = NULL;
    handler_ctx *hctx = NULL;

    if (con->request.http_method != HTTP_METHOD_GET) {
        return HANDLER_GO_ON;
    }
    if (websocket_dispatch(srv, con, p) < 0) {
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
    if (p->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "found extension:", ext->key->ptr);
    }
    /* init handler-context */
    hctx = handler_ctx_init();
    if (!hctx) {
        log_error_write(srv, __FILE__, __LINE__, "s", "no memory.");
        return HANDLER_ERROR;
    }
    hctx->ext = ext;
    hctx->con = con;
    hctx->pd = p;
    con->plugin_ctx[p->id] = hctx;
    con->mode = p->id;
    return HANDLER_GO_ON;
}

handler_t websocket_disconnect(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;

    if (con->plugin_ctx[p->id]) {
        if (p->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "disconnect - event received");
        }
        tcp_server_disconnect(srv, con->plugin_ctx[p->id]);
    }
    return HANDLER_GO_ON;
}

/* suppress warning */
int mod_websocket_plugin_init(plugin *);

int mod_websocket_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name = buffer_init_string("websocket");
    p->init = mod_websocket_init;
    p->cleanup = mod_websocket_free;
    p->set_defaults = mod_websocket_set_defaults;
    p->connection_reset = websocket_disconnect;
    p->handle_connection_close = websocket_disconnect;
    p->handle_uri_clean = websocket_check;
    p->handle_subrequest = mod_websocket_handle_subrequest;
    p->read_continuous = mod_websocket_handle_subrequest;
    p->data = NULL;
    return 0;
}

/* EOF */
