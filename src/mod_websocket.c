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
#include "md5.h"
#include "log.h"

#include "mod_websocket.h"

/* prototypes */
#ifndef	_MOD_WEBSOCKET_TEST_
static handler_ctx *handler_ctx_init(void);
static void handler_ctx_free(handler_ctx *);
static int set_subproto_extension(data_array *, const data_array *);
static int set_extension(data_array *, const data_array *);
static int tcp_server_connect(server *, handler_ctx *);
static void tcp_server_disconnect(server *, handler_ctx *);
static mod_websocket_bool_t check_const_headers(const array *);
static int get_subproto_field(buffer *, const array *);
static data_array *get_subproto_extension(const array *, buffer *);
static int get_origin_field(buffer *, const array *);
static mod_websocket_bool_t is_allowed_origin(const array *, const buffer *);
static int get_host_field(buffer *, const array *);

# ifdef	_MOD_WEBSOCKET_SPEC_76_
static int get_key1_field(buffer *, const array *);
static int get_key2_field(buffer *, const array *);
static int get_key3_field(buffer *, const handler_ctx *);
static uint32_t count_spc(const buffer *);
static int get_key_number(uint32_t *, const buffer *);
static int create_MD5_sum(handler_ctx *);
# endif	/* _MOD_WEBSOCKET_SPEC_76_ */

static int create_handshake_response(handler_ctx *);
static int websocket_handle_frame(handler_ctx *);
static void websocket_send_closing_frame(server *, handler_ctx *);
static int encode_to(iconv_t, char *, size_t *, char *, size_t);
static handler_t websocket_handle_fdevent(void *, void *, int);
static int websocket_dispatch(server *, connection *, plugin_data *);
static handler_t websocket_check(server *, connection *, void *);
static handler_t websocket_disconnect(server *, connection *, void *);
#endif


handler_ctx *handler_ctx_init(void) {
    handler_ctx *hctx = calloc(1, sizeof(*hctx));

    if (!hctx) {
        return NULL;
    }
    hctx->state = MOD_WEBSOCKET_STATE_INIT;

    hctx->req.host = buffer_init();
    hctx->req.origin = buffer_init();
    hctx->req.subproto = buffer_init();

#ifdef	_MOD_WEBSOCKET_SPEC_76_
    hctx->req.md5sum = buffer_init();
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx->frame.siz = 0;
    hctx->send_response = MOD_WEBSOCKET_FALSE;
    hctx->client_closed = MOD_WEBSOCKET_TRUE;
    hctx->server_closed = MOD_WEBSOCKET_TRUE;
    hctx->write_queue = chunkqueue_init();
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
    hctx->state = MOD_WEBSOCKET_STATE_INIT;
    if (hctx->req.host) {
        buffer_free(hctx->req.host);
        hctx->req.host = NULL;
    }
    if (hctx->req.origin) {
        buffer_free(hctx->req.origin);
        hctx->req.origin = NULL;
    }
    if (hctx->req.subproto) {
        buffer_free(hctx->req.subproto);
        hctx->req.subproto = NULL;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_76_
    buffer_free(hctx->req.md5sum);
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

    if (hctx->write_queue) {
        chunkqueue_free(hctx->write_queue);
        hctx->write_queue = NULL;
    }
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
    data_string *host = NULL;
    data_integer *port = NULL;
    data_array *da_origins = NULL;
    data_array *origins = NULL;
    data_string *origin = NULL;
    data_string *locale = NULL;
    buffer *key = NULL;

    for (i = src->value->used; i > 0; i--) {
        key = src->value->data[i - 1]->key;
        if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_HOST) ) {
            host = data_string_init();
            buffer_copy_string_buffer(host->key, key);
            buffer_copy_string_buffer(host->value,
                                      ((data_string *)(src->value->data[i - 1]))->value);
            array_insert_unique(dst->value, (data_unset *)host);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_PORT) ) {
            port = data_integer_init();
            buffer_copy_string_buffer(port->key, key);
            port->value = ((data_integer *)(src->value->data[i - 1]))->value;
            array_insert_unique(dst->value, (data_unset *)port);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_SUBPROTO) ) {
            buffer_copy_string_buffer(dst->key, ((data_string *)(src->value->data[i - 1]))->value);
        } else if ( 0 == strcmp(key->ptr, MOD_WEBSOCKET_CONFIG_ORIGINS) ) {
            origins = data_array_init();
            buffer_copy_string_len(origins->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_CONFIG_ORIGINS));
            if (src->value->data[i - 1]->type == TYPE_STRING) {
                origin = data_string_init();
                buffer_copy_string_buffer(origin->value,
                                          ((data_string *)src->value->data[i - 1])->value);
                array_insert_unique(origins->value, (data_unset *)origin);
            } else if (src->value->data[i - 1]->type == TYPE_ARRAY) {
                da_origins = (data_array *)src->value->data[i - 1];
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
                                      ((data_string *)(src->value->data[i - 1]))->value);
            array_insert_unique(dst->value, (data_unset *)locale);
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
            { MOD_WEBSOCKET_CONFIG_SERVER, NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
            { MOD_WEBSOCKET_CONFIG_DEBUG,  NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
            { NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
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

    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_HOST);
    if (!du) {
        return -1;
    }
    host = ((data_string *)du)->value;
    du = array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_PORT);
    if (!du) {
        return -1;
    }
    port = ((data_integer *)du)->value;

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
    } else
#endif
        {
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
        }

    hctx->fde_ndx = -1;
    srv->cur_fds++;
    fdevent_register(srv->ev, hctx->fd, websocket_handle_fdevent, hctx);
    if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "fcntl failed:", strerror(errno));
        return -1;
    }
    if (-1 == connect(hctx->fd, addr, servlen)) {
        if (errno == EINPROGRESS || errno == EALREADY) {
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTING;
            if (hctx->pd->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                                "connect - delayed: fd =",
                                hctx->fd, "=>", host->ptr, ":", port);
            }
            return 1;
        } else {
            if (hctx->pd->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                                "connect - failed: fd =",
                                hctx->fd, "=>", host->ptr, ":", port);
            }
            return -1;
        }
    }
    if (hctx->pd->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__, "sdsssd",
                        "connect - success: fd =",
                        hctx->fd, "=>", host->ptr, ":", port);
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

mod_websocket_bool_t check_const_headers(const array *headers) {
    struct {
        const char *key;
        const char *val;
        mod_websocket_bool_t pass;
    } const_hdrs[] = {
        {
            MOD_WEBSOCKET_CONNECTION_STR,
            MOD_WEBSOCKET_UPGRADE_STR,
            MOD_WEBSOCKET_FALSE
        },
        {
            MOD_WEBSOCKET_UPGRADE_STR,
            MOD_WEBSOCKET_WEBSOCKET_STR,
            MOD_WEBSOCKET_FALSE
        },
    };
    size_t i, j;
    mod_websocket_bool_t ret = MOD_WEBSOCKET_TRUE;
    data_string *header = NULL;

    if (!headers) {
        return MOD_WEBSOCKET_FALSE;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return MOD_WEBSOCKET_FALSE;
        }
        for (j = (sizeof(const_hdrs) / sizeof(const_hdrs[0])); j > 0; j--) {
            if ( buffer_is_equal_string(header->key,
                                        const_hdrs[j - 1].key,
                                        strlen(const_hdrs[j - 1].key)) &&
                 buffer_is_equal_string(header->value,
                                        const_hdrs[j - 1].val,
                                        strlen(const_hdrs[j - 1].val)) ) {
                const_hdrs[j - 1].pass = MOD_WEBSOCKET_TRUE;
            }
        }
    }
    for (i = (sizeof(const_hdrs) / sizeof(const_hdrs[0])); i > 0; i--) {
        ret &= const_hdrs[i - 1].pass;
    }
    return ret;
}

int get_subproto_field(buffer *subproto, const array *headers) {
    size_t i;
    data_string *header = NULL;

    if (!subproto || !headers) {
        return -1;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return -1;
        }

#ifdef	_MOD_WEBSOCKET_SPEC_UP_TO_75_
        if ( buffer_is_equal_string(header->key,
                                    CONST_STR_LEN(MOD_WEBSOCKET_WEBSOCKET_PROTOCOL_STR)) ) {
            return buffer_copy_string_buffer(subproto, header->value);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_UP_TO_75_ */

#ifdef	_MOD_WEBSOCKET_SPEC_76_
        if ( buffer_is_equal_string(header->key,
                                    CONST_STR_LEN(MOD_WEBSOCKET_SEC_WEBSOCKET_PROTOCOL_STR)) ) {
            return buffer_copy_string_buffer(subproto, header->value);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

    }
    return 0;
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
        if (buffer_is_equal(da_subproto->key, subproto)) {
            ext = (data_array *)da_subproto;
            break;
        }
    }
    return ext;
}

int get_origin_field(buffer *origin, const array *headers) {
    size_t i;
    data_string *header = NULL;

    if (!origin || !headers) {
        return -1;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return -1;
        }
        if (buffer_is_equal_string(header->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_ORIGIN_STR))) {
            return buffer_copy_string_buffer(origin, header->value);
        }
    }
    return -1;
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
    size_t i;
    data_string *header = NULL;

    if (!host || !headers) {
        return -1;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return -1;
        }
        if (buffer_is_equal_string(header->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_HOST_STR))) {
            return buffer_copy_string_buffer(host, header->value);
        }
    }
    return -1;
}

#ifdef	_MOD_WEBSOCKET_SPEC_76_
int get_key1_field(buffer *key, const array *headers) {
    size_t i;
    data_string *header = NULL;

    if (!key || !headers) {
        return -1;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return -1;
        }
        if (buffer_is_equal_string(header->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_SEC_WEBSOCKET_KEY1_STR))) {
            return buffer_copy_string_buffer(key, header->value);
        }
    }
    return -1;
}

int get_key2_field(buffer *key, const array *headers) {
    size_t i;
    data_string *header = NULL;

    if (!key || !headers) {
        return -1;
    }
    for (i = headers->used; i > 0; i--) {
        header = (data_string *)headers->data[i - 1];
        if (!header->key->used || !header->value->used) {
            return -1;
        }
        if (buffer_is_equal_string(header->key,
                                   CONST_STR_LEN(MOD_WEBSOCKET_SEC_WEBSOCKET_KEY2_STR))) {
            return buffer_copy_string_buffer(key, header->value);
        }
    }
    return -1;
}

int get_key3_field(buffer *key, const handler_ctx *hctx) {
    const char *body = NULL;
    int ret;

    if (!key || !hctx) {
        return -1;
    }
    if (hctx->con->read_queue->first != hctx->con->read_queue->last) {
        return -1; /* XXX: key3 is separated */
    }
    body = &hctx->con->read_queue->first->mem->ptr[hctx->con->read_queue->first->offset];
    ret = buffer_copy_string_len(key, body, MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN);
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
    return buffer_copy_string_len(hctx->req.md5sum, (char *)final, MD5SUM_STRLEN);

 err_out:
    buffer_free(key1);
    buffer_free(key2);
    buffer_free(key3);
    return -1;
#undef	MD5SUM_STRLEN
}
#endif /* _MOD_WEBSOCKET_SPEC_76_ */

int create_handshake_response(handler_ctx *hctx) {
    size_t i;
    struct {
        const char *b;
    } const_hdrs[] = {
        { "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" },
        { "Upgrade: WebSocket\r\n" },
        { "Connection: Upgrade\r\n" },
    };
    buffer *resp = NULL;

    if (!hctx) {
        return -1;
    }
    resp = chunkqueue_get_append_buffer(hctx->write_queue);

    for (i = 0; i < (sizeof(const_hdrs) / sizeof(const_hdrs[0])); i++) {
        buffer_append_string(resp, const_hdrs[i].b);
    }
#ifdef	_MOD_WEBSOCKET_SPEC_UP_TO_75_
    buffer_append_string(resp, MOD_WEBSOCKET_WEBSOCKET_ORIGIN_STR);
    buffer_append_string(resp, ": ");
    buffer_append_string_buffer(resp, hctx->req.origin);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);

    if (!buffer_is_empty(hctx->req.subproto)) {
        buffer_append_string(resp, MOD_WEBSOCKET_WEBSOCKET_PROTOCOL_STR);
        buffer_append_string(resp, ": ");
        buffer_append_string_buffer(resp, hctx->req.subproto);
        buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
    }
    buffer_append_string(resp, MOD_WEBSOCKET_WEBSOCKET_LOCATION_STR);
    buffer_append_string(resp, ": ");
#endif	/* _MOD_WEBSOCKET_SPEC_UP_TO_75_ */

#ifdef	_MOD_WEBSOCKET_SPEC_76_
    buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_ORIGIN_STR);
    buffer_append_string(resp, ": ");
    buffer_append_string_buffer(resp, hctx->req.origin);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);

    if (!buffer_is_empty(hctx->req.subproto)) {
        buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_PROTOCOL_STR);
        buffer_append_string(resp, ": ");
        buffer_append_string_buffer(resp, hctx->req.subproto);
        buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
    }
    buffer_append_string(resp, MOD_WEBSOCKET_SEC_WEBSOCKET_LOCATION_STR);
    buffer_append_string(resp, ": ");
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

#ifdef	USE_OPENSSL
        buffer_append_string(resp, MOD_WEBSOCKET_SCHEME_WSS);
#else	/* SSL is not available */
        return -1;
#endif	/* USE_OPENSSL */

    } else {
        buffer_append_string(resp, MOD_WEBSOCKET_SCHEME_WS);
    }
    buffer_append_string_buffer(resp, hctx->req.host);
    buffer_append_string_buffer(resp, hctx->con->uri.path);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);
    buffer_append_string(resp, MOD_WEBSOCKET_CRLF_STR);

#ifdef	_MOD_WEBSOCKET_SPEC_76_
    buffer_append_string_buffer(resp, hctx->req.md5sum);
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

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
        /* ok, check request */
        if (!check_const_headers(con->request.headers)) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found some mandatory headers");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (0 != get_subproto_field(hctx->req.subproto,
                                    con->request.headers)) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "recv invalid request");
            }
            con->http_status = MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if ( (hctx->ext = get_subproto_extension(hctx->ext->value,
                                                 hctx->req.subproto)) == NULL ) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "not found specified sub protocol:",
                                hctx->req.subproto->ptr);
            }
            con->http_status = MOD_WEBSOCKET_NOT_FOUND;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (0 != get_origin_field(hctx->req.origin, con->request.headers)) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found origin header");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        origins = (data_array *)array_get_element(hctx->ext->value, MOD_WEBSOCKET_CONFIG_ORIGINS);
        if (origins) {
            if (!is_allowed_origin(origins->value, hctx->req.origin)) {
                if (p->conf.debug) {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                                    "not allowed origin:", hctx->req.origin->ptr);
                }
                con->http_status = MOD_WEBSOCKET_FORBIDDEN;
                con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
        }
        if (0 != get_host_field(hctx->req.host, con->request.headers)) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "not found host headers");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }

#ifdef	_MOD_WEBSOCKET_SPEC_76_
        if (create_MD5_sum(hctx) < 0) {
            if (p->conf.debug) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "failed to create MD5 sum for response");
            }
            con->http_status = MOD_WEBSOCKET_BAD_REQUEST;
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
#endif	/* _MOD_WEBSOCKET_SPEC_76_ */

        /* ok, next connect to server */
        switch (tcp_server_connect(srv, hctx)) {
        case 0: /* connected */
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
            break;
        case 1: /* connecting */
            hctx->state = MOD_WEBSOCKET_STATE_CONNECTING;
            fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
            return HANDLER_WAIT_FOR_EVENT;
            break;
        default: /* could not connect */
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "connect - failed: fd =", hctx->fd);
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
        if (!hctx->send_response) {
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
            ret = srv->network_backend_write(srv, con, hctx->con->fd, hctx->write_queue);
            if (0 <= ret) {
                chunkqueue_remove_finished_chunks(hctx->write_queue);
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
            hctx->send_response = MOD_WEBSOCKET_TRUE;
            return HANDLER_WAIT_FOR_EVENT;
        } else {
            if (chunkqueue_is_empty(hctx->write_queue)) {
                hctx->state = MOD_WEBSOCKET_STATE_CONNECTED;
                chunkqueue_reset(hctx->con->read_queue);
                return HANDLER_WAIT_FOR_EVENT;
            } else {
                ret = srv->network_backend_write(srv, con, hctx->con->fd, hctx->write_queue);
                if (0 <= ret) {
                    chunkqueue_remove_finished_chunks(hctx->write_queue);
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
            ret = srv->network_backend_write(srv, con, hctx->fd, con->read_queue);
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
            ret = srv->network_backend_write(srv, con, hctx->con->fd, hctx->write_queue);
            if (0 <= ret) {
                chunkqueue_remove_finished_chunks(hctx->write_queue);
            } else {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "write error(client):", strerror(errno));
                break;
            }
        }
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
        if (!chunkqueue_is_empty(con->read_queue)) {
            fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
        } else {
            fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
        }
        if (!chunkqueue_is_empty(hctx->write_queue)) {
            fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_OUT);
        } else {
            fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
        }
        return HANDLER_WAIT_FOR_EVENT;
        break;
    }
    chunkqueue_reset(hctx->write_queue);
    chunkqueue_reset(hctx->con->read_queue);
    connection_set_state(srv, con, CON_STATE_CLOSE);
    fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
    fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
    tcp_server_disconnect(srv, hctx);
    return HANDLER_FINISHED;
}

int websocket_handle_frame(handler_ctx *hctx) {
    chunk *c = NULL;
    buffer *readbuf = NULL;
    char *preadbuf = NULL, *first_byte = NULL, *last_byte = NULL;
    char *writebuf = NULL;
    size_t len = 0;

    if (!hctx->con || !hctx->con->read_queue) {
        return -1;
    }
    /* serialize data */
    for (c = hctx->con->read_queue->first; c; c = c->next) {
        if (NULL == readbuf) {
            readbuf = buffer_init_buffer(c->mem);
        } else {
            buffer_append_memory(readbuf, c->mem->ptr, c->mem->used);
        }
    }
    chunkqueue_reset(hctx->con->read_queue);
    if (!readbuf || !readbuf->used) {
        return 0;
    }
    preadbuf = readbuf->ptr;
    /* padded '\0' by buffer, so last_byte at c->mem->used - 2 */
    last_byte = readbuf->ptr + readbuf->used - 2;

    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT) {
        if (0x00 == *preadbuf) {
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_UTF8;
            if (preadbuf == last_byte) {
                buffer_free(readbuf);
                return 0;
            }
            preadbuf++;
        } else if (0xff == (unsigned char)(*preadbuf)) {
            hctx->frame.siz = 0;
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH;
            if (preadbuf == last_byte) {
                buffer_free(readbuf);
                return 0;
            }
        } else {
            buffer_free(readbuf);
            return -1;
        }
    }
    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH) {
        if (0x00 == *(preadbuf + 1)) { /* closing frame */
            buffer_free(readbuf);
            return -1;
        }
        do {
            preadbuf++;
            hctx->frame.siz = (hctx->frame.siz) * 128 + (*preadbuf & 0x7f);
            /* limits frame length under UINT32_MAX */
            if (hctx->frame.siz > UINT32_MAX) {
                buffer_free(readbuf);
                return -1;
            }
            if (preadbuf == last_byte) {
                break;
            }
        } while (*preadbuf & 0x80);
        if (preadbuf == last_byte) {
            buffer_free(readbuf);
            return 0;
        } else {
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_BINARY;
        }
    }
    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_READ_UTF8) {
        first_byte = preadbuf;
        for (;preadbuf != last_byte; preadbuf++) {
            if (0xff == (unsigned char)(*preadbuf)) {
                break;
            }
        }
        if (0xff == (unsigned char)(*preadbuf)) {
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        }
        len = (size_t)(preadbuf - first_byte);
        if (!len) {
            buffer_free(readbuf);
            return 0;
        }
        writebuf = (char *)malloc(len + 1);
        if (!writebuf) {
            buffer_free(readbuf);
            return -1;
        }
        if (encode_to(hctx->cdc, writebuf, &len, first_byte, len) < 0) {
            buffer_free(readbuf);
            free(writebuf);
            writebuf = NULL;
            return -1;
        }
        len = strlen(writebuf);
        chunkqueue_append_mem(hctx->con->read_queue, writebuf, len + 1);
        buffer_free(readbuf);
        free(writebuf);
        writebuf = NULL;
        return 0;
    }
    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_READ_BINARY) {
        len = (size_t)(last_byte - preadbuf);
        hctx->frame.siz -= len;
        if (hctx->frame.siz <= 0) {
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
        }
        chunkqueue_append_mem(hctx->con->read_queue, preadbuf, len + 1);
        buffer_free(readbuf);
        return 0;
    }
    /* never reach */
    return -1;
}

void websocket_send_closing_frame(server *srv, handler_ctx *hctx) {
    buffer *buf;
    const unsigned char closing_frame[2] = { 0xff, 0x00 };

    buf = chunkqueue_get_append_buffer(hctx->write_queue);
    /* XXX:BUG? in buffer.c */
    buffer_append_memory(buf, (const char *)closing_frame, sizeof(closing_frame) + 1);
    srv->network_backend_write(srv, hctx->con, hctx->con->fd, hctx->write_queue);
    chunkqueue_remove_finished_chunks(hctx->write_queue);
    return;
}

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

handler_t websocket_handle_fdevent(void *s, void *ctx, int revents) {
    server *srv = (server *)s;
    handler_ctx *hctx = (handler_ctx *)ctx;
    int b;
    ssize_t r;
    buffer *buf = NULL;
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;

#define	WEBSOCKET_BUFSIZ	(1024)
    char readbuf[WEBSOCKET_BUFSIZ];
    char writebuf[WEBSOCKET_BUFSIZ];
    size_t wbuflen;

    if (revents & FDEVENT_NVAL) {
        if (hctx->pd->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "sdsd",
                            "fd is not open(NVAL): fd(srv) =", hctx->fd,
                            "fd(browser) =", hctx->con->fd);
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
                wbuflen = WEBSOCKET_BUFSIZ;
#undef	WEBSOCKET_BUFSIZ
                if (0 <= encode_to(hctx->cdc, writebuf, &wbuflen,
                                   readbuf, (size_t)r)) {
                    buf = chunkqueue_get_append_buffer(hctx->write_queue);
                    buffer_append_memory(buf, (const char *)&head, 1);
                    buffer_append_memory(buf, writebuf, strlen(writebuf));
                    /* XXX:BUG? in buffer.c */
                    buffer_append_memory(buf, (const char *)&tail, 2);
                } else {
                    log_error_write(srv, __FILE__, __LINE__, "sd",
                                    "iconv failed: fd =", hctx->fd);
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
