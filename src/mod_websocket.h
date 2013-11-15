/*
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

#ifndef	_MOD_WEBSOCKET_H_
#define	_MOD_WEBSOCKET_H_

#include "config.h"

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif /* HAVE_STDINT_H */

#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "base.h"
#include "plugin.h"
#include "log.h"

#define	MOD_WEBSOCKET_CONFIG_SERVER		"websocket.server"
#define	MOD_WEBSOCKET_CONFIG_PING_INTERVAL	"websocket.ping_interval"
#define	MOD_WEBSOCKET_CONFIG_TIMEOUT		"websocket.timeout"
#define	MOD_WEBSOCKET_CONFIG_DEBUG		"websocket.debug"

#define	MOD_WEBSOCKET_LOG_NONE	(0)
#define	MOD_WEBSOCKET_LOG_ERR	(1)
#define	MOD_WEBSOCKET_LOG_WARN	(2)
#define	MOD_WEBSOCKET_LOG_INFO	(3)
#define	MOD_WEBSOCKET_LOG_DEBUG	(4)

#define DEBUG_LOG(level, format, ...)                                   \
    if (hctx->pd->conf.debug >= level) {                                \
        log_error_write(hctx->srv, __FILE__, __LINE__, format, __VA_ARGS__); \
    }

#define	MOD_WEBSOCKET_TRUE			(1)
#define	MOD_WEBSOCKET_FALSE			(0)

typedef unsigned char mod_websocket_bool_t;

#define	MOD_WEBSOCKET_ERRNO_MAP(GEN)    \
    GEN(OK, 200)                        \
    GEN(BAD_REQUEST, 400)               \
    GEN(FORBIDDEN, 403)                 \
    GEN(NOT_FOUND, 404)                 \
    GEN(PRECONDITION_FAILED, 412)       \
    GEN(INTERNAL_SERVER_ERROR, 500)     \
    GEN(SERVICE_UNAVAILABLE, 503)

#define	MOD_WEBSOCKET_ERRNO_GEN(ident, num) MOD_WEBSOCKET_##ident = num,

typedef enum {
    MOD_WEBSOCKET_ERRNO_MAP(MOD_WEBSOCKET_ERRNO_GEN)
} mod_websocket_errno_t;

typedef struct {
    array *exts;
    unsigned int timeout;
    unsigned int debug;

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    unsigned int ping_interval;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef enum {
    MOD_WEBSOCKET_TCP_PROXY,
    MOD_WEBSOCKET_WEBSOCKET_PROXY,
} mod_websocket_mode_t;

typedef enum {
    MOD_WEBSOCKET_STATE_INIT,
    MOD_WEBSOCKET_STATE_CONNECTED,
} mod_websocket_state_t;

typedef struct {
    buffer *host;
    buffer *origin;
    int version;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer *key1;
    buffer *key2;
    buffer *key3;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    buffer *key;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_websocket_handshake_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_STATE_INIT,

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_MASK,
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD,
} mod_websocket_frame_state_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_TYPE_TEXT,
    MOD_WEBSOCKET_FRAME_TYPE_BIN,
    MOD_WEBSOCKET_FRAME_TYPE_CLOSE,

#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
    MOD_WEBSOCKET_FRAME_TYPE_PING,
    MOD_WEBSOCKET_FRAME_TYPE_PONG,
#endif  /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_websocket_frame_type_t;

typedef struct {
    uint64_t siz;

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    int siz_cnt;
# define	MOD_WEBSOCKET_MASK_CNT	(4)
    unsigned char mask[MOD_WEBSOCKET_MASK_CNT];
    int mask_cnt;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_websocket_frame_control_t;

typedef struct {
    mod_websocket_frame_state_t state;
    mod_websocket_frame_control_t ctl;
    mod_websocket_frame_type_t type, type_before;
    buffer *payload;
} mod_websocket_frame_t;

typedef struct {
    mod_websocket_mode_t mode;
    mod_websocket_state_t state;
    mod_websocket_handshake_t handshake;
    mod_websocket_frame_t frame;

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
    time_t ping_ts;
    unsigned int timeout_cnt;
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    /* fd and fd_idx to backend */
    int fd, fd_idx;

    /* mbuf for server */
    chunkqueue  *tosrv;		/* chunkqueue to server */

    /* ref */
    server      *srv;		/* server */
    connection  *con;		/* connection */
    data_array  *ext;		/* extention */
    plugin_data *pd;		/* config */
    chunkqueue  *fromcli;	/* chunkqueue from client */
    chunkqueue  *tocli;		/* chunkqueue to client */
} handler_ctx;

#ifdef  __cplusplus
extern "C" {
#endif

    int mod_websocket_backend_connect(const char *, const char *);
    void mod_websocket_backend_disconnect(int);

    mod_websocket_errno_t mod_websocket_handshake_check_request(handler_ctx *);
    mod_websocket_errno_t mod_websocket_handshake_create_response(handler_ctx *);
    mod_websocket_errno_t mod_websocket_handshake_forward_request(handler_ctx *);

    int mod_websocket_frame_send(handler_ctx *, mod_websocket_frame_type_t, char *, size_t);
    int mod_websocket_frame_recv(handler_ctx *);

#ifdef  __cplusplus
}
#endif

#endif /* _MOD_WEBSOCKET_H_ */
