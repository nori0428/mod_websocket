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

#ifndef	_MOD_WEBSOCKET_H_
#define	_MOD_WEBSOCKET_H_

#include <time.h>
#include <unicode/ucnv.h>

#include "config.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "base.h"
#include "plugin.h"
#include "log.h"

#define	MOD_WEBSOCKET_CONFIG_SERVER		"websocket.server"
#define	MOD_WEBSOCKET_CONFIG_DEBUG		"websocket.debug"
#define	MOD_WEBSOCKET_CONFIG_TIMEOUT		"websocket.timeout"
#define	MOD_WEBSOCKET_CONFIG_PING_INTERVAL	"websocket.ping_interval"

#define	MOD_WEBSOCKET_CONFIG_HOST		"host"
#define	MOD_WEBSOCKET_CONFIG_PORT		"port"
#define	MOD_WEBSOCKET_CONFIG_SUBPROTO		"subproto"
#define	MOD_WEBSOCKET_CONFIG_ORIGINS		"origins"

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
# define	MOD_WEBSOCKET_CONFIG_LOCALE	"locale"
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

#define	MOD_WEBSOCKET_CONFIG_TYPE		"type"

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
# define	MOD_WEBSOCKET_OPCODE_CONT	(0x00)
# define	MOD_WEBSOCKET_OPCODE_TEXT	(0x01)
# define	MOD_WEBSOCKET_OPCODE_BIN	(0x02)
# define	MOD_WEBSOCKET_OPCODE_CLOSE	(0x08)
# define	MOD_WEBSOCKET_OPCODE_PING	(0x09)
# define	MOD_WEBSOCKET_OPCODE_PONG	(0x0A)

# define	MOD_WEBSOCKET_FRAME_LEN16	(0x7E)
# define	MOD_WEBSOCKET_FRAME_LEN63	(0x7F)
# define	MOD_WEBSOCKET_FRAME_LEN16_CNT	(2)
# define	MOD_WEBSOCKET_FRAME_LEN63_CNT	(8)
# define	MOD_WEBSOCKET_MASK_CNT		(4)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

#define	MOD_WEBSOCKET_UTF8_STR			"UTF-8"
#define	MOD_WEBSOCKET_BIN_STR			"bin"
#define	MOD_WEBSOCKET_PING_STR			"ping"

typedef unsigned char mod_websocket_bool_t;

#define	MOD_WEBSOCKET_TRUE			(1)
#define	MOD_WEBSOCKET_FALSE			(0)
#define	MOD_WEBSOCKET_DEFAULT_TIMEOUT_SEC	(30)

#define DEBUG_LOG(format, args...)\
    if (hctx->pd->conf.debug) {\
        log_error_write(hctx->srv, __FILE__, __LINE__, format, ## args); \
    }

#if (LIGHTTPD_VERSION_ID >= (1 << 16 | 4 << 8 | 30))
# define	NETWORK_SSL_BACKEND_WRITE(a,b,c,d)\
    network_ssl_backend_write(a, b, c, d, MAX_WRITE_LIMIT)
# define	NETWORK_BACKEND_WRITE(a,b,c,d)\
    network_backend_write(a, b, c, d, MAX_WRITE_LIMIT)
#else
# define	NETWORK_SSL_BACKEND_WRITE(a,b,c,d)\
    network_ssl_backend_write(a, b, c, d)
# define	NETWORK_BACKEND_WRITE(a,b,c,d)\
    network_backend_write(a, b, c, d)
#endif

typedef enum {
    MOD_WEBSOCKET_NOT_WEBSOCKET		= -1,
    MOD_WEBSOCKET_OK			= 200,
    MOD_WEBSOCKET_BAD_REQUEST		= 400,
    MOD_WEBSOCKET_FORBIDDEN		= 403,
    MOD_WEBSOCKET_NOT_FOUND		= 404,
    MOD_WEBSOCKET_INTERNAL_SERVER_ERROR	= 500,
    MOD_WEBSOCKET_SERVICE_UNAVAILABLE	= 503,
} mod_websocket_errno_t;

typedef struct {
    array *exts;
    unsigned int debug;
    unsigned int timeout;

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    unsigned int ping;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef enum {
    MOD_WEBSOCKET_STATE_INIT,
    MOD_WEBSOCKET_STATE_SEND_RESPONSE,
    MOD_WEBSOCKET_STATE_CONNECTED,
} mod_websocket_state_t;

typedef struct {
    buffer *host;
    buffer *origin;
    buffer *subproto;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer *key1;
    buffer *key2;
    buffer *key3;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    buffer *key;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_websocket_handshake_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_STATE_INIT,

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_MASK,
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD,
} mod_websocket_frame_state_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_TYPE_TEXT,
    MOD_WEBSOCKET_FRAME_TYPE_CLOSE,

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    MOD_WEBSOCKET_FRAME_TYPE_BIN,
    MOD_WEBSOCKET_FRAME_TYPE_PING,
    MOD_WEBSOCKET_FRAME_TYPE_PONG,
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_websocket_frame_type_t;

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
typedef struct {
    unsigned char rsv;
    unsigned char opcode;
    mod_websocket_bool_t mask_flag;
    unsigned char mask[MOD_WEBSOCKET_MASK_CNT];
    int mask_cnt;
    size_t siz;
    size_t ex_siz;
    int ex_siz_cnt;
} mod_websocket_frame_control_t;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

typedef struct {

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    mod_websocket_frame_control_t ctl;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    mod_websocket_frame_state_t state;
    mod_websocket_frame_type_t type;
    buffer *payload;
} mod_websocket_frame_t;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
typedef struct {
    UConverter *cli;
    UConverter *srv;
} mod_websocket_conv_t;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

typedef struct {
    mod_websocket_state_t state;
    mod_websocket_handshake_t handshake;
    mod_websocket_frame_t frame;
    time_t last_access;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_t *cnv;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    time_t ping_ts;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ || _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    /* fd and fd_idx to backend */
    int fd, fd_idx;

    /* ref */
    server      *srv;	/* server */
    connection  *con;	/* connection */
    data_array  *ext;	/* extention */
    plugin_data *pd;	/* config */

    chunkqueue  *tosrv;	/* chunkqueue to server */
    chunkqueue  *tocli;	/* chunkqueue to client */
} handler_ctx;

/* prototypes */
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
mod_websocket_conv_t *mod_websocket_conv_init(const char *);
mod_websocket_bool_t mod_websocket_conv_isUTF8(const char *, size_t);
int mod_websocket_conv_to_client(mod_websocket_conv_t *,
                                 char *, size_t *, const char *, size_t);
int mod_websocket_conv_to_server(mod_websocket_conv_t *,
                                 char *, size_t *, const char *, size_t);
void mod_websocket_conv_final(mod_websocket_conv_t *);
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

mod_websocket_errno_t mod_websocket_handshake_check_request(handler_ctx *);
mod_websocket_errno_t mod_websocket_handshake_create_response(handler_ctx *);

int mod_websocket_tcp_server_connect(const char *, const char *);
void mod_websocket_tcp_server_disconnect(int);

int mod_websocket_frame_send(handler_ctx *, mod_websocket_frame_type_t,
                             char *, size_t);
int mod_websocket_frame_recv(handler_ctx *);

#endif /* _MOD_WEBSOCKET_H_ */
