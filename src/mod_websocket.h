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

#include <ctype.h>
#include <iconv.h>

#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "base.h"
#include "plugin.h"

#define	MOD_WEBSOCKET_CONFIG_SERVER						"websocket.server"
#define	MOD_WEBSOCKET_CONFIG_DEBUG						"websocket.debug"
#define	MOD_WEBSOCKET_CONFIG_HOST						"host"
#define	MOD_WEBSOCKET_CONFIG_PORT						"port"
#define	MOD_WEBSOCKET_CONFIG_SUBPROTO					"subproto"
#define	MOD_WEBSOCKET_CONFIG_ORIGINS					"origins"
#define	MOD_WEBSOCKET_CONFIG_LOCALE						"locale"
#define	MOD_WEBSOCKET_CONFIG_TYPE						"type"

#define	MOD_WEBSOCKET_UTF8_STR							"UTF-8"
#define	MOD_WEBSOCKET_BIN_STR							"BIN"

#define	MOD_WEBSOCKET_GET_STR							"GET"
#define	MOD_WEBSOCKET_HOST_STR							"Host"
#define	MOD_WEBSOCKET_CONNECTION_STR					"Connection"
#define	MOD_WEBSOCKET_UPGRADE_STR						"Upgrade"
#define	MOD_WEBSOCKET_CRLF_STR							"\r\n"

#define	MOD_WEBSOCKET_SEC_WEBSOCKET_PROTOCOL_STR		"Sec-WebSocket-Protocol"
#define	MOD_WEBSOCKET_SEC_WEBSOCKET_ORIGIN_STR			"Sec-WebSocket-Origin"

#define	MOD_WEBSOCKET_SCHEME_WS							"ws://"
#define	MOD_WEBSOCKET_SCHEME_WSS						"wss://"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# define	MOD_WEBSOCKET_WEBSOCKET_STR					"WebSocket"
# define	MOD_WEBSOCKET_ORIGIN_STR					"Origin"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_LOCATION_STR	"Sec-WebSocket-Location"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_KEY1_STR		"Sec-WebSocket-Key1"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_KEY2_STR		"Sec-WebSocket-Key2"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_KEY3_LEN		(8)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
# define	MOD_WEBSOCKET_WEBSOCKET_STR					"websocket"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_KEY_STR			"Sec-WebSocket-Key"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_VERSION_STR		"Sec-WebSocket-Version"
# define	MOD_WEBSOCKET_SEC_WEBSOCKET_ACCEPT_STR		"Sec-WebSocket-Accept"

# define	MOD_WEBSOCKET_GUID_STR	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# define	MOD_WEBSOCKET_MESSAGE_DIGEST_LEN			(20)

# define	MOD_WEBSOCKET_OPCODE_CONT					(0x00)
# define	MOD_WEBSOCKET_OPCODE_TEXT					(0x01)
# define	MOD_WEBSOCKET_OPCODE_BIN					(0x02)
# define	MOD_WEBSOCKET_OPCODE_CLOSE					(0x08)
# define	MOD_WEBSOCKET_OPCODE_PING					(0x09)
# define	MOD_WEBSOCKET_OPCODE_PONG					(0x0A)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

#define	MOD_WEBSOCKET_FRAME_TYPE_TEXT					(0x00)
#define	MOD_WEBSOCKET_FRAME_TYPE_BIN					(0x01)

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
# define	MOD_WEBSOCKET_FRAME_TYPE_PING				(0x02)
# define	MOD_WEBSOCKET_FRAME_TYPE_PONG				(0x03)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

#define	MOD_WEBSOCKET_TRUE								(1)
#define	MOD_WEBSOCKET_FALSE								(0)

typedef unsigned char mod_websocket_bool_t;

typedef enum {
    MOD_WEBSOCKET_OK					= 200,
    MOD_WEBSOCKET_BAD_REQUEST			= 400,
    MOD_WEBSOCKET_FORBIDDEN				= 403,
    MOD_WEBSOCKET_NOT_FOUND				= 404,
    MOD_WEBSOCKET_INTERNAL_SERVER_ERROR	= 500,
    MOD_WEBSOCKET_SERVICE_UNAVAILABLE	= 503,
} mod_websocket_response_code_t;

typedef enum {
    MOD_WEBSOCKET_STATE_INIT,
    MOD_WEBSOCKET_STATE_CONNECTING,
    MOD_WEBSOCKET_STATE_SEND_RESPONSE,
    MOD_WEBSOCKET_STATE_CONNECTED,
} mod_websocket_state_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_STATE_INIT,
    MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD,

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_MASK,
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

} mod_websocket_frame_state_t;

typedef struct {
    array *exts;
    unsigned int debug;
} plugin_config;

typedef struct {
    PLUGIN_DATA;

    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

/* storage of some header fields for handshake */
typedef struct _mod_websocket_handshake_t {
    mod_websocket_bool_t send;
    buffer *host;
    buffer *origin;
    buffer *subproto;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer *md5sum;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    buffer *accept;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

} mod_websocket_handshake_t;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
typedef struct _mod_websocket_control_t {
    mod_websocket_bool_t fin;
    unsigned char rsv;
    unsigned char opcode;
    mod_websocket_bool_t mask_flag;
    unsigned char mask[4];
    int mask_len;
    size_t siz;
} mod_websocket_control_t;
#endif /* _MOD_WEBSOCKET_SPEC_IETF_08_ */

typedef struct _mod_websocket_payload_t {
    int type;
    size_t siz;
    buffer *data;
} mod_websocket_payload_t;

typedef struct _mod_websocket_frame_t {
    mod_websocket_frame_state_t state;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    mod_websocket_control_t ctl;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    mod_websocket_payload_t payload;
} mod_websocket_frame_t;

typedef struct {
    mod_websocket_state_t state;
    mod_websocket_bool_t client_closed;
    mod_websocket_bool_t server_closed;
    mod_websocket_handshake_t handshake;
    mod_websocket_frame_t frame;

    iconv_t cds, cdc;					/* conversion descripter */
    int fd;								/* fd to the backend srv */
    int fde_ndx;						/* index into the fd-event buffer */

    buffer *inbuf;						/* from client */
    chunkqueue *outbuf;					/* to client */

    data_array *ext;					/* dump pointer */
    connection *con;					/* dump pointer */
    plugin_data *pd;					/* dump pointer */
} handler_ctx;

#endif /* _MOD_WEBSOCKET_H_ */

