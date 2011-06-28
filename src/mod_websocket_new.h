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

#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "base.h"
#include "plugin.h"
#include "log.h"

#include "mod_websocket_types.h"

#define	MOD_WEBSOCKET_CONFIG_SERVER	"websocket.server"
#define	MOD_WEBSOCKET_CONFIG_DEBUG	"websocket.debug"
#define	MOD_WEBSOCKET_CONFIG_HOST	"host"
#define	MOD_WEBSOCKET_CONFIG_PORT	"port"
#define	MOD_WEBSOCKET_CONFIG_SUBPROTO	"subproto"
#define	MOD_WEBSOCKET_CONFIG_ORIGINS	"origins"
#define	MOD_WEBSOCKET_CONFIG_LOCALE	"locale"
#define	MOD_WEBSOCKET_CONFIG_TYPE	"type"

#define DEBUG_LOG(format, args...)\
    if (hctx->pd->conf.debug) {\
        log_error_write(hctx->srv, __FILE__, __LINE__, format, ## args); \
    }

typedef struct {
    array *exts;
    unsigned int debug;
} plugin_config;

typedef struct {
    PLUGIN_DATA;

    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef struct {
    buffer *host;
    buffer *origin;
    buffer *subproto;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    buffer *key1;
    buffer *key2;
    buffer *key3;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    buffer *key;
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

} mod_websocket_handshake_t;

typedef struct {
    mod_websocket_handshake_t handshake;

    server *srv;	/* server */
    connection *con;	/* connection */
    data_array *ext;	/* extention */
    plugin_data *pd;	/* config */

    chunkqueue *tocli;	/* chunkqueue to client */
} handler_ctx;

#endif /* _MOD_WEBSOCKET_H_ */
