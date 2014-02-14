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

#ifndef _MOD_WEBSOCKET_CONFIG_H_
#define _MOD_WEBSOCKET_CONFIG_H_

// a key of environment var
#define	MOD_WEBSOCKET_CONFIG_PATH	"MOD_WEBSOCKET_CONFIG_PATH"

typedef enum {
    MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP,
    MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET,
} mod_websocket_backend_protocol_t;

typedef struct _mod_websocket_origin_t {
    char *origin;
    struct _mod_websocket_origin_t *next;
} mod_websocket_origin_t;

typedef struct _mod_websocket_backend_t {
    char *host;
    int port;
    mod_websocket_backend_protocol_t proto;
    char *subproto;
    int binary;				/* 1: true, 0: false */
    mod_websocket_origin_t *origins;	/* null if not set */
} mod_websocket_backend_t;

typedef struct _mod_websocket_resource_t {
    char *key;
    mod_websocket_backend_t *backend;
    struct _mod_websocket_resource_t *next;
} mod_websocket_resource_t;

typedef struct {
    mod_websocket_resource_t *resources;
    int ping_interval;
    int timeout;
    int debug;
} mod_websocket_config_t;

#ifdef  __cplusplus
extern "C" {
#endif

    mod_websocket_config_t *mod_websocket_config_parse(const char *);
    void mod_websocket_config_free(mod_websocket_config_t *);
    void mod_websocket_config_print(mod_websocket_config_t *);

#ifdef  __cplusplus
}
#endif

#endif /* _MOD_WEBSOCKET_CONFIG_H_ */
