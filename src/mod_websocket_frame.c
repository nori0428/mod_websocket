/**
 * $Id$
 * a part of mod_websocket
 */

#include <string.h>

#include "mod_websocket_new.h"
#include "mod_websocket_conv.h"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
int
mod_websocket_frame_send(handler_ctx *hctx,
                         mod_websocket_frame_type_t type,
                         char *payload, size_t siz) {
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    const unsigned char cfrm[3] = { 0xff, 0x00, 0x00 };
    int ret = -1;
    buffer *b = NULL;
    char *enc = NULL;
    size_t encsiz = siz * 3; // XXX

    if (!hctx || !payload) {
        return -1;
    }
    if (!siz) {
        return 0;
    }
    b = chunkqueue_get_append_buffer(hctx->tocli);
    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        ret = buffer_append_memory(b, (const char *)&head, 1);
        if (ret != 0) {
            DEBUG_LOG("s", "no memory");
            break;
        }
        enc = (char *)malloc(sizeof(char) * encsiz + 1);
        if (!enc) {
            DEBUG_LOG("s", "no memory");
            ret = -1;
            break;
        }
        memset(enc, 0, encsiz);
        ret = mod_websocket_conv_to_client(hctx->cnv,
                                           enc, &encsiz, payload, siz);
        if (ret != 0) {
            DEBUG_LOG("s", "failed to convert char encodings");
            break;
        }
        ret = buffer_append_memory(b, enc, encsiz);
        if (ret != 0) {
            DEBUG_LOG("s", "no memory");
            break;
        }
        ret = buffer_append_memory(b, (const char *)&tail, 1);
        if (ret != 0) {
            DEBUG_LOG("s", "no memory");
        }
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
        ret = buffer_append_memory(b, (const char *)cfrm, sizeof(cfrm));
        if (ret != 0) {
            DEBUG_LOG("s", "no memory");
        }
        break;
    default:
        ret = -1;
        DEBUG_LOG("s", "not support type");
        break;
    }
    if (enc) {
        free(enc);
        enc = NULL;
    }
    if (ret != 0) {
        chunkqueue_reset(hctx->tocli);
    }
    return ret;
}

int
mod_websocket_frame_recv(handler_ctx *hctx) {
    chunk *c = NULL;
    buffer *fragment = NULL, *payload = NULL;
    char *p = NULL;
    int ret;
    char *enc = NULL;
    size_t encsiz;
    size_t i;

    if (!hctx || !hctx->con || !hctx->con->read_queue) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->con->read_queue)) {
        return 0;
    }
    /* serialize data */
    for (c = hctx->con->read_queue->first; c; c = c->next) {
        if (NULL == fragment) {
            fragment = buffer_init();
            if (!fragment) {
                DEBUG_LOG("s", "no memory");
                chunkqueue_reset(hctx->con->read_queue);
                return -1;
            }
            ret = buffer_copy_memory(fragment, c->mem->ptr, c->mem->used);
            if (ret != 0) {
                DEBUG_LOG("s", "no memory");
                buffer_free(fragment);
                chunkqueue_reset(hctx->con->read_queue);
                return -1;
            }
         } else {
            ret = buffer_append_memory(fragment, c->mem->ptr, c->mem->used);
            if (ret != 0) {
                DEBUG_LOG("s", "no memory");
                buffer_free(fragment);
                chunkqueue_reset(hctx->con->read_queue);
                return -1;
            }
        }
    }
    chunkqueue_reset(hctx->con->read_queue);
    p = fragment->ptr;
    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT) {
        if (0x00 == *p) {
            payload = buffer_init();
            if (!payload) {
                DEBUG_LOG("s", "no memory");
                buffer_free(fragment);
                return -1;
            }
            p++;
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
        } else {
            DEBUG_LOG("s", "recv closing or invalid frame");
            buffer_free(fragment);
            return -1;
        }
    }
    payload = buffer_init();
    if (!payload) {
        DEBUG_LOG("s", "no memory");
        buffer_free(fragment);
        return -1;
    }
    ret = buffer_copy_memory(payload, p,
                             fragment->used - (p - fragment->ptr));
    buffer_free(fragment);
    if (ret != 0) {
        DEBUG_LOG("s", "no memory");
        buffer_free(payload);
        return -1;
    }
    /* check for abnormal frame */
    /* like "0x00, ..., 0xff, 0x02" etc. */
    for (i = 0; i < payload->used; i++) {
        if (payload->ptr[i] == -1) { // XXX: equal to tail flag(0xff)
            payload->ptr[i] = '\0';
            hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
            break;
        }
    }
    if (buffer_is_empty(hctx->frame.payload.data)) {
        ret = buffer_copy_memory(hctx->frame.payload.data, payload->ptr, i);
    } else {
        ret = buffer_append_memory(hctx->frame.payload.data, payload->ptr, i);
    }
    buffer_free(payload);
    if (ret != 0) {
        DEBUG_LOG("s", "no memory");
        return -1;
    }
    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT) {
        encsiz = (hctx->frame.payload.data->used) * 3; // XXX
        enc = (char *)malloc(sizeof(char) * encsiz + 1);
        if (!enc) {
            DEBUG_LOG("s", "no memory");
            buffer_reset(hctx->frame.payload.data);
            return -1;
        }
        memset(enc, 0, encsiz);
        ret = mod_websocket_conv_to_server(hctx->cnv,
                                           enc, &encsiz,
                                           hctx->frame.payload.data->ptr,
                                           hctx->frame.payload.data->used);
        buffer_reset(hctx->frame.payload.data);
        if (ret != 0) {
            DEBUG_LOG("s", "fail to convert chars");
            free(enc);
            return -1;
        }
        chunkqueue_append_mem(hctx->tosrv, enc, encsiz + 1);
    }
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

/* EOF */
