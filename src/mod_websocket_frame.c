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
    const unsigned char cfrm[2] = { 0xff, 0x00 };
    int ret = -1;
    buffer *b = NULL;
    char *enc = NULL;
    size_t encsiz = siz * 3; // XXX

    if (!hctx || (!payload && type != MOD_WEBSOCKET_FRAME_TYPE_CLOSE)) {
        return -1;
    }
    if (!siz && type != MOD_WEBSOCKET_FRAME_TYPE_CLOSE) {
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
    buffer *frame = NULL;
    buffer *payload = NULL, *cb = NULL;
    int ret;
    char *enc = NULL;
    size_t i, encsiz;

    if (!hctx || !hctx->con || !hctx->con->read_queue) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->con->read_queue)) {
        return 0;
    }
    /* serialize data */
    for (c = hctx->con->read_queue->first; c; c = c->next) {
        if (NULL == frame) {
            frame = buffer_init();
            if (!frame) {
                DEBUG_LOG("s", "no memory");
                chunkqueue_reset(hctx->con->read_queue);
                return -1;
            }
        }
        ret = buffer_append_memory(frame, c->mem->ptr, c->mem->used);
        if (ret != 0) {
            DEBUG_LOG("s", "no memory");
            buffer_free(frame);
            chunkqueue_reset(hctx->con->read_queue);
            return -1;
        }
    }
    chunkqueue_reset(hctx->con->read_queue);

    /* get payload from frame */
    payload = hctx->frame.payload.data;
    for (i = 0; i < frame->used; i++) {
        if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT) {
            if (0x00 == frame->ptr[i]) {
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
            } else {
                DEBUG_LOG("s", "recv closing or invalid frame");
                buffer_free(frame);
                buffer_reset(payload);
                return -1;
            }
        } else {
            if (-1 == frame->ptr[i]) { // XXX: equal to tail flag(0xff)
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                encsiz = (payload->used) * 3; // XXX
                enc = (char *)malloc(sizeof(char) * encsiz + 1);
                if (!enc) {
                    DEBUG_LOG("s", "no memory");
                    buffer_free(frame);
                    buffer_reset(payload);
                    return -1;
                }
                memset(enc, 0, encsiz);
                ret = mod_websocket_conv_to_server(hctx->cnv,
                                                   enc, &encsiz,
                                                   payload->ptr,
                                                   payload->used);
                buffer_reset(payload);
                if (ret != 0) {
                    DEBUG_LOG("s", "fail to convert chars");
                    buffer_free(frame);
                    free(enc);
                    return -1;
                }
                cb = chunkqueue_get_append_buffer(hctx->tosrv);
                if (!cb) {
                    DEBUG_LOG("s", "no memory");
                    buffer_free(frame);
                    free(enc);
                    return -1;
                }
                ret = buffer_append_memory(cb, enc, encsiz);
                if (ret != 0) {
                    DEBUG_LOG("s", "no memory");
                    buffer_free(frame);
                    free(enc);
                    return -1;
                }
                free(enc);
            } else {
                ret = buffer_append_memory(payload, &frame->ptr[i], 1);
                if (ret != 0) {
                    DEBUG_LOG("s", "no memory");
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    buffer_free(frame);
                    buffer_reset(payload);
                    return -1;
                }
            }
        }
    }
    buffer_free(frame);
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

/* EOF */
