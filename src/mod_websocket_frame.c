/**
 * $Id$
 * a part of mod_websocket
 */

#include <string.h>
#include <stdint.h>

#include "mod_websocket.h"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# include "base64.h"

int
mod_websocket_frame_send_ietf_00(handler_ctx *hctx,
                                 mod_websocket_frame_type_t type,
                                 char *payload, size_t siz) {
    const char additional = 0x00;
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    int ret = -1;
    buffer *b = NULL;
    char *enc = NULL;
    size_t encsiz = 0;

    if (!hctx ||
        (!payload && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                      type == MOD_WEBSOCKET_FRAME_TYPE_BIN))) {
        return -1;
    }
    if (siz == 0 && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                     type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
        return 0;
    }
    b = chunkqueue_get_append_buffer(hctx->tocli);
    if (!b) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        return -1;
    }
    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        ret = buffer_append_memory(b, (const char *)&head, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        ret = mod_websocket_conv_to_client(hctx->cnv,
                                           &enc, &encsiz, payload, siz);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                      "s", "failed to convert char encodings");
            break;
        }
        ret = buffer_append_memory(b, enc, encsiz);
        free(enc);
        enc = NULL;
#else
        ret = buffer_append_memory(b, payload, siz);
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        ret = buffer_append_memory(b, (const char *)&tail, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        ret = buffer_append_memory(b, (const char *)&head, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "s", "convert binary data into base64 text data");
        ret = base64_encode((unsigned char **)&enc, &encsiz,
                            (unsigned char *)payload, siz);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        ret = buffer_append_memory(b, enc, encsiz);
        free(enc);
        enc = NULL;
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        ret = buffer_append_memory(b, (const char *)&tail, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
        ret = buffer_append_memory(b, (const char *)&tail, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        ret = buffer_append_memory(b, (const char *)&head, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            break;
        }
        break;
    default:
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "not support type");
        ret = -1;
        break;
    }
    if (ret != 0) {
        chunkqueue_reset(hctx->tocli);
        return -1;
    }
    /* lighty needs additional char to send */
    ret = buffer_append_memory(b, &additional, 1);
    if (ret != 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        chunkqueue_reset(hctx->tocli);
        return -1;
    }
    return 0;
}

int
mod_websocket_frame_recv_ietf_00(handler_ctx *hctx) {
    const char additional = 0x00;
    char *pff = NULL;
    chunk *c = NULL;
    buffer *frame = NULL, *payload = NULL, *b = NULL;
    int ret;
    size_t i;
    char *b64 = NULL;
    size_t b64siz = 0;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    char *enc = NULL;
    size_t encsiz = 0;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    if (!hctx || !hctx->fromcli) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->fromcli)) {
        return 0;
    }
    for (c = hctx->fromcli->first; c; c = c->next) {
        frame = c->mem;
        if (!frame) {
            continue;
        }
        payload = hctx->frame.payload;
        i = 0;
        while (i < frame->used - 1) {
            switch (hctx->frame.state) {
            case MOD_WEBSOCKET_FRAME_STATE_INIT:
                hctx->frame.ctl.siz = 0;
                if (0x00 == frame->ptr[i]) {
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    i++;
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                              "s", "recv closing or invalid frame");
                    chunkqueue_reset(hctx->tosrv);
                    chunkqueue_reset(hctx->fromcli);
                    buffer_reset(payload);
                    return -1;
                }
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
                pff = (char *)memchr(&frame->ptr[i], 0xff, frame->used - i - 1);
                if (pff == NULL) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "got continuous payload size:", frame->used - i - 1);
                    hctx->frame.ctl.siz += frame->used - i - 1;
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARNING,
                                  "sx", "frame size has beed exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    ret = buffer_append_memory(payload, &frame->ptr[i],
                                               frame->used - i - 1);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    i = frame->used - i - 1;
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "got final payload size:", (pff - &frame->ptr[i]));
                    hctx->frame.ctl.siz += (pff - &frame->ptr[i]);
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARNING,
                                  "sx", "frame size has beed exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    ret = buffer_append_memory(payload, &frame->ptr[i],
                                               pff - &frame->ptr[i]);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    i += (pff - &frame->ptr[i]);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                }
                i++;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                if (hctx->frame.state != MOD_WEBSOCKET_FRAME_STATE_INIT) {
                    break;
                }
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

                hctx->frame.ctl.siz = 0;
                if (payload->used > 0) {
                    b = chunkqueue_get_append_buffer(hctx->tosrv);
                    if (!b) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                    if (mod_websocket_conv_isUTF8(payload->ptr,
                                                  payload->used) !=
                        MOD_WEBSOCKET_TRUE) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "recv not UTF-8");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    ret = mod_websocket_conv_to_server(hctx->cnv,
                                                       &enc, &encsiz,
                                                       payload->ptr,
                                                       payload->used);
                    buffer_reset(payload);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                                  "s", "fail to convert chars");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_BIN) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                                  "s", "convert base64 text data into binary data");
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                                  "ss", "receive base64 text:", enc);
                        ret = base64_decode((unsigned char **)&b64, &b64siz, (unsigned char *)enc);
                        if (ret != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid base64 text");
                            chunkqueue_reset(hctx->tosrv);
                            chunkqueue_reset(hctx->fromcli);
                            return -1;
                        }
                        ret = buffer_append_memory(b, b64, b64siz);
                        free(enc);
                        free(b64);
                    } else {
                        ret = buffer_append_memory(b, enc, encsiz);
                        free(enc);
                    }
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
#else
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_BIN) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                                  "s", "convert base64 text data into binary data");
                        payload->ptr[payload->used] = '\0';
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                                  "ss", "receive base64 text:", payload->ptr);
                        ret = base64_decode((unsigned char **)&b64, &b64siz,
                                            (unsigned char *)payload->ptr);
                        if (ret != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid base64 text");
                            chunkqueue_reset(hctx->tosrv);
                            chunkqueue_reset(hctx->fromcli);
                            return -1;
                        }
                        ret = buffer_append_memory(b, b64, b64siz);
                        buffer_reset(payload);
                        free(b64);
                    } else {
                        ret = buffer_append_memory(b, payload->ptr, payload->used);
                        buffer_reset(payload);
                    }
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

                    /* lighty needs additional char to send */
                    ret = buffer_append_memory(b, &additional, 1);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
                }
                break;
            default: /* never reach */
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,"s", "BUG: unknown state");
                chunkqueue_reset(hctx->tosrv);
                chunkqueue_reset(hctx->fromcli);
                buffer_reset(payload);
                return -1;
            }
        }
    }
    chunkqueue_reset(hctx->fromcli);
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
int
mod_websocket_frame_send_rfc_6455(handler_ctx *hctx,
                                  mod_websocket_frame_type_t type,
                                  char *payload, size_t siz) {
    const char additional = 0x00;
    int ret = -1;
    char c, len[MOD_WEBSOCKET_FRAME_LEN63 + 1];
    buffer *b = NULL;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    char *enc = NULL;
    size_t encsiz = 0;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    if (!hctx || (!payload &&
                  (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                   type == MOD_WEBSOCKET_FRAME_TYPE_BIN))) {
        return -1;
    }
    b = chunkqueue_get_append_buffer(hctx->tocli);
    if (!b) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        return -1;
    }
    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_TEXT);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type: text");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_BIN);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type: binary");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PING:
        c = (char) (0x80 | MOD_WEBSOCKET_OPCODE_PING);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type: ping");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PONG:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_PONG);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type: pong");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
    default:
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type: close");
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_CLOSE);
        break;
    }
    ret = buffer_append_memory(b, &c, 1);
    if (ret != 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        buffer_reset(b);
        return -1;
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT && siz > 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                  "sx", "payload size (before convert):", siz);
        ret = mod_websocket_conv_to_client(hctx->cnv,
                                           &enc, &encsiz, payload, siz);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "fail to convert encoding");
            buffer_reset(b);
            return -1;
        }
        siz = encsiz;
    }
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "payload size:", siz);
    memset(len, 0, sizeof(len));
    if (siz < MOD_WEBSOCKET_FRAME_LEN16) {
        len[0] = siz;
        ret = buffer_append_memory(b, len, 1);
    } else if (siz <= UINT16_MAX) {
        len[0] = MOD_WEBSOCKET_FRAME_LEN16;
        len[1] = (siz >> 8) & 0xff;
        len[2] = siz & 0xff;
        ret = buffer_append_memory(b, len, MOD_WEBSOCKET_FRAME_LEN16_CNT + 1);
    } else {
        len[0] = MOD_WEBSOCKET_FRAME_LEN63;
        len[5] = (siz >> 24) & 0xff;
        len[6] = (siz >> 16) & 0xff;
        len[7] = (siz >> 8) & 0xff;
        len[8] = siz & 0xff;
        ret = buffer_append_memory(b, len, MOD_WEBSOCKET_FRAME_LEN63 + 1);
    }
    if (ret != 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        if (enc) {
            free(enc);
            enc = NULL;
        }
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

        buffer_reset(b);
        return -1;
    }
    if (siz == 0) {
        /* lighty needs additional char to send */
        ret = buffer_append_memory(b, &additional, 1);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            buffer_reset(b);
            return -1;
        }
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "frame size:", b->used - 1);
        return 0;
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
        ret = buffer_append_memory(b, enc, siz);
        free(enc);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            buffer_reset(b);
            return -1;
        }
    } else
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    {
        ret = buffer_append_memory(b, payload, siz);
        if (ret != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            buffer_reset(b);
            return -1;
        }
    }

    /* lighty needs additional char to send */
    ret = buffer_append_memory(b, &additional, 1);
    if (ret != 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        buffer_reset(b);
    }
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "frame size:", b->used - 1);
    return ret;
}

void
unmask_payload(handler_ctx *hctx) {
    size_t i;

    for (i = 0; i < hctx->frame.payload->used; i++) {
        hctx->frame.payload->ptr[i] =
            hctx->frame.payload->ptr[i] ^
            hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt];
        hctx->frame.ctl.mask_cnt = (hctx->frame.ctl.mask_cnt + 1) % 4;
    }
    return;
}

int
mod_websocket_frame_recv_rfc_6455(handler_ctx *hctx) {
    /* for debug log */
    const char *typestr[8] = {"text", "close", "binary", "ping", "pong"};
    char u64str[128];
    /* end for debug log */
    const char additional = 0x00;
    chunk *c = NULL;
    buffer *frame = NULL, *payload = NULL, *b = NULL;
    int ret;
    size_t i;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    char *enc = NULL;
    size_t encsiz = 0;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    if (!hctx || !hctx->fromcli) {
        return -1;
    }
    if (chunkqueue_is_empty(hctx->fromcli)) {
        return 0;
    }
    for (c = hctx->fromcli->first; c; c = c->next) {
        frame = c->mem;
        if (!frame) {
            continue;
        }
        payload = hctx->frame.payload;
        i = 0;
        while (i < frame->used - 1) {
            switch (hctx->frame.state) {
            case MOD_WEBSOCKET_FRAME_STATE_INIT:
                switch (frame->ptr[i] & 0x0f) {
                case MOD_WEBSOCKET_OPCODE_CONT:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "type: continue");
                    hctx->frame.type = hctx->frame.type_before;
                    break;
                case MOD_WEBSOCKET_OPCODE_TEXT:
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_BIN:
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_PING:
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PING;
                    break;
                case MOD_WEBSOCKET_OPCODE_PONG:
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
                    break;
                case MOD_WEBSOCKET_OPCODE_CLOSE:
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
                    chunkqueue_reset(hctx->fromcli);
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                              "ss", "type:", typestr[hctx->frame.type]);
                    return -1;
                    break;
                default:
                    chunkqueue_reset(hctx->fromcli);
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "type: invalid");
                    return -1;
                    break;
                }
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                          "ss", "type:", typestr[hctx->frame.type]);
                i++;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH:
                if ((frame->ptr[i] & 0x80) != 0x80) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                              "s", "payload was not masked");
                    chunkqueue_reset(hctx->fromcli);
                    return -1;
                }
                hctx->frame.ctl.mask_cnt = 0;
                hctx->frame.ctl.siz = (uint64_t)(frame->ptr[i] & 0x7f);
                if (hctx->frame.ctl.siz == 0) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "specified payload size:",
                              hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                } else if (hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN16) {
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.ctl.siz_cnt = MOD_WEBSOCKET_FRAME_LEN16_CNT;
                    hctx->frame.state =
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
                } else if (hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN63) {
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.ctl.siz_cnt = MOD_WEBSOCKET_FRAME_LEN63_CNT;
                    hctx->frame.state =
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "specified payload size:",
                              hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH:
                hctx->frame.ctl.siz =
                    (hctx->frame.ctl.siz << 8) + (frame->ptr[i] & 0xff);
                hctx->frame.ctl.siz_cnt--;
                if (hctx->frame.ctl.siz_cnt <= 0) {

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                    if ((hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                         hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING) &&
                        hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
#else
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING &&
                        hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARNING,
                                  "sx", "can't handle over",
                                  MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
                    if (hctx->pd->conf.debug > MOD_WEBSOCKET_LOG_DEBUG) {
                        memset(u64str, 0, sizeof(u64str));
                        snprintf(u64str, sizeof(u64str) - 1,
                                 "specified payload size: 0x%llx",
                                 (long long unsigned int)hctx->frame.ctl.siz &
                                 UINT64_MAX);
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", u64str);
                    }
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_MASK:
                hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt] = frame->ptr[i];
                hctx->frame.ctl.mask_cnt++;
                if (hctx->frame.ctl.mask_cnt >= MOD_WEBSOCKET_MASK_CNT) {
                    hctx->frame.ctl.mask_cnt = 0;
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING &&
                        hctx->frame.ctl.siz == 0) {
                        mod_websocket_frame_send(hctx,
                                                 MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                                 NULL, 0);
                    }
                    if (hctx->frame.ctl.siz == 0) {
                        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    } else {
                        hctx->frame.state =
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    }
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
                /* hctx->frame.ctl.siz <= SIZE_MAX */
                if (hctx->frame.ctl.siz <= (uint64_t)(frame->used - i - 1)) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "got payload size:", hctx->frame.ctl.siz);
                    ret = buffer_append_memory(payload, &frame->ptr[i],
                                               (size_t)(hctx->frame.ctl.siz &
                                                        SIZE_MAX));
                    i += (size_t)(hctx->frame.ctl.siz & SIZE_MAX);
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "rest of frame size:", frame->used - i - 1);
                /* SIZE_MAX < hctx->frame.ctl.siz */
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "got short payload size:",
                              frame->used - i - 1);
                    ret = buffer_append_memory(payload, &frame->ptr[i],
                                               frame->used - i - 1);
                    hctx->frame.ctl.siz -= (uint64_t)(frame->used - i - 1);
                    i += (frame->used - i - 1);
                    if (hctx->pd->conf.debug > MOD_WEBSOCKET_LOG_DEBUG) {
                        memset(u64str, 0, sizeof(u64str));
                        snprintf(u64str, sizeof(u64str) - 1,
                                 "rest of payload size: 0x%llx",
                                 (long long unsigned int)hctx->frame.ctl.siz &
                                 UINT64_MAX);
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", u64str);
                    }
                }
                if (ret != 0) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    chunkqueue_reset(hctx->fromcli);
                    buffer_reset(payload);
                    return -1;
                }
                switch (hctx->frame.type) {

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
                    if (hctx->frame.ctl.siz == 0) {
                        unmask_payload(hctx);
                        if (mod_websocket_conv_isUTF8(payload->ptr,
                                                      payload->used) !=
                            MOD_WEBSOCKET_TRUE) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                                      "s", "recv non UTF-8");
                            buffer_reset(payload);
                            return -1;
                        }
                        ret = mod_websocket_conv_to_server(hctx->cnv,
                                                           &enc, &encsiz,
                                                           payload->ptr,
                                                           payload->used);
                        if (ret != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                                      "s", "fail to convert chars");
                            buffer_reset(payload);
                            return -1;
                        }
                        buffer_reset(payload);
                        b = chunkqueue_get_append_buffer(hctx->tosrv);
                        if (!b) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                            free(enc);
                            return -1;
                        }
                        ret = buffer_append_memory(b, enc, encsiz);
                        free(enc);
                        if (ret != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                            buffer_reset(payload);
                            return -1;
                        }
                        /* lighty needs additional char to send */
                        ret = buffer_append_memory(b, &additional, 1);
                        if (ret != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                            chunkqueue_reset(hctx->tosrv);
                            return -1;
                        }
                    }
                    break;
#else
                case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

                case MOD_WEBSOCKET_FRAME_TYPE_BIN:
                    unmask_payload(hctx);
                    b = chunkqueue_get_append_buffer(hctx->tosrv);
                    if (!b) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    ret = buffer_append_memory(b, payload->ptr, payload->used);
                    buffer_reset(payload);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
                    /* lighty needs additional char to send */
                    ret = buffer_append_memory(b, &additional, 1);
                    if (ret != 0) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        return -1;
                    }
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_PING:
                    if (hctx->frame.ctl.siz == 0) {
                        unmask_payload(hctx);
                        mod_websocket_frame_send(hctx,
                                                 MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                                 payload->ptr, payload->used);
                        buffer_reset(payload);
                    }
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_PONG:
                    buffer_reset(payload);
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
                default:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid state");
                    chunkqueue_reset(hctx->fromcli);
                    buffer_reset(payload);
                    return -1;
                }
                break;
            default:
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: unknown state");
                chunkqueue_reset(hctx->fromcli);
                buffer_reset(payload);
                return -1;
            }
        }
    }
    chunkqueue_reset(hctx->fromcli);
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

int
mod_websocket_frame_send(handler_ctx *hctx,
                         mod_websocket_frame_type_t type,
                         char *payload, size_t siz) {
    if (!hctx) {
        return -1;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    if (hctx->handshake.version == 0) {
        return mod_websocket_frame_send_ietf_00(hctx, type, payload, siz);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->handshake.version >= 8) {
        return mod_websocket_frame_send_rfc_6455(hctx, type, payload, siz);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    return -1;
}

int
mod_websocket_frame_recv(handler_ctx *hctx) {
    if (!hctx) {
        return -1;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    if (hctx->handshake.version == 0) {
        return mod_websocket_frame_recv_ietf_00(hctx);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->handshake.version >= 8) {
        return mod_websocket_frame_recv_rfc_6455(hctx);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    return -1;
}

/* EOF */
