/*
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 */

#include <string.h>

#include "mod_websocket.h"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# include "mod_websocket_base64.h"
#endif

#define MOD_WEBSOCKET_BUFMAX (0x0fffff)

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
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
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
static int send_ietf_00(handler_ctx *hctx, mod_websocket_frame_type_t type, char *payload, size_t siz) {
    const char endl = '\0';
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    buffer *b = NULL;
    char *enc = NULL;
    size_t encsiz = 0;

    /* allowed null payload for close frame */
    if (payload == NULL && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT || type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
        return -1;
    }
    if (siz == 0 && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT || type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
        return 0;
    }
    b = chunkqueue_get_append_buffer(hctx->tocli);
    if (!b) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        return -1;
    }
    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        buffer_append_memory(b, (const char *)&head, 1);
        buffer_append_memory(b, payload, siz);
        buffer_append_memory(b, (const char *)&tail, 1);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        buffer_append_memory(b, (const char *)&head, 1);
        if (mod_websocket_base64_encode((unsigned char **)&enc, &encsiz,
                                        (unsigned char *)payload, siz) != 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            chunkqueue_reset(hctx->tocli);
            return -1;
        }
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "ss", "covert base64 text:", enc);
        buffer_append_memory(b, enc, encsiz);
        free(enc);
        buffer_append_memory(b, (const char *)&tail, 1);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
        buffer_append_memory(b, (const char *)&tail, 1);
        buffer_append_memory(b, (const char *)&head, 1);
        break;
    default:
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid frame type");
        return -1;
    }
    /* needs '\0' char to send */
    buffer_append_memory(b, &endl, 1);
    return 0;
}

static int recv_ietf_00(handler_ctx *hctx) {
    const char endl = '\0';
    char *pff = NULL;
    chunk *c = NULL;
    buffer *frame = NULL, *payload = NULL, *b = NULL;
    size_t i;
    char *b64 = NULL;
    size_t b64siz = 0;

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from client ( fd =", hctx->con->fd, "), size =", chunkqueue_length(hctx->fromcli));
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
                if (frame->ptr[i] == 0x00) {
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    i++;
                } else if (frame->ptr[i] == 0xff) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "recv close frame");
                    chunkqueue_reset(hctx->tosrv);
                    chunkqueue_reset(hctx->fromcli);
                    buffer_reset(payload);
                    return -1;
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "recv invalid frame");
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
                              "sx", "got continuous payload, size =", frame->used - i - 1);
                    hctx->frame.ctl.siz += frame->used - i - 1;
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN,
                                  "sx", "frame size has been exceeded:", MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    buffer_append_memory(payload, &frame->ptr[i], frame->used - i - 1);
                    i += frame->used - i - 1;
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "got final payload, size =", (pff - &frame->ptr[i]));
                    hctx->frame.ctl.siz += (pff - &frame->ptr[i]);
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN,
                                  "sx", "frame size has beed exceeded:", MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    buffer_append_memory(payload, &frame->ptr[i], pff - &frame->ptr[i]);
                    i += (pff - &frame->ptr[i]);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                }
                i++;
                if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT && payload->used > 0) {
                    hctx->frame.ctl.siz = 0;
                    b = chunkqueue_get_append_buffer(hctx->tosrv);
                    if (!b) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->tosrv);
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    buffer_append_memory(b, payload->ptr, payload->used);
                    /* needs '\0' char to send */
                    buffer_append_memory(b, &endl, 1);
                    buffer_reset(payload);
                } else {
                    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT && payload->used > 0) {
                        b = chunkqueue_get_append_buffer(hctx->tosrv);
                        if (!b) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                            chunkqueue_reset(hctx->tosrv);
                            chunkqueue_reset(hctx->fromcli);
                            buffer_reset(payload);
                            return -1;
                        }
                        payload->ptr[payload->used] = '\0';
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "ss", "recv base64 text:", payload->ptr);
                        if (mod_websocket_base64_decode((unsigned char **)&b64, &b64siz,
                                                        (unsigned char *)payload->ptr) != 0) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid base64 text");
                            chunkqueue_reset(hctx->tosrv);
                            chunkqueue_reset(hctx->fromcli);
                            return -1;
                        }
                        buffer_append_memory(b, b64, b64siz);
                        /* needs '\0' char to send */
                        buffer_append_memory(b, &endl, 1);
                        buffer_reset(payload);
                        free(b64);
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
static int send_rfc_6455(handler_ctx *hctx, mod_websocket_frame_type_t type, char *payload, size_t siz) {
    const char endl = '\0';
    char c, sizbuf[MOD_WEBSOCKET_FRAME_LEN63 + 1];
    buffer *b = NULL;

    /* allowed null payload for ping, pong, close frame */
    if (payload == NULL && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT || type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
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
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = text");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_BIN);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = binary");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PING:
        c = (char) (0x80 | MOD_WEBSOCKET_OPCODE_PING);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = ping");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PONG:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_PONG);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = pong");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
    default:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_CLOSE);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = close");
        break;
    }
    buffer_append_memory(b, &c, 1);

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "payload size =", siz);
    if (siz < MOD_WEBSOCKET_FRAME_LEN16) {
        sizbuf[0] = siz;
        buffer_append_memory(b, sizbuf, 1);
    } else if (siz <= UINT16_MAX) {
        sizbuf[0] = MOD_WEBSOCKET_FRAME_LEN16;
        sizbuf[1] = (siz >> 8) & 0xff;
        sizbuf[2] = siz & 0xff;
        buffer_append_memory(b, sizbuf, MOD_WEBSOCKET_FRAME_LEN16_CNT + 1);
    } else {
        memset(sizbuf, 0, sizeof(sizbuf));
        sizbuf[0] = MOD_WEBSOCKET_FRAME_LEN63;
        sizbuf[5] = (siz >> 24) & 0xff;
        sizbuf[6] = (siz >> 16) & 0xff;
        sizbuf[7] = (siz >> 8) & 0xff;
        sizbuf[8] = siz & 0xff;
        buffer_append_memory(b, sizbuf, MOD_WEBSOCKET_FRAME_LEN63_CNT + 1);
    }
    if (siz == 0) {
        /* needs '\0' char to send */
        buffer_append_memory(b, &endl, 1);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "frame size =", b->used - 1);
        return 0;
    }
    buffer_append_memory(b, payload, siz);
    /* needs '\0' char to send */
    buffer_append_memory(b, &endl, 1);
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "frame size =", b->used - 1);
    return 0;
}

static void unmask_payload(handler_ctx *hctx) {
    size_t i;

    for (i = 0; i < hctx->frame.payload->used; i++) {
        hctx->frame.payload->ptr[i] =
            hctx->frame.payload->ptr[i] ^ hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt];
        hctx->frame.ctl.mask_cnt = (hctx->frame.ctl.mask_cnt + 1) % 4;
    }
    return;
}

static int recv_rfc_6455(handler_ctx *hctx) {
    const char endl = '\0';
    chunk *c = NULL;
    buffer *frame = NULL, *payload = NULL, *b = NULL;
    size_t i;

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from client ( fd =", hctx->con->fd, "), size =", chunkqueue_length(hctx->fromcli));
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
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = continue");
                    hctx->frame.type = hctx->frame.type_before;
                    break;
                case MOD_WEBSOCKET_OPCODE_TEXT:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = text");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_BIN:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = binary");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_PING:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = ping");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PING;
                    break;
                case MOD_WEBSOCKET_OPCODE_PONG:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = pong");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
                    break;
                case MOD_WEBSOCKET_OPCODE_CLOSE:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = close");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
                    chunkqueue_reset(hctx->fromcli);
                    return -1;
                    break;
                default:
                    chunkqueue_reset(hctx->fromcli);
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "type is invalid");
                    return -1;
                    break;
                }
                i++;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH:
                if ((frame->ptr[i] & 0x80) != 0x80) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "payload was not masked");
                    chunkqueue_reset(hctx->fromcli);
                    return -1;
                }
                hctx->frame.ctl.mask_cnt = 0;
                hctx->frame.ctl.siz = (uint64_t)(frame->ptr[i] & 0x7f);
                if (hctx->frame.ctl.siz == 0) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "specified payload size =", hctx->frame.ctl.siz);
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
                              "sx", "specified payload size =", hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH:
                hctx->frame.ctl.siz =
                    (hctx->frame.ctl.siz << 8) + (frame->ptr[i] & 0xff);
                hctx->frame.ctl.siz_cnt--;
                if (hctx->frame.ctl.siz_cnt <= 0) {
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING &&
                        hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN,
                                  "sx", "frame size has beed exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        chunkqueue_reset(hctx->fromcli);
                        return -1;
                    }
                    if (hctx->pd->conf.debug >= MOD_WEBSOCKET_LOG_DEBUG) {
                        char u64str[128];
                        snprintf(u64str, sizeof(u64str),
                                 "specified payload size = 0x%llx",
                                 (uint64_t)hctx->frame.ctl.siz & UINT64_MAX);
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
                              "sx", "read payload, size =", hctx->frame.ctl.siz);
                    buffer_append_memory(payload, &frame->ptr[i],
                                         (size_t)(hctx->frame.ctl.siz & SIZE_MAX));
                    i += (size_t)(hctx->frame.ctl.siz & SIZE_MAX);
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "rest of frame size =", frame->used - i - 1);
                /* SIZE_MAX < hctx->frame.ctl.siz */
                } else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,
                              "sx", "read payload, size =",
                              frame->used - i - 1);
                    buffer_append_memory(payload, &frame->ptr[i], frame->used - i - 1);
                    hctx->frame.ctl.siz -= (uint64_t)(frame->used - i - 1);
                    i += (frame->used - i - 1);
                    if (hctx->pd->conf.debug >= MOD_WEBSOCKET_LOG_DEBUG) {
                        char u64str[128];
                        snprintf(u64str, sizeof(u64str),
                                 "rest of payload size = 0x%llx",
                                 (uint64_t)hctx->frame.ctl.siz & UINT64_MAX);
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", u64str);
                    }
                }
                switch (hctx->frame.type) {
                case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
                case MOD_WEBSOCKET_FRAME_TYPE_BIN:
                    unmask_payload(hctx);
                    b = chunkqueue_get_append_buffer(hctx->tosrv);
                    if (!b) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
                        chunkqueue_reset(hctx->fromcli);
                        buffer_reset(payload);
                        return -1;
                    }
                    buffer_append_memory(b, payload->ptr, payload->used);
                    buffer_reset(payload);
                    /* needs '\0' char to send */
                    buffer_append_memory(b, &endl, 1);
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
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid frame type");
                    chunkqueue_reset(hctx->fromcli);
                    buffer_reset(payload);
                    return -1;
                }
                break;
            default:
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid state");
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

static int send_forward(handler_ctx *hctx, char *payload, size_t siz) {
    const char endl = '\0';
    buffer *b = NULL;

    b = chunkqueue_get_append_buffer(hctx->tocli);
    if (!b) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
        return -1;
    }
    buffer_append_memory(b, payload, siz);
    /* needs '\0' char to send */
    buffer_append_memory(b, &endl, 1);
    return 0;
}

static int recv_forward(handler_ctx *hctx) {
    chunk *c = NULL;
    buffer *frame = NULL, *b = NULL;

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from client ( fd =", hctx->con->fd,
              "), size =", chunkqueue_length(hctx->fromcli));
    for (c = hctx->fromcli->first; c; c = c->next) {
        frame = c->mem;
        if (!frame) {
            continue;
        }
        b = chunkqueue_get_append_buffer(hctx->tosrv);
        if (!b) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "no memory");
            return -1;
        }
        buffer_append_memory(b, frame->ptr, frame->used);
    }
    chunkqueue_reset(hctx->fromcli);
    return 0;
}

int mod_websocket_frame_send(handler_ctx *hctx, mod_websocket_frame_type_t type,
                             char *payload, size_t siz) {
    if (!hctx) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid context");
        return -1;
    }
    if (hctx->mode == MOD_WEBSOCKET_WEBSOCKET_PROXY) {
        return send_forward(hctx, payload, siz);
    } else if (hctx->mode == MOD_WEBSOCKET_TCP_PROXY) {

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        if (hctx->handshake.version == 0) {
            return send_ietf_00(hctx, type, payload, siz);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        if (hctx->handshake.version >= 8) {
            return send_rfc_6455(hctx, type, payload, siz);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    }
    return -1;
}

int mod_websocket_frame_recv(handler_ctx *hctx) {
    if (!hctx) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid context");
        return -1;
    }
    if (hctx->mode == MOD_WEBSOCKET_WEBSOCKET_PROXY) {
        return recv_forward(hctx);
    } else if (hctx->mode == MOD_WEBSOCKET_TCP_PROXY) {

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        if (hctx->handshake.version == 0) {
            return recv_ietf_00(hctx);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        if (hctx->handshake.version >= 8) {
            return recv_rfc_6455(hctx);
        }
#endif	/* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    }
    return -1;
}
