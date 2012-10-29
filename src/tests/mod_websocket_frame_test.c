/**
 * $Id$
 **/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket.h"

#define	ASCII_STR	"Hello"
#define	SHOW_DETAIL	(0)

CU_TestFunc
mod_websocket_frame_send_test() {
    struct tstptns {
        const char *fname;
        const char *locale;
        mod_websocket_bool_t exp;
    } ptns[] = {
        {
            "mod_websocket_conv.utf8.dat",
            "UTF-8",
            MOD_WEBSOCKET_TRUE
        },
        {
            "mod_websocket_conv.sjis.dat",
            "Shift_JIS",
            MOD_WEBSOCKET_FALSE
        },
        {
            "mod_websocket_conv.euc.dat",
            "EUC-JP",
            MOD_WEBSOCKET_FALSE
        },
    };
    FILE *fp;
    int i;
    char buf[4096];
    size_t siz;
    handler_ctx hctx;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    plugin_data pd;

    fprintf(stderr, "check send\n");
    memset(&hctx, 0, sizeof(hctx));
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    ret = mod_websocket_frame_send(NULL, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   NULL, 0);
    CU_ASSERT_EQUAL(ret, -1);
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   NULL, 1);
    CU_ASSERT_EQUAL(ret, -1);
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   NULL, 0);
    CU_ASSERT_EQUAL(ret, -1);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    fprintf(stderr, "check: ASCII\n");
    hctx.handshake.version = 0;
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
            buffer_copy_memory(b, c->mem->ptr, c->mem->used);
        } else {
            buffer_append_memory(b, c->mem->ptr, c->mem->used);
        }
    }
    CU_ASSERT_EQUAL(b->used - 3, strlen(ASCII_STR));
    if (b->ptr[0] != 0x00) {
        CU_FAIL("frame start bit invalid");
    }
    if (b->ptr[b->used - 2] != -1) {
        CU_FAIL("frame end bit invalid");
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 1, ASCII_STR, strlen(ASCII_STR)), 0);
    buffer_free(b);
    b = NULL;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    for (i = 0; i < 3; i++) {
        chunkqueue_reset(hctx.tocli);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);
#endif

        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        siz = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);

        ret = mod_websocket_frame_send(&hctx,
                                       MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                       buf, siz);
        CU_ASSERT_EQUAL(ret, 0);
        for (c = hctx.tocli->first; c; c = c->next) {
            if (NULL == b) {
                b = buffer_init();
                buffer_copy_memory(b, c->mem->ptr, c->mem->used);
            } else {
                buffer_append_memory(b, c->mem->ptr, c->mem->used);
            }
        }
        if (!buffer_is_empty(b)) {
            if (b->ptr[0] != 0x00) {
                CU_FAIL("frame start bit invalid");
            }
            if (b->ptr[b->used - 2] != -1) {
                CU_FAIL("frame end bit invalid");
            }
            buffer_free(b);
            b = NULL;
        } else {
            CU_FAIL("send buffer is empty");
        }
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif
    }

    chunkqueue_reset(hctx.tocli);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif

    fprintf(stderr, "check: close\n");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                   NULL, 0);
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 3);
    if (b->ptr[0] != -1) {
        CU_FAIL("frame start bit invalid");
    }
    if (b->ptr[b->used - 1] != 0x00) {
        CU_FAIL("frame end bit invalid");
    }
    buffer_free(b);
    chunkqueue_reset(hctx.tocli);
#endif

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    b = NULL;
    hctx.handshake.version = 8;
    fprintf(stderr, "check: ASCII\n");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, strlen(ASCII_STR) + 3);
    if ((b->ptr[0] & 0xff) != 0x81) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x05) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 2, ASCII_STR, strlen(ASCII_STR)), 0);
    buffer_free(b);
    b = NULL;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    for (i = 0; i < 3; i++) {
        fprintf(stderr, "check: %s\n", ptns[i].fname);
        chunkqueue_reset(hctx.tocli);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);
#endif
        fp = fopen(ptns[i].fname, "r");
        siz = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);

        ret = mod_websocket_frame_send(&hctx,
                                       MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                       buf, siz);
        CU_ASSERT_EQUAL(ret, 0);
        for (c = hctx.tocli->first; c; c = c->next) {
            if (NULL == b) {
                b = buffer_init();
            }
            buffer_append_memory(b, c->mem->ptr, c->mem->used);
        }
        if (!buffer_is_empty(b)) {
            if ((b->ptr[0] & 0xff) != 0x81) {
                CU_FAIL("opcode invalid");
                fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
            }
            buffer_free(b);
            b = NULL;
        } else {
            CU_FAIL("send buffer is empty");
        }
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif
    }

    fprintf(stderr, "check: BINARY\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    buf[0] = 0x00;
    buf[1] = 0x01;
    buf[2] = 0x02;
    buf[3] = 0x03;
    buf[4] = 0x04;
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                   buf, 5);
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 8);
    if ((b->ptr[0] & 0xff) != 0x82) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x05) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 2, buf, 5), 0);
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    fprintf(stderr, "check: PING\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PING,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 8);
    if ((b->ptr[0] & 0xff) != 0x89) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x05) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 2, ASCII_STR, strlen(ASCII_STR)), 0);
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    fprintf(stderr, "check: PONG\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 8);
    if ((b->ptr[0] & 0xff) != 0x8A) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x05) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 2, ASCII_STR, strlen(ASCII_STR)), 0);
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    fprintf(stderr, "check: close\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                   NULL, 0);
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 3);
    if ((b->ptr[0] & 0xff) != 0x88) {
        CU_FAIL("opcode invalid");
    }
    if (b->ptr[1] != 0x00) {
        CU_FAIL("payload length invalid");
    }
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    fprintf(stderr, "check: 16bit length TEXT\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    memset(buf, 'a', sizeof(buf));
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   buf, sizeof(buf));
    CU_ASSERT_EQUAL(ret, 0);
    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, sizeof(buf) + 5);
    if ((b->ptr[0] & 0xff) != 0x81) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x7e) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    siz = ((b->ptr[2] & 0xff) << 8) + (b->ptr[3] & 0xff);
    if (siz != sizeof(buf)) {
        CU_FAIL("extend payload length invalid");
        fprintf(stderr, "%lu\n", (long unsigned int)siz);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 4, buf, sizeof(buf)), 0);
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    fprintf(stderr, "check: 16bit length BINARY\n");
    chunkqueue_reset(hctx.tocli);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    memset(buf, 0, sizeof(buf));
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                   buf, sizeof(buf));
    CU_ASSERT_EQUAL(ret, 0);
    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, sizeof(buf) + 5);
    if ((b->ptr[0] & 0xff) != 0x82) {
        CU_FAIL("opcode invalid");
        fprintf(stderr, "0x%x\n", b->ptr[0] & 0xff);
    }
    if ((b->ptr[1] & 0xff) != 0x7e) {
        CU_FAIL("payload length invalid");
        fprintf(stderr, "0x%x\n", b->ptr[1] & 0xff);
    }
    siz = ((b->ptr[2] & 0xff) << 8) + (b->ptr[3] & 0xff);
    if (siz != sizeof(buf)) {
        CU_FAIL("extend payload length invalid");
        fprintf(stderr, "%u\n", (long unsigned int)siz);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 4, buf, sizeof(buf)), 0);
    buffer_free(b);
    b = NULL;
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif
#endif

    return 0;
}

void
mask_payload(char *buf, size_t siz, const char *mask) {
    size_t i;

    for (i = 0; i < siz; i++) {
        buf[i] = buf[i] ^ mask[i % 4];
    }
    return;
}

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
CU_TestFunc
mod_websocket_frame_recv_test() {
    struct tstptns {
        const char *fname;
        const char *locale;
        mod_websocket_bool_t exp;
    } ptns[] = {
        {
            "mod_websocket_conv.euc.dat",
            "EUC-JP",
            MOD_WEBSOCKET_FALSE
        },
        {
            "mod_websocket_conv.sjis.dat",
            "Shift_JIS",
            MOD_WEBSOCKET_FALSE
        },
        {
            "mod_websocket_conv.utf8.dat",
            "UTF-8",
            MOD_WEBSOCKET_TRUE
        },
    };
    FILE *fp;
    int i, j;
    char buf[1024];
    size_t siz;
    handler_ctx hctx;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    connection con;
    plugin_data pd;
    const char additional = 0x00;

    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    const unsigned char cfrm[2] = { 0xff, 0x00 };
    char longframe[MOD_WEBSOCKET_BUFMAX + 1];

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    char *enc = NULL;
    size_t encsiz = 0;
#endif	/* _MOD_WEBSOCKET_WITH_ICU_ */

    fprintf(stderr, "check recv\n");
    memset(&hctx, 0, sizeof(hctx));
    hctx.fd = 1;
    hctx.handshake.version = 0;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.fromcli = con.read_queue;
    hctx.tosrv = chunkqueue_init();
    hctx.tocli = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif

    ret = mod_websocket_frame_recv(NULL);
    CU_ASSERT_EQUAL(ret, -1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);

    fprintf(stderr, "check: ASCII\n");
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&tail, 1);
    buffer_append_memory(b, (char *)&additional, 1);
    ret = mod_websocket_frame_recv(&hctx);
    b = NULL;
    CU_ASSERT_EQUAL(ret, 0);
    for (c = hctx.tosrv->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    if (!buffer_is_empty(b)) {
        CU_ASSERT_EQUAL(memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)), 0);
        buffer_free(b);
        b = NULL;

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

    } else {
        CU_FAIL("recv no frames");
    }

    chunkqueue_reset(hctx.fromcli);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(hctx.tocli);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    for (i = 0; i < 3; i++) {
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);
        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        memset(buf, 0, sizeof(buf));
        siz = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        mod_websocket_conv_to_client(hctx.cnv, &enc, &encsiz, buf, siz);
        b = chunkqueue_get_append_buffer(con.read_queue);
        buffer_append_memory(b, (char *)&head, 1);
        buffer_append_memory(b, enc, encsiz);
        free(enc);
        buffer_append_memory(b, (char *)&tail, 1);
        buffer_append_memory(b, (char *)&additional, 1);

        CU_ASSERT_EQUAL(ret, 0);
        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
        b = NULL;
        mod_websocket_conv_final(hctx.cnv);
        for (c = hctx.tosrv->first; c; c = c->next) {
            if (NULL == b) {
                b = buffer_init();
            }
            buffer_append_memory(b, c->mem->ptr, c->mem->used);
        }
        if (!buffer_is_empty(b)) {
            if (memcmp(b->ptr, buf, b->used) != 0) {
                fprintf(stderr, "exp: \n");
                for (j = 0; j < siz; j++) {
                    fprintf(stderr, "0x%02x, ", buf[j] & 0xff);
                }
                fprintf(stderr, "\nres: \n");
                for (j = 0; j < b->used; j++) {
                    fprintf(stderr, "0x%02x, ", b->ptr[j] &0xff);
                }
                fprintf(stderr, "\n\n");
                CU_FAIL("invalid recv");
            }
            buffer_free(b);
            b = NULL;
        } else {
            CU_FAIL("recv no frames");
        }
        chunkqueue_reset(hctx.fromcli);
        chunkqueue_reset(hctx.tosrv);
        chunkqueue_reset(hctx.tocli);
    }
#endif

    /* recv payload * 2 */
    fprintf(stderr, "check: double payload\n");
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&tail, 1);
    buffer_append_memory(b, &additional, 1);
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&tail, 1);
    buffer_append_memory(b, &additional, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    b = NULL;

    for (c = hctx.tosrv->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    if (!buffer_is_empty(b)) {
        memcpy(buf, ASCII_STR, strlen(ASCII_STR));
        buf[strlen(ASCII_STR)] = 0x00;
        memcpy(buf + strlen(ASCII_STR) + 1, ASCII_STR, strlen(ASCII_STR));
        buf[strlen(ASCII_STR) * 2 + 1] = 0x00;
        if (memcmp(b->ptr, buf, strlen(ASCII_STR) * 2 + 2) != 0 ||
            b->used != strlen(ASCII_STR) * 2 + 2) {
            fprintf(stderr, "exp: \n");
            for (j = 0; j < strlen(ASCII_STR) * 2 + 2; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        buf[j] & 0xff, buf[j] & 0xff);
            }
            fprintf(stderr, "\nres: \n");
            for (j = 0; j < b->used; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        b->ptr[j] & 0xff, b->ptr[j] & 0xff);
            }
            fprintf(stderr, "\n\n");
            CU_FAIL("invalid recv");
        }
        buffer_free(b);
        b = NULL;
    } else {
        CU_FAIL("recv no frames");
    }
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    /* recv chunk */
    fprintf(stderr, "check: chunk\n");

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif

    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&tail, 1);
    buffer_append_memory(b, &additional, 1);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    b = NULL;

    for (c = hctx.tosrv->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    if (!buffer_is_empty(b)) {

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR) + 1) {
            fprintf(stderr, "res: \n");
            for (j = 0; j < b->used; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        b->ptr[j] & 0xff, b->ptr[j] & 0xff);
            }
            fprintf(stderr, "\n\n");
            CU_FAIL("invalid recv");
        }
        buffer_free(b);
        b = NULL;
#else
        memcpy(buf, ASCII_STR, strlen(ASCII_STR));
        buf[strlen(ASCII_STR)] = 0x00;
        memcpy(buf + strlen(ASCII_STR) + 1, ASCII_STR, strlen(ASCII_STR));
        buf[strlen(ASCII_STR) * 2 + 1] = 0x00;
        if (memcmp(b->ptr, buf, strlen(ASCII_STR) * 2 + 2) != 0 ||
            b->used != strlen(ASCII_STR) * 2 + 2) {
            fprintf(stderr, "exp: \n");
            for (j = 0; j < strlen(ASCII_STR) * 2 + 2; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        buf[j] & 0xff, buf[j] & 0xff);
            }
            fprintf(stderr, "\nres: \n");
            for (j = 0; j < b->used; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        b->ptr[j] & 0xff, b->ptr[j] & 0xff);
            }
            fprintf(stderr, "\n\n");
            CU_FAIL("invalid recv");
        }
        buffer_free(b);
        b = NULL;
#endif

    } else {
        CU_FAIL("recv no frames");
    }
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(hctx.fromcli);
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&tail, 1);
    buffer_append_memory(b, &additional, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    b = NULL;
    for (c = hctx.tosrv->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (!buffer_is_empty(b)) {
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR) + 1) {
            fprintf(stderr, "res: \n");
            for (j = 0; j < b->used; j++) {
                fprintf(stderr, "0x%02x(%c), ",
                        b->ptr[j] & 0xff, b->ptr[j] & 0xff);
            }
            fprintf(stderr, "\n\n");
            CU_FAIL("invalid recv");
        }
        buffer_free(b);
        b = NULL;
    } else {
        CU_FAIL("recv no frames");
    }
    mod_websocket_conv_final(hctx.cnv);
#else
    CU_ASSERT_EQUAL(1, buffer_is_empty(b));
#endif

    /* recv close */
    fprintf(stderr, "check: close\n");

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif

    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)cfrm, sizeof(cfrm));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, -1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    /* recv long frame */
    fprintf(stderr, "check: long frame\n");

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
#endif

    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&head, 1);
    buffer_append_memory(b, (char *)&additional, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(1, chunkqueue_is_empty(hctx.fromcli));
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);

    memset(longframe, 'a', MOD_WEBSOCKET_BUFMAX);
    longframe[MOD_WEBSOCKET_BUFMAX] = 0x00;
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, longframe, sizeof(longframe));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, longframe, sizeof(longframe));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, -1);
#else
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, longframe, sizeof(longframe));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, &tail, 1);
    buffer_append_memory(b, &additional, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
#endif

    /* dead loop test */
    fprintf(stderr, "check: dead loop\n");

    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.fromcli);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(hctx.tocli);

    char issuebuf[][9] = {
        {0x00, 0x30, 0x20, 0x30, 0x20, 0x30, 0x20, 0x30, 0x00},
        {0x20, 0x30, 0x0a, 0x00, 0xff, 0x00, 0x30, 0x20, 0x00},
        {0x30, 0x20, 0x30, 0x20, 0x30, 0x20, 0x30, 0x0a, 0x00},
        {0x00, 0xff, 0x00, 0x30, 0x20, 0x30, 0x20, 0x30, 0x00},
        {0x20, 0x30, 0x20, 0x30, 0x0a, 0x00, 0xff, 0x00, 0x00},
        {0x30, 0x20, 0x30, 0x20, 0x30, 0x20, 0x30, 0x20, 0x00},
        {0x30, 0x0a, 0x00, 0xff, 0x00, 0x30, 0x20, 0x00, 0x00}
    };

    for (i = 0; i < 7; ++i) {
        b = chunkqueue_get_append_buffer(con.read_queue);
        buffer_append_memory(b, issuebuf[i], sizeof(issuebuf[i]));
    }
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);

    return 0;
}
#endif

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
void
_recv_short_chunk_test(char type, uint64_t ex_len) {
    handler_ctx hctx;
    connection con;
    plugin_data pd;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    const char additional = 0x00;
    unsigned char ctl;
    unsigned char len;
    const char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
    char ch, data[MAX_READ_LIMIT], mask_data[MAX_READ_LIMIT];
    char *pdata, *pmask_data;
    char rnd;
    size_t i;
    int exp_type;
    uint64_t bex_len = ex_len;

    fprintf(stderr, "check: payload size: 0x%llx\n",
            (long long unsigned int)ex_len);
    if (type == MOD_WEBSOCKET_OPCODE_TEXT ||
        type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = 'a' + (random() % 26);
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN ||
               type == MOD_WEBSOCKET_OPCODE_PING ||
               type == MOD_WEBSOCKET_OPCODE_PONG) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = random() % 0x100;
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    }

    if (type == MOD_WEBSOCKET_OPCODE_TEXT) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    } else if (type == MOD_WEBSOCKET_OPCODE_PING) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PING;
    } else if (type == MOD_WEBSOCKET_OPCODE_PONG) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
    } else if (type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    } else {
        exp_type = -1;
    }

    /* initialize */
    memset(&hctx, 0, sizeof(hctx));

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    hctx.fd = 1;
    hctx.handshake.version = 8;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.fromcli = con.read_queue;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x80 | type;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
        exp_type == -1) {
        CU_ASSERT_EQUAL(ret, -1);
        return;
    }
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.type, exp_type);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

    if (ex_len < 0x7e) {
        len = 0x80 | (ex_len &0x0ff);
    } else if (ex_len <= 0x0ffff) {
        len = 0x80 | 0x7e;
    } else {
        len = 0x80 | 0x7f;
    }
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    if (ex_len < 0x7e) {
        CU_ASSERT_EQUAL(ex_len, hctx.frame.ctl.siz);
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_MASK);
    } else {
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH);
    }
    CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

    if (0x7e <= ex_len && ex_len <= 0x0ffff) {
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = (ex_len >> 8) & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(ex_len, hctx.frame.ctl.siz);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_MASK);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
         exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING)) {
#else
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
#endif

        for (i = 7; i > 0; i--) {
            b = chunkqueue_get_append_buffer(con.read_queue);
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
            buffer_append_memory(b, &additional, 1);

            ret = mod_websocket_frame_recv(&hctx);
            CU_ASSERT_EQUAL(ret, 0);
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        }
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, -1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }
    if (0x0ffff < ex_len) {
        for (i = 7; i > 0; i--) {
            b = chunkqueue_get_append_buffer(con.read_queue);
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
            buffer_append_memory(b, &additional, 1);

            ret = mod_websocket_frame_recv(&hctx);
            CU_ASSERT_EQUAL(ret, 0);
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        }
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(ex_len, hctx.frame.ctl.siz);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_MASK);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    }

    // check chunked mask
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)mask, sizeof(mask) - 1);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_MASK);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&mask[sizeof(mask) - 1], 1);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    if (ex_len == 0) {
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[2] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

    pmask_data = mask_data;
    pdata = data;
    bex_len = ex_len;

    /* get 1 byte payload */
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, pmask_data, 1);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if ((exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT && ex_len != 1) ||
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    } else {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
        c = hctx.tosrv->first;
        if (!buffer_is_empty(c->mem)) {
            CU_ASSERT_EQUAL(1 + 1, c->mem->used);
            CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
            CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
        } else {
            CU_FAIL("recv no frames");
        }
    }
#else
    if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    } else {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
        c = hctx.tosrv->first;
        if (!buffer_is_empty(c->mem)) {
            CU_ASSERT_EQUAL(1 + 1, c->mem->used);
            CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
            CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
        } else {
            CU_FAIL("recv no frames");
        }
    }
#endif

    CU_ASSERT_EQUAL(hctx.frame.ctl.siz, ex_len - 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (ex_len == 1) {
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(1, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(*pdata & 0xff, c->mem->ptr[2] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[3] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        }
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
            c = hctx.tosrv->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
            } else {
                CU_FAIL("recv no frames");
            }
        }
        mod_websocket_conv_final(hctx.cnv);
        return;
    } else {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
    }
    if (exp_type != MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
        chunkqueue_reset(hctx.tosrv);
    }
#else
    chunkqueue_reset(hctx.tosrv);
    if (ex_len == 1) {
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(1, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(*pdata & 0xff, c->mem->ptr[2] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[3] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        }
        return;
    } else {
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
    }
#endif

    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    ex_len -= 1;
    pdata++;
    pmask_data++;

    while (ex_len > 0) {
        b = chunkqueue_get_append_buffer(con.read_queue);
        if (ex_len < MAX_READ_LIMIT) { // lighty's MAX_READ_LIMIT
            /* gets 1 byte short payload */
            buffer_append_memory(b, pmask_data, ex_len - 1);
            buffer_append_memory(b, &additional, 1);
            ret = mod_websocket_frame_recv(&hctx);
            CU_ASSERT_EQUAL(ret, 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
#else
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
#endif

            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(ex_len - 1 + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr, ex_len - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            chunkqueue_reset(hctx.tosrv);
            pdata += (ex_len - 1);
            pmask_data += (ex_len - 1);

            /* gets last 1 byte of payload */
            b = chunkqueue_get_append_buffer(con.read_queue);
            buffer_append_memory(b, pmask_data, 1);
            buffer_append_memory(b, &additional, 1);

            ret = mod_websocket_frame_recv(&hctx);
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
                c = hctx.tocli->first;
                if (!buffer_is_empty(c->mem)) {
                    if (bex_len < 0x7e) {
                        CU_ASSERT_EQUAL(2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(bex_len, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[2], bex_len));
                    } else if (bex_len <= 0xffff) {
                        CU_ASSERT_EQUAL(2 + 2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0x7e, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL((bex_len >> 8) & 0xff,
                                        c->mem->ptr[2] & 0xff);
                        CU_ASSERT_EQUAL(bex_len & 0xff,
                                        c->mem->ptr[3] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[4], bex_len));
                    }
                    CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                    c->mem->ptr[0] & 0xff);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                } else {
                    CU_FAIL("not send pong");
                }
            }
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
                    c = hctx.tosrv->first;
                    if (!buffer_is_empty(c->mem)) {
                        CU_ASSERT_EQUAL(bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                        if (bex_len < sizeof(data)) {
                            CU_ASSERT_EQUAL(0, memcmp(data, c->mem->ptr,
                                                      bex_len));
                        } else {
                            CU_ASSERT_EQUAL(0, memcmp(data, c->mem->ptr,
                                                      sizeof(data)));
                        }
                    } else {
                        CU_FAIL("recv no frames");
                    }
                } else {
                    c = hctx.tosrv->first;
                    if (!buffer_is_empty(c->mem)) {
                        CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                        CU_ASSERT_EQUAL(*pdata, c->mem->ptr[c->mem->used - 2]);
                    } else {
                        CU_FAIL("recv no frames");
                    }
                }
            }
#else
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
                } else {
                    CU_FAIL("recv no frames");
                }
            }
#endif

            CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            ex_len = 0;
        } else {
            buffer_append_memory(b, pmask_data, sizeof(mask_data) - 1);
            buffer_append_memory(b, &additional, 1);
            ret = mod_websocket_frame_recv(&hctx);
            CU_ASSERT_EQUAL(ret, 0);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
#else
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
#endif
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(sizeof(data) - 1 + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(&data[1],
                                              c->mem->ptr, sizeof(data) - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
            ex_len -= (sizeof(data) - 1);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, ex_len);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            chunkqueue_reset(hctx.tosrv);
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
            // skip
            if (exp_type != MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
                hctx.frame.ctl.siz = MAX_READ_LIMIT - 1;
                ex_len = MAX_READ_LIMIT - 1;
                pdata = data;
                pmask_data = mask_data;
            }
#else
            // skip
            hctx.frame.ctl.siz = MAX_READ_LIMIT - 1;
            ex_len = MAX_READ_LIMIT - 1;
            pdata = data;
            pmask_data = mask_data;
#endif
        }
    }
}

void
_recv_short_chunk_test_2(char type, uint64_t ex_len) {
    handler_ctx hctx;
    connection con;
    plugin_data pd;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    const char additional = 0x00;
    unsigned char ctl;
    unsigned char len;
    const char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
    char ch, data[MAX_READ_LIMIT], mask_data[MAX_READ_LIMIT];
    char *pdata, *pmask_data;
    char rnd;
    size_t i;
    int exp_type;
    uint64_t bex_len = ex_len;

    fprintf(stderr, "check: payload size: 0x%llx\n",
            (long long unsigned int)ex_len);
    if (type == MOD_WEBSOCKET_OPCODE_TEXT ||
        type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = 'a' + (random() % 26);
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN ||
               type == MOD_WEBSOCKET_OPCODE_PING ||
               type == MOD_WEBSOCKET_OPCODE_PONG) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = random() % 0x100;
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    }

    if (type == MOD_WEBSOCKET_OPCODE_TEXT) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    } else if (type == MOD_WEBSOCKET_OPCODE_PING) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PING;
    } else if (type == MOD_WEBSOCKET_OPCODE_PONG) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
    } else if (type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    } else {
        exp_type = -1;
    }

    /* initialize */
    memset(&hctx, 0, sizeof(hctx));

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    hctx.fd = 1;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.handshake.version = 8;
    hctx.fromcli = con.read_queue;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x80 | type;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, &additional, 1);

    if (ex_len < 0x7e) {
        len = 0x80 | (ex_len &0x0ff);
    } else if (ex_len <= 0x0ffff) {
        len = 0x80 | 0x7e;
    } else {
        len = 0x80 | 0x7f;
    }
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, &additional, 1);

    if (0x7e <= ex_len && ex_len <= 0x0ffff) {
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = (ex_len >> 8) & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
         exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING)) {
#else
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
#endif

        for (i = 7; i > 0; i--) {
            b = chunkqueue_get_append_buffer(con.read_queue);
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
            buffer_append_memory(b, &additional, 1);
        }
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, -1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }
    if (0x0ffff < ex_len) {
        for (i = 7; i > 0; i--) {
            b = chunkqueue_get_append_buffer(con.read_queue);
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
            buffer_append_memory(b, &additional, 1);
        }
        b = chunkqueue_get_append_buffer(con.read_queue);
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);
    }

    // check chunked mask
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)mask, sizeof(mask) - 1);
    buffer_append_memory(b, &additional, 1);
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)&mask[sizeof(mask) - 1], 1);
    buffer_append_memory(b, &additional, 1);

    if (ex_len == 0) {
        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[2] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    pmask_data = mask_data;
    pdata = data;
    bex_len = ex_len;

    if (ex_len == 1) {
        /* get 1 byte payload */
        b = chunkqueue_get_append_buffer(con.read_queue);
        buffer_append_memory(b, pmask_data, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(1, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(*pdata & 0xff, c->mem->ptr[2] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[3] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        } else if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        } else {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
            c = hctx.tosrv->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
            } else {
                CU_FAIL("recv no frames");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    while (ex_len > 0) {
        b = chunkqueue_get_append_buffer(con.read_queue);
        if (ex_len < MAX_READ_LIMIT) { // lighty's MAX_READ_LIMIT
            pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
            /* gets 1 byte short payload */
            buffer_append_memory(b, pmask_data, ex_len - 1);
            buffer_append_memory(b, &additional, 1);
            /* gets last 1 byte of payload */
            b = chunkqueue_get_append_buffer(con.read_queue);
            buffer_append_memory(b, pmask_data + (ex_len - 1), 1);
            buffer_append_memory(b, &additional, 1);

            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
                c = hctx.tocli->first;
                if (!buffer_is_empty(c->mem)) {
                    if (bex_len < 0x7e) {
                        CU_ASSERT_EQUAL(2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(bex_len, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[2], bex_len));
                    } else if (bex_len <= 0xffff) {
                        CU_ASSERT_EQUAL(2 + 2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0x7e, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL((bex_len >> 8) & 0xff,
                                        c->mem->ptr[2] & 0xff);
                        CU_ASSERT_EQUAL(bex_len & 0xff,
                                        c->mem->ptr[3] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[4], bex_len));
                    }
                    CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                    c->mem->ptr[0] & 0xff);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                } else {
                    CU_FAIL("not send pong");
                }
            }
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
                if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
                    c = hctx.tosrv->first;
                    if (!buffer_is_empty(c->mem)) {
                        CU_ASSERT_EQUAL(ex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                        CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr,
                                                  c->mem->used - 1));
                    } else {
                        CU_FAIL("recv no frames");
                    }
                } else {
                    c = hctx.tosrv->first;
                    if (!buffer_is_empty(c->mem)) {
                        CU_ASSERT_EQUAL(ex_len - 1 + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                        CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr,
                                                  c->mem->used - 1));
                    } else {
                        CU_FAIL("recv no frames");
                    }
                    c = c->next;
                    if (!buffer_is_empty(c->mem)) {
                        CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                        CU_ASSERT_EQUAL(0, memcmp(&pdata[ex_len - 1],
                                                  c->mem->ptr,
                                                  c->mem->used - 1));
                    } else {
                        CU_FAIL("recv no frames");
                    }
                }
#else
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(ex_len - 1 + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr,
                                              c->mem->used - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
                c = c->next;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(&pdata[ex_len - 1],
                                              c->mem->ptr,
                                              c->mem->used - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
#endif
            }
            CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            ex_len = 0;
        } else {
            buffer_append_memory(b, mask_data, sizeof(data));
            buffer_append_memory(b, &additional, 1);
            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(sizeof(data) + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(data,
                                              c->mem->ptr, sizeof(data) - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
            ex_len -= sizeof(data);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, ex_len);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            chunkqueue_reset(hctx.tosrv);
            // skip
            hctx.frame.ctl.siz = MAX_READ_LIMIT - 1;
            ex_len = MAX_READ_LIMIT - 1;
            pdata = data;
            pmask_data = mask_data;
        }
    }
}

void
_recv_long_chunk_test(char type, uint64_t ex_len) {
    handler_ctx hctx;
    connection con;
    plugin_data pd;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    const char additional = 0x00;
    unsigned char ctl;
    unsigned char len;
    const char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
    char ch, data[MAX_READ_LIMIT], mask_data[MAX_READ_LIMIT];
    char *pdata, *pmask_data;
    char rnd;
    size_t i;
    int exp_type;
    uint64_t bex_len = ex_len;

    fprintf(stderr, "check: payload size: 0x%llx\n",
            (long long unsigned int)ex_len);
    if (type == MOD_WEBSOCKET_OPCODE_TEXT ||
        type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = 'a' + (random() % 26);
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN ||
               type == MOD_WEBSOCKET_OPCODE_PING ||
               type == MOD_WEBSOCKET_OPCODE_PONG) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = random() % 0x100;
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    }

    if (type == MOD_WEBSOCKET_OPCODE_TEXT) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    } else if (type == MOD_WEBSOCKET_OPCODE_PING) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PING;
    } else if (type == MOD_WEBSOCKET_OPCODE_PONG) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
    } else if (type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    } else {
        exp_type = -1;
    }

    /* initialize */
    memset(&hctx, 0, sizeof(hctx));

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    hctx.fd = 1;
    hctx.handshake.version = 8;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.fromcli = con.read_queue;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x80 | type;
    buffer_append_memory(b, (char *)&ctl, 1);

    if (ex_len < 0x7e) {
        len = 0x80 | (ex_len &0x0ff);
    } else if (ex_len <= 0x0ffff) {
        len = 0x80 | 0x7e;
    } else {
        len = 0x80 | 0x7f;
    }
    buffer_append_memory(b, (char *)&len, 1);

    if (0x7e <= ex_len && ex_len <= 0x0ffff) {
        ch = (ex_len >> 8) & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        ch = ex_len & 0x0ff;
        buffer_append_memory(b, &ch, 1);
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
         exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING)) {
#else
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
#endif

        for (i = 7; i > 0; i--) {
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
        }
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, -1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }
    if (0x0ffff < ex_len) {
        for (i = 7; i > 0; i--) {
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
        }
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
    }

    buffer_append_memory(b, (char *)mask, sizeof(mask));

    if (ex_len == 0) {
        /* append next frame header */
        ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
        buffer_append_memory(b, (char *)&ctl, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[2] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    pmask_data = mask_data;
    pdata = data;
    bex_len = ex_len;

    if (ex_len == 1) {
        /* get 1 byte payload */
        buffer_append_memory(b, pmask_data, 1);
        /* append next frame header */
        ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
        buffer_append_memory(b, (char *)&ctl, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(1, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(*pdata & 0xff, c->mem->ptr[2] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[3] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        } else if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        } else {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
            c = hctx.tosrv->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
            } else {
                CU_FAIL("recv no frames");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    while (ex_len > 0) {
        if (ex_len < MAX_READ_LIMIT) { // lighty's MAX_READ_LIMIT
            pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
            /* gets 1 byte short payload */
            buffer_append_memory(b, pmask_data, ex_len);
            /* append next frame header */
            ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
            buffer_append_memory(b, (char *)&ctl, 1);
            buffer_append_memory(b, &additional, 1);

            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
                c = hctx.tocli->first;
                if (!buffer_is_empty(c->mem)) {
                    if (bex_len < 0x7e) {
                        CU_ASSERT_EQUAL(2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(bex_len, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[2], bex_len));
                    } else if (bex_len <= 0xffff) {
                        CU_ASSERT_EQUAL(2 + 2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0x7e, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL((bex_len >> 8) & 0xff,
                                        c->mem->ptr[2] & 0xff);
                        CU_ASSERT_EQUAL(bex_len & 0xff,
                                        c->mem->ptr[3] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[4], bex_len));
                    }
                    CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                    c->mem->ptr[0] & 0xff);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                } else {
                    CU_FAIL("not send pong");
                }
            }
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(ex_len + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr,
                                              c->mem->used - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            ex_len = 0;
        } else {
            buffer_append_memory(b, mask_data, sizeof(data));
            buffer_append_memory(b, &additional, 1);
            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(sizeof(data) + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(data, c->mem->ptr, sizeof(data)));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
            ex_len -= sizeof(data);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, ex_len);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            chunkqueue_reset(hctx.tosrv);
            b = chunkqueue_get_append_buffer(con.read_queue);
            // skip
            hctx.frame.ctl.siz = MAX_READ_LIMIT - 1;
            ex_len = MAX_READ_LIMIT - 1;
            pdata = data;
            pmask_data = mask_data;
        }
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

}

void
_recv_long_chunk_test_2(char type, uint64_t ex_len) {
    handler_ctx hctx;
    connection con;
    plugin_data pd;
    int ret;
    chunk *c = NULL;
    buffer *b = NULL;
    const char additional = 0x00;
    unsigned char ctl;
    unsigned char len;
    const char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
    char ch, data[MAX_READ_LIMIT], mask_data[MAX_READ_LIMIT];
    char *pdata, *pmask_data;
    char rnd;
    size_t i;
    int exp_type;
    uint64_t bex_len = ex_len;

    fprintf(stderr, "check: payload size: 0x%llx\n",
            (long long unsigned int)ex_len);
    if (type == MOD_WEBSOCKET_OPCODE_TEXT ||
        type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = 'a' + (random() % 26);
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN ||
               type == MOD_WEBSOCKET_OPCODE_PING ||
               type == MOD_WEBSOCKET_OPCODE_PONG) {
        for (i = 0; i < MAX_READ_LIMIT; i++) {
            rnd = random() % 0x100;
            data[i] = rnd;
        }
        memcpy(mask_data, data, sizeof(mask_data));
        mask_payload(mask_data, sizeof(mask_data), mask);
    }

    if (type == MOD_WEBSOCKET_OPCODE_TEXT) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    } else if (type == MOD_WEBSOCKET_OPCODE_BIN) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    } else if (type == MOD_WEBSOCKET_OPCODE_PING) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PING;
    } else if (type == MOD_WEBSOCKET_OPCODE_PONG) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
    } else if (type == MOD_WEBSOCKET_OPCODE_CLOSE) {
        exp_type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    } else {
        exp_type = -1;
    }

    /* initialize */
    memset(&hctx, 0, sizeof(hctx));

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    hctx.fd = 1;
    hctx.handshake.version = 8;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.fromcli = con.read_queue;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x80 | type;
    buffer_append_memory(b, (char *)&ctl, 1);

    if (ex_len < 0x7e) {
        len = 0x80 | (ex_len &0x0ff);
    } else if (ex_len <= 0x0ffff) {
        len = 0x80 | 0x7e;
    } else {
        len = 0x80 | 0x7f;
    }
    buffer_append_memory(b, (char *)&len, 1);

    if (0x7e <= ex_len && ex_len <= 0x0ffff) {
        ch = (ex_len >> 8) & 0x0ff;
        buffer_append_memory(b, &ch, 1);
        ch = ex_len & 0x0ff;
        buffer_append_memory(b, &ch, 1);
    }
#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        (exp_type == MOD_WEBSOCKET_FRAME_TYPE_TEXT ||
         exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING)) {
#else
    if (MOD_WEBSOCKET_BUFMAX < ex_len &&
        exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
#endif
        for (i = 7; i > 0; i--) {
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
        }
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, -1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }
    if (0x0ffff < ex_len) {
        for (i = 7; i > 0; i--) {
            ch = (ex_len >> (8 * i)) & 0x0ff;
            buffer_append_memory(b, &ch, 1);
        }
        ch = ex_len & 0xff;
        buffer_append_memory(b, &ch, 1);
    }
    buffer_append_memory(b, (char *)mask, sizeof(mask));

    if (ex_len == 0) {
        buffer_append_memory(b, &additional, 1);
        b = chunkqueue_get_append_buffer(con.read_queue);
        /* append next frame header */
        ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
        buffer_append_memory(b, (char *)&ctl, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
        CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[2] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        } else {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    pmask_data = mask_data;
    pdata = data;
    bex_len = ex_len;

    if (ex_len == 1) {
        buffer_append_memory(b, pmask_data, 1);
        buffer_append_memory(b, &additional, 1);

        /* append next frame header */
        b = chunkqueue_get_append_buffer(con.read_queue);
        ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
        buffer_append_memory(b, (char *)&ctl, 1);
        buffer_append_memory(b, &additional, 1);

        ret = mod_websocket_frame_recv(&hctx);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
            exp_type == -1) {
            CU_ASSERT_EQUAL(ret, -1);
            return;
        }
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(hctx.frame.state,
                        MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
        if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            c = hctx.tocli->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(2 + 1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                c->mem->ptr[0] & 0xff);
                CU_ASSERT_EQUAL(1, c->mem->ptr[1] & 0xff);
                CU_ASSERT_EQUAL(*pdata & 0xff, c->mem->ptr[2] & 0xff);
                CU_ASSERT_EQUAL(0, c->mem->ptr[3] & 0xff);
            } else {
                CU_FAIL("not send pong");
            }
        } else if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
        } else {
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 1);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
            c = hctx.tosrv->first;
            if (!buffer_is_empty(c->mem)) {
                CU_ASSERT_EQUAL(1 + 1, c->mem->used);
                CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                CU_ASSERT_EQUAL(*pdata & 0xff, *c->mem->ptr & 0xff);
            } else {
                CU_FAIL("recv no frames");
            }
        }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

        return;
    }

    while (ex_len > 0) {
        if (ex_len < MAX_READ_LIMIT) { // lighty's MAX_READ_LIMIT
            pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
            /* gets 1 byte short payload */
            buffer_append_memory(b, pmask_data, ex_len);
            buffer_append_memory(b, &additional, 1);

            /* append next frame header */
            b = chunkqueue_get_append_buffer(con.read_queue);
            ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
            buffer_append_memory(b, (char *)&ctl, 1);
            buffer_append_memory(b, &additional, 1);


            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tocli), 0);
                c = hctx.tocli->first;
                if (!buffer_is_empty(c->mem)) {
                    if (bex_len < 0x7e) {
                        CU_ASSERT_EQUAL(2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(bex_len, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[2], bex_len));
                    } else if (bex_len <= 0xffff) {
                        CU_ASSERT_EQUAL(2 + 2 + bex_len + 1, c->mem->used);
                        CU_ASSERT_EQUAL(0x7e, c->mem->ptr[1] & 0xff);
                        CU_ASSERT_EQUAL((bex_len >> 8) & 0xff,
                                        c->mem->ptr[2] & 0xff);
                        CU_ASSERT_EQUAL(bex_len & 0xff,
                                        c->mem->ptr[3] & 0xff);
                        CU_ASSERT_EQUAL(0, memcmp(data,
                                                  &c->mem->ptr[4], bex_len));
                    }
                    CU_ASSERT_EQUAL(0x80 | MOD_WEBSOCKET_OPCODE_PONG,
                                    c->mem->ptr[0] & 0xff);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                } else {
                    CU_FAIL("not send pong");
                }
            }
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(ex_len + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(pdata, c->mem->ptr,
                                              c->mem->used - 1));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, 0);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            ex_len = 0;
        } else {
            buffer_append_memory(b, mask_data, sizeof(data));
            buffer_append_memory(b, &additional, 1);
            ret = mod_websocket_frame_recv(&hctx);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_CLOSE ||
                exp_type == -1) {
                CU_ASSERT_EQUAL(ret, -1);
                return;
            }
            CU_ASSERT_EQUAL(ret, 0);
            if (exp_type == MOD_WEBSOCKET_FRAME_TYPE_PING ||
                exp_type == MOD_WEBSOCKET_FRAME_TYPE_PONG) {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
            } else {
                CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 0);
                c = hctx.tosrv->first;
                if (!buffer_is_empty(c->mem)) {
                    CU_ASSERT_EQUAL(sizeof(data) + 1, c->mem->used);
                    CU_ASSERT_EQUAL(0, c->mem->ptr[c->mem->used - 1]);
                    CU_ASSERT_EQUAL(0, memcmp(data, c->mem->ptr, sizeof(data)));
                } else {
                    CU_FAIL("recv no frames");
                }
            }
            CU_ASSERT_EQUAL(hctx.frame.state,
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
            ex_len -= sizeof(data);
            CU_ASSERT_EQUAL(hctx.frame.ctl.siz, ex_len);
            CU_ASSERT_EQUAL(chunkqueue_is_empty(con.read_queue), 1);
            chunkqueue_reset(hctx.tosrv);
            b = chunkqueue_get_append_buffer(con.read_queue);
            // skip
            hctx.frame.ctl.siz = MAX_READ_LIMIT - 1;
            ex_len = MAX_READ_LIMIT - 1;
            pdata = data;
            pmask_data = mask_data;
        }
    }

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
        mod_websocket_conv_final(hctx.cnv);
#endif

}

CU_TestFunc
mod_websocket_frame_recv_continue_test() {
    handler_ctx hctx;
    connection con;
    plugin_data pd;
    int ret;
    buffer *b = NULL;
    const char additional = 0x00;
    unsigned char ctl;
    unsigned char len;
    const char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
    char data[MAX_READ_LIMIT], mask_data[MAX_READ_LIMIT];
    char rnd;
    size_t i;

    fprintf(stderr, "check: continue frame\n");
    for (i = 0; i < MAX_READ_LIMIT; i++) {
        rnd = 'a' + (random() % 26);
        data[i] = rnd;
    }
    memcpy(mask_data, data, sizeof(mask_data));
    mask_payload(mask_data, sizeof(mask_data), mask);

    memset(&hctx, 0, sizeof(hctx));

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);
#endif

    hctx.fd = 1;
    hctx.handshake.version = 8;
    con.fd = 2;
    con.read_queue = chunkqueue_init();
    hctx.con = &con;
    hctx.fromcli = con.read_queue;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.type_before = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
    hctx.frame.payload = buffer_init();
    pd.conf.debug =  MOD_WEBSOCKET_LOG_DEBUG + 1;
    hctx.pd = &pd;

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create TEXT frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_TEXT;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_TEXT, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_TEXT, hctx.frame.type_before);

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create PING frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PING;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_PING, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_TEXT, hctx.frame.type_before);

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create CONTINUE frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_CONT;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_TEXT, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_TEXT, hctx.frame.type_before);

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create BINARY frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_BIN;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_BIN, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_BIN, hctx.frame.type_before);

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create PONG frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_PONG;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_PONG, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_BIN, hctx.frame.type_before);

    b = chunkqueue_get_append_buffer(con.read_queue);

    /* create CONTINUE frame */
    ctl = 0x80 | MOD_WEBSOCKET_OPCODE_CONT;
    buffer_append_memory(b, (char *)&ctl, 1);
    len = 0x80 | 0x7d;
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)mask, sizeof(mask));
    buffer_append_memory(b, mask_data, 0x7d);
    buffer_append_memory(b, &additional, 1);

    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_BIN, hctx.frame.type);
    CU_ASSERT_EQUAL(MOD_WEBSOCKET_FRAME_TYPE_BIN, hctx.frame.type_before);

#ifdef	_MOD_WEBSOCKET_WITH_ICU_
    mod_websocket_conv_final(hctx.cnv);
#endif

    return 0;
}

CU_TestFunc
mod_websocket_frame_recv_short_chunk_test() {
    int i;
    uint64_t len[] = {
        0, 0x1, 0x7d, 0x7e, 0xffff, 0x10000UL,
        MOD_WEBSOCKET_BUFMAX, 0xffffffffUL, 0x100000000ULL
    };

    fprintf(stderr, "check: recv short text frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(MOD_WEBSOCKET_OPCODE_TEXT, len[i]);
    }
    fprintf(stderr, "check: recv short bianry frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(MOD_WEBSOCKET_OPCODE_BIN, len[i]);
    }
    fprintf(stderr, "check: recv short ping frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(MOD_WEBSOCKET_OPCODE_PING, len[i]);
    }
    fprintf(stderr, "check: recv short pong frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(MOD_WEBSOCKET_OPCODE_PONG, len[i]);
    }
    fprintf(stderr, "check: recv short close frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(MOD_WEBSOCKET_OPCODE_CLOSE, len[i]);
    }
    fprintf(stderr, "check: recv short invalid frame in separate chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test(-1, len[i]);
    }
    return 0;
}

CU_TestFunc
mod_websocket_frame_recv_short_chunk_test_2() {
    int i;
    uint64_t len[] = {
        0, 0x1, 0x7d, 0x7e, 0xffff, 0x10000UL, 0xffffffffUL, 0x100000002ULL
    };

    fprintf(stderr, "check: recv short text frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(MOD_WEBSOCKET_OPCODE_TEXT, len[i]);
    }
    fprintf(stderr, "check: recv short bianry frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(MOD_WEBSOCKET_OPCODE_BIN, len[i]);
    }
    fprintf(stderr, "check: recv short ping frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(MOD_WEBSOCKET_OPCODE_PING, len[i]);
    }
    fprintf(stderr, "check: recv short pong frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(MOD_WEBSOCKET_OPCODE_PONG, len[i]);
    }
    fprintf(stderr, "check: recv short close frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(MOD_WEBSOCKET_OPCODE_CLOSE, len[i]);
    }
    fprintf(stderr, "check: recv short invalid frame in concat chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_short_chunk_test_2(-1, len[i]);
    }
    return 0;
}

CU_TestFunc
mod_websocket_frame_recv_long_chunk_test() {
    int i;
    uint64_t len[] = {
        0, 0x1, 0x7d, 0x7e, 0xffff, 0x10000UL, 0xffffffffUL, 0x100000002ULL
    };

    fprintf(stderr, "check: recv text frame and next header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(MOD_WEBSOCKET_OPCODE_TEXT, len[i]);
    }
    fprintf(stderr, "check: recv binary frame and header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(MOD_WEBSOCKET_OPCODE_BIN, len[i]);
    }
    fprintf(stderr, "check: recv ping frame and header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(MOD_WEBSOCKET_OPCODE_PING, len[i]);
    }
    fprintf(stderr, "check: recv pong frame and header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(MOD_WEBSOCKET_OPCODE_PONG, len[i]);
    }
    fprintf(stderr, "check: recv close frame and header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(MOD_WEBSOCKET_OPCODE_CLOSE, len[i]);
    }
    fprintf(stderr, "check: recv invalid frame and header in same buffer\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test(-1, len[i]);
    }
    return 0;
}

CU_TestFunc
mod_websocket_frame_recv_long_chunk_test_2() {
    int i;
    uint64_t len[] = {
        0, 0x1, 0x7d, 0x7e, 0xffff, 0x10000UL, 0xffffffffUL, 0x100000002ULL
    };

    fprintf(stderr, "check: recv text frame and next header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(MOD_WEBSOCKET_OPCODE_TEXT, len[i]);
    }
    fprintf(stderr, "check: recv binary frame and header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(MOD_WEBSOCKET_OPCODE_BIN, len[i]);
    }
    fprintf(stderr, "check: recv ping frame and header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(MOD_WEBSOCKET_OPCODE_PING, len[i]);
    }
    fprintf(stderr, "check: recv pong frame and header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(MOD_WEBSOCKET_OPCODE_PONG, len[i]);
    }
    fprintf(stderr, "check: recv close frame and header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(MOD_WEBSOCKET_OPCODE_CLOSE, len[i]);
    }
    fprintf(stderr, "check: recv invalid frame and header in same chunk\n");
    for (i = 0; i < sizeof(len) / sizeof(uint64_t); i++) {
        _recv_long_chunk_test_2(-1, len[i]);
    }
    return 0;
}
#endif

int
main() {
    CU_ErrorCode ret;
    CU_pSuite suite;

    ret = CU_initialize_registry();
    if (ret != CUE_SUCCESS) {
        return -1;
    }
    CU_basic_set_mode(CU_BRM_SILENT);

    suite = CU_add_suite("mod_websocket_frame_suite", NULL, NULL);
    CU_ADD_TEST(suite, mod_websocket_frame_send_test);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    CU_ADD_TEST(suite, mod_websocket_frame_recv_test);
#endif

#if defined	_MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined	_MOD_WEBSOCKET_SPEC_RFC_6455_
    CU_ADD_TEST(suite, mod_websocket_frame_recv_short_chunk_test);
    CU_ADD_TEST(suite, mod_websocket_frame_recv_short_chunk_test_2);
    CU_ADD_TEST(suite, mod_websocket_frame_recv_long_chunk_test);
    CU_ADD_TEST(suite, mod_websocket_frame_recv_long_chunk_test_2);
    CU_ADD_TEST(suite, mod_websocket_frame_recv_continue_test);
#endif

    CU_basic_run_tests();
    ret = CU_get_number_of_failures();
    if (ret != 0) {
        CU_basic_show_failures(CU_get_failure_list());
        fprintf(stderr, "\n");
    }
    return ret;
}

/* EOF */
