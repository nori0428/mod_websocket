/**
 * $Id$
 **/

#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket_new.h"

#define	ASCII_STR	"Hello"

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
    pd.conf.debug = 1;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    CU_ASSERT_NOT_EQUAL(NULL, hctx.cnv);

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
    mod_websocket_conv_final(hctx.cnv);

    for (i = 0; i < 3; i++) {
        chunkqueue_reset(hctx.tocli);
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);
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
        mod_websocket_conv_final(hctx.cnv);
    }

    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
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
    CU_ASSERT_EQUAL(b->used, strlen(ASCII_STR) + 2);
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
    mod_websocket_conv_final(hctx.cnv);

    for (i = 0; i < 3; i++) {
        fprintf(stderr, "check: %s\n", ptns[i].fname);
        chunkqueue_reset(hctx.tocli);
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);
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
        mod_websocket_conv_final(hctx.cnv);
    }

    fprintf(stderr, "check: BINARY\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
    CU_ASSERT_EQUAL(b->used, 7);
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
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: PING\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PING,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 7);
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
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: PONG\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 7);
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
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: close\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                   NULL, 0);
    CU_ASSERT_EQUAL(ret, 0);

    for (c = hctx.tocli->first; c; c = c->next) {
        if (NULL == b) {
            b = buffer_init();
        }
        buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
    CU_ASSERT_EQUAL(b->used, 2);
    if ((b->ptr[0] & 0xff) != 0x88) {
        CU_FAIL("opcode invalid");
    }
    if (b->ptr[1] != 0x00) {
        CU_FAIL("payload length invalid");
    }
    buffer_free(b);
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: 16bit length TEXT\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
    CU_ASSERT_EQUAL(b->used, sizeof(buf) + 4);
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
        fprintf(stderr, "%lu\n", siz);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 4, buf, sizeof(buf)), 0);
    buffer_free(b);
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: 16bit length BINARY\n");
    chunkqueue_reset(hctx.tocli);
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
    CU_ASSERT_EQUAL(b->used, sizeof(buf) + 4);
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
        fprintf(stderr, "%lu\n", siz);
    }
    CU_ASSERT_EQUAL(memcmp(b->ptr + 4, buf, sizeof(buf)), 0);
    buffer_free(b);
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);
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

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    const unsigned char head = 0x00;
    const unsigned char tail = 0xff;
    const unsigned char cfrm[2] = { 0xff, 0x00 };
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    unsigned char ctl;
    unsigned char len;
    unsigned char ex_len;
    const char nomask[4] = { 0x00, 0x00, 0x00, 0x00 };
    const char mask[4] = { 0x11, 0x11, 0x11, 0x11 };
    char enc[4096];
    size_t encsiz;
#endif

    fprintf(stderr, "check recv\n");
    memset(&hctx, 0, sizeof(hctx));
    hctx.tosrv = chunkqueue_init();
    hctx.tocli = chunkqueue_init();
    con.read_queue = hctx.tocli;
    hctx.con = &con;
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.payload = buffer_init();
    pd.conf.debug = 1;
    hctx.pd = &pd;

    hctx.cnv = mod_websocket_conv_init("UTF-8");
    ret = mod_websocket_frame_recv(NULL);
    CU_ASSERT_EQUAL(ret, -1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    fprintf(stderr, "check: ASCII\n");
    ret = mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                   ASCII_STR, strlen(ASCII_STR));
    CU_ASSERT_EQUAL(ret, 0);
    ret = mod_websocket_frame_recv(&hctx);
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
        mod_websocket_conv_final(hctx.cnv);
    } else {
        CU_FAIL("recv no frames");
    }

    for (i = 0; i < 3; i++) {
        chunkqueue_reset(hctx.tosrv);
        chunkqueue_reset(hctx.tocli);
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);

        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        memset(buf, 0, sizeof(buf));
        siz = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);

        ret = mod_websocket_frame_send(&hctx,
                                       MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                       buf, siz);
        CU_ASSERT_EQUAL(ret, 0);
        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
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
    }

    /* recv payload * 2 */
    fprintf(stderr, "check: double payload\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
        if (memcmp(b->ptr, ASCII_STR ASCII_STR, strlen(ASCII_STR) * 2) != 0 ||
            b->used != strlen(ASCII_STR) * 2) {
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

    /* recv chunk */
    fprintf(stderr, "check: chunk\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
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
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR)) {
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
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    chunkqueue_reset(hctx.tosrv);
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
    if (!buffer_is_empty(b)) {
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR)) {
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

    /* recv close */
    fprintf(stderr, "check: close\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, (char *)cfrm, sizeof(cfrm));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, -1);
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    fprintf(stderr, "check: ASCII\n");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x81; // TEXT
    len = 0x80 | strlen(ASCII_STR);
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
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
        CU_ASSERT_EQUAL(memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)), 0);
        buffer_free(b);
    } else {
        CU_FAIL("recv no frames");
    }
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

    for (i = 0; i < 3; i++) {
        chunkqueue_reset(hctx.tosrv);
        chunkqueue_reset(con.read_queue);
        hctx.cnv = mod_websocket_conv_init(ptns[i].locale);

        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        memset(buf, 0, sizeof(buf));
        siz = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);

        encsiz = 4096;
        mod_websocket_conv_to_client(hctx.cnv, enc, &encsiz, buf, siz);
        b = chunkqueue_get_append_buffer(con.read_queue);
        ctl = 0x81; // TEXT
        len = 0x80 | encsiz;
        buffer_append_memory(b, (char *)&ctl, 1);
        buffer_append_memory(b, (char *)&len, 1);
        buffer_append_memory(b, (char *)mask, sizeof(mask));
        mask_payload(enc, encsiz, mask);
        buffer_append_memory(b, enc, encsiz);
        ret = mod_websocket_frame_recv(&hctx);
        CU_ASSERT_EQUAL(ret, 0);
        mod_websocket_conv_final(hctx.cnv);
        b = NULL;

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
    }

    /* binary */
    fprintf(stderr, "check: BINARY\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x82; // BIN
    memset(buf, 0x00, 5);
    len = 0x80 | 5;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, buf, 5);
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
        CU_ASSERT_EQUAL(memcmp(b->ptr, buf, 5), 0);
        buffer_free(b);
    } else {
        CU_FAIL("recv no frames");
    }
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

    /* recv payload * 2 */
    fprintf(stderr, "check: double payload\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x81; // TEXT
    len = 0x80 | strlen(ASCII_STR);
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
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
        if (memcmp(b->ptr, ASCII_STR ASCII_STR, strlen(ASCII_STR) * 2) != 0 ||
            b->used != strlen(ASCII_STR) * 2) {
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

    /* recv chunk */
    fprintf(stderr, "check: chunk\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x81; // TEXT
    len = 0x80 | strlen(ASCII_STR);
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR) - 1);
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
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR)) {
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
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD);
    b = chunkqueue_get_append_buffer(con.read_queue);
    buffer_append_memory(b, "o", 1);
    chunkqueue_reset(hctx.tosrv);
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
        if (memcmp(b->ptr, ASCII_STR, strlen(ASCII_STR)) != 0 ||
            b->used != strlen(ASCII_STR)) {
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

    /* recv ping */
    fprintf(stderr, "check: ping w/o body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x89; // PING
    len = 0x80;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: ping w/ body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x89; // PING
    len = 0x80 | strlen(ASCII_STR);
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    /* recv pong */
    fprintf(stderr, "check: pong w/o body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x8a; // PONG
    len = 0x80;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: pong w/ body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x8a; // PONG
    len = 0x80 | strlen(ASCII_STR);
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    /* recv close */
    fprintf(stderr, "check: close w/o body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x88; // CLOSE
    len = 0x80;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, -1);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    fprintf(stderr, "check: close w/ body\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x88; // CLOSE
    len = 0x80;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    buffer_append_memory(b, ASCII_STR, strlen(ASCII_STR));
    ret = mod_websocket_frame_recv(&hctx);
    CU_ASSERT_EQUAL(ret, -1);
    CU_ASSERT_EQUAL(hctx.frame.state, MOD_WEBSOCKET_FRAME_STATE_INIT);
    CU_ASSERT_EQUAL(buffer_is_empty(hctx.frame.payload), 1);
    CU_ASSERT_EQUAL(chunkqueue_is_empty(hctx.tosrv), 1);
    mod_websocket_conv_final(hctx.cnv);

    /* recv 16bit length text */
    fprintf(stderr, "check: 16bits length TEXT\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x81; // TEXT
    memset(buf, 'a', sizeof(buf));
    len = 0x80 | 0x7E;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    ex_len = (sizeof(buf) >> 8) & 0xff;
    buffer_append_memory(b, (char *)&ex_len, 1);
    ex_len = sizeof(buf) & 0xff;
    buffer_append_memory(b, (char *)&ex_len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, buf, sizeof(buf));
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
        CU_ASSERT_EQUAL(memcmp(b->ptr, buf, sizeof(buf)), 0);
        buffer_free(b);
    } else {
        CU_FAIL("recv no frames");
    }
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

    /* recv 16bit length binary */
    fprintf(stderr, "check: 16bits length BINARY\n");
    hctx.cnv = mod_websocket_conv_init("UTF-8");
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    buffer_reset(hctx.frame.payload);
    chunkqueue_reset(hctx.tosrv);
    chunkqueue_reset(con.read_queue);

    b = chunkqueue_get_append_buffer(con.read_queue);
    ctl = 0x82; // BIN
    memset(buf, 0x01, sizeof(buf));
    len = 0x80 | 0x7E;
    buffer_append_memory(b, (char *)&ctl, 1);
    buffer_append_memory(b, (char *)&len, 1);
    ex_len = (sizeof(buf) >> 8) & 0xff;
    buffer_append_memory(b, (char *)&ex_len, 1);
    ex_len = sizeof(buf) & 0xff;
    buffer_append_memory(b, (char *)&ex_len, 1);
    buffer_append_memory(b, (char *)nomask, sizeof(nomask));
    buffer_append_memory(b, buf, sizeof(buf));
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
        CU_ASSERT_EQUAL(memcmp(b->ptr, buf, sizeof(buf)), 0);
        buffer_free(b);
    } else {
        CU_FAIL("recv no frames");
    }
    b = NULL;
    mod_websocket_conv_final(hctx.cnv);

#endif
    return 0;
}

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
    CU_ADD_TEST(suite, mod_websocket_frame_recv_test);
    CU_basic_run_tests();
    ret = CU_get_number_of_failures();
    if (ret != 0) {
        CU_basic_show_failures(CU_get_failure_list());
        fprintf(stderr, "\n");
    }
    return ret;
}

/* EOF */
