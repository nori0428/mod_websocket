/**
 * $Id$
 **/

#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket_frame.h"

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
    char buf[1024];
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
    CU_ASSERT_EQUAL(b->used - 2, strlen(ASCII_STR));
    if (b->ptr[0] != 0x00) {
        CU_FAIL("frame start bit invalid");
    }
    if (b->ptr[b->used - 1] != -1) {
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
            if (b->ptr[b->used - 1] != -1) {
                CU_FAIL("frame end bit invalid");
            }
            buffer_free(b);
            b = NULL;
        } else {
            CU_FAIL("send buffer is empty");
        }
        mod_websocket_conv_final(hctx.cnv);
    }
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    CU_FAIL("no tests exist");
#endif
    return 0;
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

    fprintf(stderr, "check recv\n");
    memset(&hctx, 0, sizeof(hctx));
    hctx.tosrv = chunkqueue_init();
    hctx.tocli = chunkqueue_init();
    con.read_queue = hctx.tocli;
    hctx.con = &con;
    hctx.frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx.frame.payload.data = buffer_init();
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
            buffer_copy_memory(b, c->mem->ptr, c->mem->used);
        } else {
            buffer_append_memory(b, c->mem->ptr, c->mem->used);
        }
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
                buffer_copy_memory(b, c->mem->ptr, c->mem->used);
            } else {
                buffer_append_memory(b, c->mem->ptr, c->mem->used);
            }
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
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    CU_FAIL("no tests exist");
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
