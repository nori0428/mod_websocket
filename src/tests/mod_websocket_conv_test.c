/**
 * $Id$
 **/

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket.h"

CU_TestFunc
mod_websocket_conv_isUTF8_test() {
    struct tstptns {
        const char *fname;
        mod_websocket_bool_t exp;
    } ptns[] = {
        {
            "mod_websocket_conv.utf8.dat",
            MOD_WEBSOCKET_TRUE
        },
        {
            "mod_websocket_conv.sjis.dat",
            MOD_WEBSOCKET_FALSE
        },
        {
            "mod_websocket_conv.euc.dat",
            MOD_WEBSOCKET_FALSE
        }
    };
    FILE *fp;
    int i;
    char buf[1024];
    size_t siz;

    for (i = 0; i < 3; i++) {
        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        siz = fread(buf, 1, sizeof(buf), fp);
        CU_ASSERT_EQUAL(mod_websocket_conv_isUTF8(buf, siz - 1),
                        ptns[i].exp);
        fclose(fp);
    }
    return 0;
}

CU_TestFunc
mod_websocket_conv_test() {
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
    int i, ret;
    char src[1024], dst1[1024], dst2[1024];
    char csrc[8192], cdst1[8192], cdst2[8192], cdst[16384];
    char *pdst;
    size_t srcsiz, dst1siz = 1024, dst2siz = 1024;
    mod_websocket_conv_t *cnv;

    for (i = 0; i < 3; i++) {
        memset(src, 0, sizeof(src));
        memset(dst1, 0, sizeof(dst1));
        memset(dst2, 0, sizeof(dst2));
        fprintf(stderr, "check: %s\n", ptns[i].fname);
        fp = fopen(ptns[i].fname, "r");
        srcsiz = fread(src, 1, sizeof(src), fp);
        fclose(fp);
        src[srcsiz] = '\0';

        cnv = mod_websocket_conv_init(ptns[i].locale);
        if (!cnv) {
            CU_FAIL("init failed");
            return 0;
        }

        dst1siz = 1024;
        ret = mod_websocket_conv_to_client(cnv, dst1, &dst1siz, src, srcsiz);
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(mod_websocket_conv_isUTF8(dst1, strlen(dst1)),
                        MOD_WEBSOCKET_TRUE);

        dst2siz = 1024;
        ret = mod_websocket_conv_to_server(cnv, dst2, &dst2siz, dst1, dst1siz);
        CU_ASSERT_EQUAL(ret, 0);
        CU_ASSERT_EQUAL(mod_websocket_conv_isUTF8(dst2, dst2siz),
                        ptns[i].exp);
        CU_ASSERT_EQUAL(memcmp(src, dst2, dst2siz), 0);
        mod_websocket_conv_final(cnv);
    }
    /* test chunk */
    /*
     * But if multibyte chars are chunked,
     * a websocket frame may be invalid...
     */
    cnv = mod_websocket_conv_init(ptns[0].locale);
    if (!cnv) {
        CU_FAIL("init failed");
        return 0;
    }
    memset(src, 0, sizeof(src));
    memset(csrc, 0, sizeof(csrc));
    memset(cdst, 0, sizeof(cdst));
    memset(cdst1, 0, sizeof(cdst1));
    memset(cdst2, 0, sizeof(cdst2));
    fprintf(stderr, "check chunked: %s\n", ptns[0].fname);
    fp = fopen(ptns[0].fname, "r");
    srcsiz = fread(src, 1, sizeof(src), fp);
    fclose(fp);
    src[srcsiz] = '\0';
    for (i = 0; i < srcsiz * 5; i += srcsiz) {
        memcpy(csrc + i, src, srcsiz);
    }
    csrc[i] = '\0';
    srcsiz = i;
    dst1siz = sizeof(cdst1);
    ret = mod_websocket_conv_to_client(cnv, cdst1, &dst1siz, csrc, srcsiz / 2);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(mod_websocket_conv_isUTF8(cdst1, dst1siz),
                    MOD_WEBSOCKET_TRUE);
    memcpy(cdst, cdst1, dst1siz);
    pdst = cdst + dst1siz;
    dst1siz = sizeof(cdst2);
    ret = mod_websocket_conv_to_client(cnv, cdst2, &dst1siz,
                                       csrc + srcsiz / 2, srcsiz - srcsiz / 2);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_EQUAL(mod_websocket_conv_isUTF8(cdst, dst1siz),
                    MOD_WEBSOCKET_TRUE);
    memcpy(pdst, cdst2, dst1siz);
    *(pdst + dst1siz) = '\0';
    for (i = 0; i < srcsiz; i++) {
        if (cdst[i] != csrc[i]) {
            CU_ASSERT_EQUAL(cdst[i], csrc[i]);
            fprintf(stderr, "%02x = %02x, ", cdst[i] & 0xff, csrc[i] & 0xff);
        }
    }
    mod_websocket_conv_final(cnv);
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
    suite = CU_add_suite("mod_websocket_conv_suite", NULL, NULL);
    CU_ADD_TEST(suite, mod_websocket_conv_isUTF8_test);
    CU_ADD_TEST(suite, mod_websocket_conv_test);
    CU_basic_run_tests();
    ret = CU_get_number_of_failures();
    if (ret != 0) {
        CU_basic_show_failures(CU_get_failure_list());
        fprintf(stderr, "\n");
    }
    return ret;
}

/* EOF */

