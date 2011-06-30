/**
 * $Id$
 * a part of mod_websocket
 */

#include <stdlib.h>
#include <string.h>
#include <unicode/ucsdet.h>

#include "mod_websocket_new.h"

static int mod_websocket_conv(UConverter *, UConverter *,
                              char *, size_t *, const char *, size_t);

inline int
mod_websocket_conv(UConverter *to, UConverter *from,
                   char *dst, size_t *dstsiz,
                   const char *src, size_t srcsiz) {
    UErrorCode err = U_ZERO_ERROR;
    size_t unisiz, convsiz;
    UChar *unibuf, *punibuf, *ppunibuf;
    char *pdst;

    if (!to || !from || !dst || !src || !dstsiz || !*dstsiz) {
        return -1;
    }
    if (!srcsiz) {
        memset(dst, 0, *dstsiz);
        return 0;
    }
    unisiz = srcsiz / ucnv_getMinCharSize(from);
    unibuf = (UChar *)malloc(sizeof(UChar) * unisiz);
    if (!unibuf) {
        return -1;
    }
    punibuf = unibuf;
    ucnv_toUnicode(from, &punibuf, punibuf + unisiz,
                   &src, src + srcsiz, 0, 1, &err);
    if (U_FAILURE(err)) {
        free(unibuf);
        return -1;
    }
    convsiz = (punibuf - unibuf) * ucnv_getMaxCharSize(to);
    if (convsiz > *dstsiz) {
        free(unibuf);
        return -1;
    }
    ppunibuf = unibuf;
    pdst = dst;
    ucnv_fromUnicode(to, &pdst, pdst + *dstsiz,
                     (const UChar **)&ppunibuf, punibuf, 0, 1, &err);
    free(unibuf);
    if (U_FAILURE(err)) {
        return -1;
    }
    *pdst = '\0';
    *dstsiz = pdst - dst;
    return 0;
}

mod_websocket_conv_t *
mod_websocket_conv_init(const char *locale) {
    mod_websocket_conv_t *cnv;
    UErrorCode err = U_ZERO_ERROR;

    if (!locale) {
        return NULL;
    }
    cnv = (mod_websocket_conv_t *)malloc(sizeof(mod_websocket_conv_t));
    if (!cnv) {
        return NULL;
    }
    cnv->cli = ucnv_open(MOD_WEBSOCKET_UTF8_STR, &err);
    if (U_FAILURE(err)) {
        free(cnv);
        return NULL;
    }
    cnv->srv = ucnv_open(locale, &err);
    if (U_FAILURE(err)) {
        ucnv_close(cnv->cli);
        free(cnv);
        return NULL;
    }
    return cnv;
}

mod_websocket_bool_t
mod_websocket_conv_isUTF8(const char *data, size_t siz) {
    mod_websocket_bool_t ret = MOD_WEBSOCKET_FALSE;
    UErrorCode err = U_ZERO_ERROR;
    UCharsetDetector *detector;
    const UCharsetMatch **match;
    int32_t f = 0, i;
    const char *name;

    if (!data || !siz) {
        return MOD_WEBSOCKET_TRUE;
    }
    if (siz > INT32_MAX) {
        return MOD_WEBSOCKET_FALSE;
    }
    detector = ucsdet_open(&err);
    if (U_FAILURE(err)) {
        return MOD_WEBSOCKET_FALSE;
    }
    ucsdet_setText(detector, data, siz, &err);
    if (U_FAILURE(err)) {
        goto go_out;
    }
    match = ucsdet_detectAll(detector, &f, &err);
    if (U_FAILURE(err)) {
        goto go_out;
    }
    for (i = 0; i < f; i++) {
        name = ucsdet_getName(match[i], &err);
        if (strcasecmp(MOD_WEBSOCKET_UTF8_STR, name) == 0) {
            ret = MOD_WEBSOCKET_TRUE;
            break;
        }
    }

 go_out:
    ucsdet_close(detector);
    return ret;
}

int
mod_websocket_conv_to_client(mod_websocket_conv_t *cnv,
                             char *dst, size_t *dstsiz,
                             const char *src, size_t srcsiz) {
    if (mod_websocket_conv_isUTF8(src, srcsiz) == MOD_WEBSOCKET_TRUE) {
        if (*dstsiz < srcsiz) {
            return -1;
        }
        memset(dst, 0, *dstsiz);
        if (srcsiz) {
            memcpy(dst, src, srcsiz);
        }
        *dstsiz = srcsiz;
        return 0;
    }
    return mod_websocket_conv(cnv->cli, cnv->srv, dst, dstsiz, src, srcsiz);
}

int
mod_websocket_conv_to_server(mod_websocket_conv_t *cnv,
                             char *dst, size_t *dstsiz,
                             const char *src, size_t srcsiz) {
    return mod_websocket_conv(cnv->srv, cnv->cli, dst, dstsiz, src, srcsiz);
}

void
mod_websocket_conv_final(mod_websocket_conv_t *cnv) {
    if (cnv) {
        if (cnv->cli) {
            ucnv_close(cnv->cli);
            cnv->cli = NULL;
        }
        if (cnv->srv) {
            ucnv_close(cnv->srv);
            cnv->srv = NULL;
        }
        free(cnv);
        cnv = NULL;
    }
    return;
}

/* EOF */
