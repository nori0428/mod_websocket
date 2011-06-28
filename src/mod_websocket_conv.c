/**
 * $Id$
 * a part of mod_websocket
 */

#include <stdlib.h>
#include <string.h>
#include <unicode/ucsdet.h>

#include "mod_websocket_conv.h"

static int mod_websocket_conv(UConverter *, UConverter *,
                              char *, size_t, const char *, size_t);

inline int
mod_websocket_conv(UConverter *to, UConverter *from,
                   char *dst, size_t dstlen,
                   const char *src, size_t srclen) {
    UErrorCode err = U_ZERO_ERROR;
    size_t unisiz, convlen;
    UChar *unibuf, *punibuf, *ppunibuf;

    if (!to || !from || !dst || !src) {
        return -1;
    }
    if (!srclen) {
        memset(dst, 0, dstlen);
        return 0;
    }
    unisiz = srclen / ucnv_getMinCharSize(from);
    unibuf = (UChar *)malloc(unisiz);
    if (!unibuf) {
        return -1;
    }
    punibuf = unibuf;
    ucnv_toUnicode(from, &punibuf, punibuf + unisiz,
                   &src, src + srclen, 0, 1, &err);
    if (U_FAILURE(err)) {
        free(unibuf);
        return -1;
    }
    convlen = (punibuf - unibuf) * ucnv_getMaxCharSize(to);
    if (convlen > dstlen) {
        free(unibuf);
        return -1;
    }
    ppunibuf = unibuf;
    ucnv_fromUnicode(to, &dst, dst + dstlen,
                     (const UChar **)&ppunibuf, punibuf, 0, 1, &err);
    free(unibuf);
    if (U_FAILURE(err)) {
        return -1;
    }
    *dst = '\0';
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
mod_websocket_isUTF8(const char *data, size_t siz) {
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
                             char *dst, size_t dstlen,
                             const char *src, size_t srclen) {
    if (mod_websocket_isUTF8(src, srclen) == MOD_WEBSOCKET_TRUE) {
        if (dstlen < srclen) {
            return -1;
        }
        memset(dst, 0, dstlen);
        if (srclen) {
            memcpy(dst, src, srclen);
        }
        return 0;
    }
    return mod_websocket_conv(cnv->cli, cnv->srv, dst, dstlen, src, srclen);
}

int
mod_websocket_conv_to_server(mod_websocket_conv_t *cnv,
                             char *dst, size_t dstlen,
                             const char *src, size_t srclen) {
    return mod_websocket_conv(cnv->srv, cnv->cli, dst, dstlen, src, srclen);
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
