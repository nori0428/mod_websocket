/**
 * $Id$
 * a part of mod_websocket
 */

#include "base64.h"

static const char base64_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void
base64_encode(unsigned char *dst, const unsigned char *src, size_t siz) {
    unsigned long x = 0UL;
    int i = 0, l = 0;

    for (; siz > 0; src++, siz--) {
        x = x << 8 | *src;
        for (l += 8; l >= 6; l -= 6) {
            dst[i++] = base64_chars[(x >> (l - 6)) & 0x3f];
        }
    }
    if (l > 0) {
        x <<= 6 - l;
        dst[i++] = base64_chars[x & 0x3f];
    }
    for (; i % 4;) {
        dst[i++] = '=';
    }
    return;
}

/* EOF */
