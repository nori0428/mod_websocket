/**
 * $Id$
 * a part of mod_websocket
 */

#include <string.h>
#include "base64.h"

static const char base64_encode_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static const char base64_decode_chars[] = {
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1,  62, - 1, - 1, - 1,  63,
	 52,  53,  54,  55,  56,  57,  58,  59,
	 60,  61, - 1, - 1, - 1,   0, - 1, - 1,
	- 1,   0,   1,   2,   3,   4,   5,   6,
	  7,   8,   9,  10,  11,  12,  13,  14,
	 15,  16,  17,  18,  19,  20,  21,  22,
	 23,  24,  25, - 1, - 1, - 1, - 1, - 1,
	- 1,  26,  27,  28,  29,  30,  31,  32,
	 33,  34,  35,  36,  37,  38,  39,  40,
	 41,  42,  43,  44,  45,  46,  47,  48,
	 49,  50,  51, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
	- 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1};

void
base64_encode(unsigned char *dst, const unsigned char *src, size_t siz) {
    unsigned long x = 0UL;
    int i = 0, l = 0;

    for (; siz > 0; src++, siz--) {
        x = x << 8 | *src;
        for (l += 8; l >= 6; l -= 6) {
            dst[i++] = base64_encode_chars[(x >> (l - 6)) & 0x3f];
        }
    }
    if (l > 0) {
        x <<= 6 - l;
        dst[i++] = base64_encode_chars[x & 0x3f];
    }
    for (; i % 4;) {
        dst[i++] = '=';
    }
    return;
}

void
base64_decode(unsigned char *dst, size_t *dstsiz, const unsigned char *src) {
    union {
        unsigned long x;
        char c[4];
    } base64;
    int i, j = 0;
    size_t srcsiz = strlen((const char *)src);

    base64.x = 0UL;
    *dstsiz = 0;
    for (; srcsiz > 0; src+=4, srcsiz-=4) {
        for (i = 0; i < 4; i++) {
            base64.x = base64.x << 6 | base64_decode_chars[src[i]];
            j += (src[i] == '=');
        }
        for (i = 3; i > j; i--, (*dstsiz)++) {
            *dst++ = base64.c[i - 1];
        }
    }
    return;
}

/* EOF */
