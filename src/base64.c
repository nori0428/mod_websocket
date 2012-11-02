/*
 * $Id$
 *
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the 'incremental' nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdlib.h>

#include "base64.h"

static const char base64_encode_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static const signed char base64_decode_chars[] = {
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

int
base64_encode(unsigned char **dst, size_t *dstsiz, const unsigned char *src, size_t srcsiz) {
    unsigned long x = 0UL;
    int i = 0, l = 0;
    unsigned char *pdst;

    *dst = (unsigned char *)malloc(srcsiz * 2);
    if (!*dst) {
        return -1;
    }
    pdst = *dst;
    *dstsiz = 0;
    for (; srcsiz > 0; src++, srcsiz--) {
        x = x << 8 | *src;
        for (l += 8; l >= 6; l -= 6) {
            pdst[i++] = base64_encode_chars[(x >> (l - 6)) & 0x3f];
        }
    }
    if (l > 0) {
        x <<= 6 - l;
        pdst[i++] = base64_encode_chars[x & 0x3f];
    }
    for (; i % 4;) {
        pdst[i++] = '=';
    }
    *dstsiz = i;
    pdst[i] = '\0';
    return 0;
}

int
base64_decode(unsigned char **dst, size_t *dstsiz, const unsigned char *src) {
    union {
        unsigned long x;
        char c[4];
    } base64;
    unsigned char *pdst;
    int i, j = 0;
    size_t srcsiz = strlen((const char *)src);

    if ((srcsiz % 4) != 0) {
        return -1;
    }
    base64.x = 0UL;
    *dst = (unsigned char *)malloc(srcsiz);
    if (!*dst) {
        return -1;
    }
    pdst = *dst;
    *dstsiz = 0;
    for (; srcsiz > 0; src+=4, srcsiz-=4) {
        for (i = 0; i < 4; i++) {
            if (base64_decode_chars[src[i]] == -1) {
                return -1;
            }
            base64.x = base64.x << 6 | base64_decode_chars[src[i]];
            j += (src[i] == '=');
        }
        for (i = 3; i > j; i--, (*dstsiz)++) {
            *pdst++ = base64.c[i - 1];
        }
    }
    *pdst = '\0';
    return 0;
}
