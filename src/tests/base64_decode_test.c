/**
 * $Id$
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "base64.h"

int
main(int argc, char *argv[]) {
    FILE *fp;
    size_t siz, revsiz;
    unsigned char *src, *dst, *rev;
    int i;

    fp = fopen(argv[1], "r");
    fseek(fp, 0, SEEK_END);
    siz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    src = (unsigned char *)malloc(siz);
    dst = (unsigned char *)malloc(siz * 2);
    rev = (unsigned char *)malloc(siz);
    memset(dst, 0, siz * 2);

    fread(src, siz, 1, fp);
    base64_encode(dst, src, siz);
    fclose(fp);
    base64_decode(rev, &revsiz, dst);

    for (i = 0; i < siz; i++) {
        if (src[i] != rev[i]) {
            fprintf(stderr, "diff[%d]: src=%d, rev=%d\n", i, src[i], rev[i]);
        }
    }
    if (memcmp(src, rev, revsiz) != 0 || revsiz != siz) {
        assert(0);
    }
    free(src);
    free(dst);
    free(rev);

    return 0;
}

/* EOF */
