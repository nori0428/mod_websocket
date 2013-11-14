#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mod_websocket_base64.h"

int
main(int argc, char *argv[]) {
    FILE *fp;
    size_t siz, dstsiz, revsiz;
    unsigned char *src, *dst, *rev;
    int i, ret;

    fp = fopen(argv[1], "r");
    fseek(fp, 0, SEEK_END);
    siz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    src = (unsigned char *)malloc(siz);
    fread(src, siz, 1, fp);
    mod_websocket_base64_encode(&dst, &dstsiz, src, siz);
    fclose(fp);
    ret = mod_websocket_base64_decode(&rev, &revsiz, dst);
    assert(ret == 0);

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
