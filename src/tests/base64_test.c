/**
 * $Id$
 **/

#include <stdio.h>
#include <stdlib.h>

#include "base64.h"

int
main(int argc, char *argv[]) {
    FILE *fp;
    size_t siz;
    unsigned char *src, *dst;

    fp = fopen(argv[1], "r");
    fseek(fp, 0, SEEK_END);
    siz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    src = (unsigned char *)malloc(siz);
    dst = (unsigned char *)malloc(siz * 2);

    fread(src, siz, 1, fp);
    base64_encode(dst, src, siz);
    fprintf(stdout, "%s", dst);
    fclose(fp);
    return 0;
}

/* EOF */
