#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "mod_websocket_base64.h"

int
main(int argc, char *argv[]) {
    FILE *fp;
    size_t srcsiz, dstsiz;
    unsigned char *src, *dst;

    fp = fopen(argv[1], "r");
    fseek(fp, 0, SEEK_END);
    srcsiz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    src = (unsigned char *)malloc(srcsiz);

    fread(src, srcsiz, 1, fp);
    mod_websocket_base64_encode(&dst, &dstsiz, src, srcsiz);
    fprintf(stdout, "%s", dst);
    fclose(fp);

    free(src);
    free(dst);

    return 0;
}
