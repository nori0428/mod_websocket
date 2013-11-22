#include <stdio.h>

#include "mod_websocket_config.h"

#if defined (DEBUG_LEX)

extern int yylex();
extern FILE *yyin;

int main(int argc, char **argv) {
    FILE *input_file = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s config_file_path\n", *argv);
        return -1;
    }
    if ((input_file = fopen(*++argv, "r")) == NULL) {
        fprintf(stderr, "Can't open %s.\n", *argv);
        return -1;
    }
    yyin = input_file;
    yylex();
    return 0;
}
#else
int main(int argc, char **argv) {
    mod_websocket_config_t* config = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s config_file_path\n", *argv);
        return -1;
    }
    if ((config = mod_websocket_config_parse(*++argv)) != NULL) {
        mod_websocket_config_print(config);
        mod_websocket_config_free(config);
        fprintf(stderr, "\nconfigration is OK!\n");
    } else {
        fprintf(stderr, "\nconfigration is invalid!\n");
    }
    return 0;
}
#endif
