/**
 * $Id$
 * a part of mod_websocket
 **/

#ifndef _MOD_WEBSOCKET_CONV_H_
#define _MOD_WEBSOCKET_CONV_H_

#include <unicode/ucnv.h>

#include "mod_websocket_types.h"

typedef struct _mod_websocket_conv_t {
    UConverter *cli;
    UConverter *srv;
} mod_websocket_conv_t;

#ifdef __cplusplus
extern "C" {
#endif

    mod_websocket_conv_t *mod_websocket_conv_init(const char *);
    mod_websocket_bool_t mod_websocket_isUTF8(const char *, size_t);
    int mod_websocket_conv_to_client(mod_websocket_conv_t *,
                                     char *, size_t, const char *, size_t);
    int mod_websocket_conv_to_server(mod_websocket_conv_t *,
                                     char *, size_t, const char *, size_t);
    void mod_websocket_conv_final(mod_websocket_conv_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MOD_WEBSOCKET_BASE64_H_ */

