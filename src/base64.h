/**
 * $Id$
 * a part of mod_websocket
 */

#ifndef	_MOD_WEBSOCKET_BASE64_H_
#define	_MOD_WEBSOCKET_BASE64_H_

#include "stdio.h"

#ifdef	__cplusplus
extern "C" {
#endif

    int base64_encode(unsigned char **, size_t *, const unsigned char *, size_t);
    int base64_decode(unsigned char **, size_t *, const unsigned char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MOD_WEBSOCKET_BASE64_H_ */

/* EOF */
