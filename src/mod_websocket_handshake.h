/**
 * $Id$
 * a part of mod_websocket
 */

#ifndef	_MOD_WEBSOCKET_HANDSHAKE_H_
#define	_MOD_WEBSOCKET_HANDSHAKE_H_

#include "mod_websocket_new.h"

#ifdef	__cplusplus
extern "C" {
#endif

    mod_websocket_errno_t check_request(handler_ctx *);
    mod_websocket_errno_t create_response(handler_ctx *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MOD_WEBSOCKET_HANDSHAKE_H_ */
