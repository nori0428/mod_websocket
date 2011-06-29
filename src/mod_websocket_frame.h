/**
 * $Id$
 * a part of mod_websocket
 */

#ifndef	_MOD_WEBSOCKET_FRAME_H_
#define	_MOD_WEBSOCKET_FRAME_H_

#include "mod_websocket_new.h"

#ifdef	__cplusplus
extern "C" {
#endif

    int mod_websocket_frame_send(handler_ctx *,
                                 mod_websocket_frame_type_t,
                                 char *, size_t);
    int mod_websocket_frame_recv(handler_ctx *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MOD_WEBSOCKET_FRAME_H_ */
