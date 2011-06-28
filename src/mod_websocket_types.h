/**
 * $Id$
 * a part of mod_websocket
 **/

#ifndef	_MOD_WEBSOCKET_TYPES_H_
#define	_MOD_WEBSOCKET_TYPES_H_

#define	MOD_WEBSOCKET_UTF8_STR	"UTF-8"

#define	MOD_WEBSOCKET_TRUE	(1)
#define	MOD_WEBSOCKET_FALSE	(0)

typedef unsigned char mod_websocket_bool_t;

typedef enum {
    MOD_WEBSOCKET_NOT_WEBSOCKET		= -1,
    MOD_WEBSOCKET_OK			= 200,
    MOD_WEBSOCKET_BAD_REQUEST		= 400,
    MOD_WEBSOCKET_FORBIDDEN		= 403,
    MOD_WEBSOCKET_NOT_FOUND		= 404,
    MOD_WEBSOCKET_INTERNAL_SERVER_ERROR	= 500,
    MOD_WEBSOCKET_SERVICE_UNAVAILABLE	= 503,
} mod_websocket_errno_t;

#endif	/* _MOD_WEBSOCKET_TYPES_H_ */
