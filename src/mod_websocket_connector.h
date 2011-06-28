/**
 * $Id$
 * a part of mod_websocket
 */

#ifndef	_MOD_WEBSOCKET_CONNECTOR_H_
#define	_MOD_WEBSOCKET_CONNECTOR_H_

#ifdef	__cplusplus
extern "C" {
#endif

    int mod_websocket_tcp_server_connect(const char *, const char *);
    void mod_websocket_tcp_server_disconnect(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _MOD_WEBSOCKET_CONNECTOR_H_ */
