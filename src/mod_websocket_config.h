/**
 * a part of mod_websocket
 **/

#ifndef _MOD_WEBSOCKET_CONFIG_H_
#define _MOD_WEBSOCKET_CONFIG_H_

// a key of environment var
#define	MOD_WEBSOCKET_CONFIG_PATH	"MOD_WEBSOCKET_CONFIG_PATH"

typedef enum {
    HOST,
    PORT,
    TYPE,
    SUBPROTO,
    LOCALE,
    ORIGINS,
    PROTO
} mod_websocket_key_t;

typedef struct {
    mod_websocket_key_t key;
    void *val;
} mod_websocket_assign_t;

typedef struct _mod_websocket_origin_list_t {
    char *origin;
    struct _mod_websocket_origin_list_t *next;
} mod_websocket_origin_t;

typedef struct _mod_websocket_backend_t {
    char *host;					// IPAddr or FQDN
    int port;					// port number
    int type;					// 0: text, 1: binary
    char *subproto;				// null if not set
    mod_websocket_origin_t *origins;		// null if not set
    char *locale;				// null if not set
    struct _mod_websocket_backend_t *next;	// exists at least 1 object
    char *proto;				// "websocket" or null if not set.
} mod_websocket_backend_t;

typedef struct _mod_websocket_resource_t {
    char *key;
    mod_websocket_backend_t *backends;
    struct _mod_websocket_resource_t *next;
} mod_websocket_resource_t;

typedef struct {
    mod_websocket_resource_t *resources;
    int ping_interval;
    int timeout;
    int debug;
} mod_websocket_config_t;

#ifdef  __cplusplus
extern "C" {
#endif

    mod_websocket_config_t *mod_websocket_config_parse(const char *);
    void mod_websocket_config_free(mod_websocket_config_t *);
    void mod_websocket_config_print(mod_websocket_config_t *);

#ifdef  __cplusplus
}
#endif

#endif /* _MOD_WEBSOCKET_CONFIG_H_ */
