/**
 * $Id$
 * a part of mod_websocket
 **/

#include <ctype.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "mod_websocket.h"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# include "md5.h"

# if defined (LIGHTTPD_VERSION_ID) && \
    (LIGHTTPD_VERSION_ID >= (1 << 16 | 4 << 8 | 29))
typedef li_MD5_CTX MD5_CTX;

#  define	MD5_Init	li_MD5_Init
#  define	MD5_Update	li_MD5_Update
#  define	MD5_Final	li_MD5_Final
# endif

#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
# include <limits.h>
# ifdef HAVE_STDINT_H
#  include <stdint.h>
# endif
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# ifndef USE_OPENSSL
#  include "sha1.h"
# endif
# include "base64.h"
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

#define	HOST_STR				"Host"
#define	CONNECTION_STR				"Connection"
#define	UPGRADE_STR				"Upgrade"
#define	CRLF_STR				"\r\n"

#define	WEBSOCKET_STR				"websocket"
#define	SEC_WEBSOCKET_PROTOCOL_STR		"Sec-WebSocket-Protocol"
#define	SEC_WEBSOCKET_ORIGIN_STR		"Sec-WebSocket-Origin"
#define	SEC_WEBSOCKET_VERSION_STR		"Sec-WebSocket-Version"
#define	ORIGIN_STR				"Origin"

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# define	SEC_WEBSOCKET_LOCATION_STR	"Sec-WebSocket-Location"
# define	SEC_WEBSOCKET_KEY1_STR		"Sec-WebSocket-Key1"
# define	SEC_WEBSOCKET_KEY2_STR		"Sec-WebSocket-Key2"
# define	WS_SCHEME_STR			"ws://"
# define	WSS_SCHEME_STR			"wss://"
# define	SEC_WEBSOCKET_KEY3_STRLEN	(8)
# define	MD5_STRLEN			(16)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
# define	SEC_WEBSOCKET_KEY_STR		"Sec-WebSocket-Key"
# define	SEC_WEBSOCKET_ACCEPT_STR	"Sec-WebSocket-Accept"
# define	GUID_STR			"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# define	ACCEPT_BODY_STRLEN		(32)
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

/* prototypes */
static mod_websocket_bool_t is_allowed_origin(handler_ctx *);
static int replace_extension(handler_ctx *);

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
static int get_key3(handler_ctx *);
static uint32_t count_spc(buffer *);
static int get_key_number(uint32_t *, buffer *);
static int create_MD5_sum(unsigned char *, handler_ctx *);
static mod_websocket_errno_t create_response_ietf_00(handler_ctx *);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
static int create_accept_body(unsigned char *, handler_ctx *);
static mod_websocket_errno_t create_response_rfc_6455(handler_ctx *);
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
int
get_key3(handler_ctx *hctx) {
    int ret, timeout = 1000; /* XXX: poll timeout = 1000ms */
    char key3[SEC_WEBSOCKET_KEY3_STRLEN];
    chunkqueue *q;
    const char *body = NULL;
    struct pollfd pfd;
    ssize_t siz;

    if (!hctx) {
        return -1;
    }
    q = hctx->con->read_queue;
    if (chunkqueue_is_empty(q)) {
        pfd.fd = hctx->con->fd;
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, timeout);
        if (ret > 0 && pfd.revents & POLLIN) {
            siz = read(hctx->con->fd, key3, SEC_WEBSOCKET_KEY3_STRLEN);
            if (siz != SEC_WEBSOCKET_KEY3_STRLEN) {
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                          "ss", "read error:", strerror(errno));
                return -1;
            }
            ret = buffer_copy_string_len(hctx->handshake.key3, key3,
                                         SEC_WEBSOCKET_KEY3_STRLEN);
        } else {
            ret = -1;
        }
    } else {
        body = &q->first->mem->ptr[q->first->offset];
        ret = buffer_copy_string_len(hctx->handshake.key3, body,
                                     SEC_WEBSOCKET_KEY3_STRLEN);
    }
    return ret;
}

uint32_t
count_spc(buffer *b) {
    size_t i;
    uint32_t c = 0;

    if (buffer_is_empty(b)) {
        return 0;
    }
    for (i = b->used; i > 0; i--) {
        c += (b->ptr[i - 1] == ' ');
    }
    return c;
}

int
get_key_number(uint32_t *ret, buffer *b) {
#define	UINT32_MAX_STRLEN	(10)
    char tmp[UINT32_MAX_STRLEN + 1];
    size_t i, j = 0;
    unsigned long n;
    uint32_t s;

    if (!ret || buffer_is_empty(b)) {
        return -1;
    }
    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < b->used; i++) {
        if (isdigit((int)b->ptr[i])) {
            tmp[j] = b->ptr[i];
            j++;
        }
        if (UINT32_MAX_STRLEN < j) {
            return -1;
        }
    }
    n = strtoul(tmp, NULL, 10);
    if (UINT32_MAX < n) {
        return -1;
    }
    s = count_spc(b);
    if (s == 0) {
        return -1;
    }
    *ret = (uint32_t)(n / s);
    return 0;
#undef	UINT32_MAX_STRLEN
}

int
create_MD5_sum(unsigned char *md5sum, handler_ctx *hctx) {
    unsigned char buf[MD5_STRLEN];
    uint32_t k1 = 0, k2 = 0;
    MD5_CTX ctx;

    if (!hctx) {
        return -1;
    }
    if (get_key_number(&k1, hctx->handshake.key1) < 0) {
        return -1;
    }
    if (get_key_number(&k2, hctx->handshake.key2) < 0) {
        return -1;
    }
    if (buffer_is_empty(hctx->handshake.key3)) {
        return -1;
    }
    buf[0] = (k1 >> 24) & 0x0ff;
    buf[1] = (k1 >> 16) & 0x0ff;
    buf[2] = (k1 >>  8) & 0x0ff;
    buf[3] =  k1        & 0x0ff;
    buf[4] = (k2 >> 24) & 0x0ff;
    buf[5] = (k2 >> 16) & 0x0ff;
    buf[6] = (k2 >>  8) & 0x0ff;
    buf[7] =  k2        & 0x0ff;
    memcpy(&buf[8], hctx->handshake.key3->ptr, SEC_WEBSOCKET_KEY3_STRLEN);
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, sizeof(buf));
    MD5_Final(md5sum, &ctx);
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
int
create_accept_body(unsigned char *digest, handler_ctx *hctx) {
    SHA_CTX sha;
# ifdef	USE_OPENSSL
    uint8_t sha1_digest[SHA_DIGEST_LENGTH];
# else
    uint8_t sha1_digest[SHA1_DIGEST_LENGTH];
# endif

    if (!hctx) {
        return -1;
    }
    if (buffer_is_empty(hctx->handshake.key) ||
        buffer_append_string(hctx->handshake.key, GUID_STR) < 0) {
        return -1;
    }
    /* get SHA1 hash of key */
# ifdef	USE_OPENSSL
    if (SHA1_Init(&sha) == 0) {
        return -1;
    }
    if (SHA1_Update(&sha, hctx->handshake.key->ptr,
                    hctx->handshake.key->used - 1) == 0) {
        return -1;
    }
    if (SHA1_Final(sha1_digest, &sha) == 0) {
        return -1;
    }
    /* get base64 encoded SHA1 hash */
    base64_encode(digest, sha1_digest, SHA_DIGEST_LENGTH);
# else
    SHA1_Init(&sha);
    SHA1_Update(&sha, (sha1_byte *)hctx->handshake.key->ptr,
                hctx->handshake.key->used - 1);
    SHA1_Final(sha1_digest, &sha);
    /* get base64 encoded SHA1 hash */
    base64_encode(digest, sha1_digest, SHA1_DIGEST_LENGTH);
#endif
    return 0;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

mod_websocket_bool_t
is_allowed_origin(handler_ctx *hctx) {
    size_t i;
    data_array *cfg_origins = NULL;
    array *allowed_origins = NULL;
    data_string *allowed_origin = NULL;

    cfg_origins = (data_array *)array_get_element(hctx->ext->value,
                                                  MOD_WEBSOCKET_CONFIG_ORIGINS);
    if (!cfg_origins ||
        !cfg_origins->value || !cfg_origins->value->used) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "s", "allowed origins are not specified");
        return MOD_WEBSOCKET_TRUE;
    }
    allowed_origins = cfg_origins->value;
    if (!hctx->handshake.origin) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "request has no origin");
        return MOD_WEBSOCKET_FALSE;
    }
    for (i = allowed_origins->used; i > 0; i--) {
        allowed_origin = (data_string *)allowed_origins->data[i - 1];
        if (NULL != strstr(hctx->handshake.origin->ptr,
                           allowed_origin->value->ptr)) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                      "ss", "allowed origin:", hctx->handshake.origin->ptr);
            return MOD_WEBSOCKET_TRUE;
        }
    }
    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
              "ss", "not allowed origin:", hctx->handshake.origin->ptr);
    return MOD_WEBSOCKET_FALSE;
}

int
replace_extension(handler_ctx *hctx) {
    size_t i;
    data_array *da_subproto = NULL;
    array *subprotos;
    buffer *subproto;

    if (!hctx || !hctx->ext || !hctx->ext->value) {
        return -1;
    }
    subprotos = hctx->ext->value;
    subproto = hctx->handshake.subproto;
    for (i = subprotos->used; i > 0; i--) {
        da_subproto = (data_array *)subprotos->data[i - 1];
        if (buffer_is_empty(subproto)) {
            if (da_subproto->is_index_key) {
                hctx->ext = (data_array *)da_subproto;
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                          "s", "found extension w/o subproto");
                return 0;
            }
        } else {
            if (!buffer_is_empty(da_subproto->key) &&
                strstr(subproto->ptr, da_subproto->key->ptr) != NULL) {
                hctx->ext = (data_array *)da_subproto;
                DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                          "ss", "found subproto extension:",
                          hctx->handshake.subproto->ptr);
                return 0;
            }
        }
    }
    if (buffer_is_empty(subproto)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "not found extension w/o subproto");
    } else {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "ss", "not found subproto extension:",
                  hctx->handshake.subproto->ptr);
    }
    return -1;
}

mod_websocket_errno_t
mod_websocket_handshake_check_request(handler_ctx *hctx) {
    size_t i;
    array *hdrs;
    data_string *hdr = NULL;
    mod_websocket_handshake_t *handshake;
    buffer *con = NULL;
    buffer *upgrade = NULL;
    buffer *version = NULL;
    char *endp;

    if (!hctx || !hctx->con || !hctx->srv) {
        return MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
    }
    hdrs = hctx->con->request.headers;
    handshake = &hctx->handshake;

    /* store necessary headers */
    for (i = hdrs->used; i > 0; i--) {
        hdr = (data_string *)hdrs->data[i - 1];
        if (buffer_is_empty(hdr->key) || buffer_is_empty(hdr->value)) {
            continue;
        }
        if (buffer_is_equal_string(hdr->key, CONST_STR_LEN(CONNECTION_STR))) {
            con = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key, CONST_STR_LEN(UPGRADE_STR))) {
            upgrade = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key, CONST_STR_LEN(HOST_STR))) {
            handshake->host = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_PROTOCOL_STR))) {
            handshake->subproto = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_VERSION_STR))) {
            version = hdr->value;
        }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
        if (buffer_is_equal_string(hdr->key, CONST_STR_LEN(ORIGIN_STR))) {
            handshake->origin = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_KEY1_STR))) {
            handshake->key1 = hdr->value;
        }
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_KEY2_STR))) {
            handshake->key2 = hdr->value;
        }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_ORIGIN_STR))) {
            handshake->origin = hdr->value;
        }
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(ORIGIN_STR))) {
            handshake->origin = hdr->value;
        }
#endif

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
        if (buffer_is_equal_string(hdr->key,
                                   CONST_STR_LEN(SEC_WEBSOCKET_KEY_STR))) {
            handshake->key = hdr->value;
        }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    }
    if (buffer_is_empty(version)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s",
                  "not found Sec-WebSocket-Version header. assume hybi-00");
        handshake->version = 0;
    } else {
        endp = version->ptr + version->used - 1;
        handshake->version = (int)(strtol(version->ptr, &endp, 10) & INT_MAX);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sd",
                  "Sec-WebSocket-Version:", handshake->version);
    }

    /* check store headers */
    if (buffer_is_empty(con) || buffer_is_empty(upgrade)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "s", "not found WebSocket specific headers");
        return MOD_WEBSOCKET_NOT_WEBSOCKET;
    }
    buffer_to_lower(upgrade);
    if (strstr(con->ptr, UPGRADE_STR) == NULL ||
        !buffer_is_equal_string(upgrade, CONST_STR_LEN(WEBSOCKET_STR))) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,
                  "s", "not found WebSocket specific headers");
        return MOD_WEBSOCKET_NOT_WEBSOCKET;
    }
    if (buffer_is_empty(handshake->host)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "not found HOST header");
        return MOD_WEBSOCKET_BAD_REQUEST;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    if (handshake->version == 0) {
        if (buffer_is_empty(handshake->key1) || buffer_is_empty(handshake->key2) ||
            get_key3(hctx) < 0) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                      "s", "not found Sec-WebSocket-Key{1,2,3} header");
            return MOD_WEBSOCKET_BAD_REQUEST;
        }
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (handshake->version > 0) {
        if (buffer_is_empty(handshake->key)) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                      "s", "not found Sec-WebSocket-Key header");
            return MOD_WEBSOCKET_BAD_REQUEST;
        }
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    if (buffer_is_empty(handshake->origin)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "not found Origin header");
        return MOD_WEBSOCKET_BAD_REQUEST;
    }

    /* replace hctx->ext if subproto exsists */
    if (replace_extension(hctx) < 0) {
        return MOD_WEBSOCKET_NOT_FOUND;
    }

    if (is_allowed_origin(hctx) != MOD_WEBSOCKET_TRUE) {
        return MOD_WEBSOCKET_FORBIDDEN;
    }

    return MOD_WEBSOCKET_OK;
}

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
mod_websocket_errno_t
create_response_ietf_00(handler_ctx *hctx) {
    const char *const_hdrs =
        "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
        "Upgrade: WebSocket\r\n"
        "Connection: Upgrade\r\n";
    buffer *resp = NULL;
    unsigned char md5sum[MD5_STRLEN];

    resp = chunkqueue_get_append_buffer(hctx->tocli);
    buffer_append_string(resp, const_hdrs);
    /* Sec-WebSocket-Protocol header if exists */
    if (!buffer_is_empty(hctx->handshake.subproto)) {
        buffer_append_string(resp, SEC_WEBSOCKET_PROTOCOL_STR ": ");
        buffer_append_string_buffer(resp, hctx->handshake.subproto);
        buffer_append_string(resp, CRLF_STR);
    }
    /* Sec-WebSocket-Origin header */
    buffer_append_string(resp, SEC_WEBSOCKET_ORIGIN_STR ": ");
    buffer_append_string_buffer(resp, hctx->handshake.origin);
    buffer_append_string(resp, CRLF_STR);
    /* Sec-WebSocket-Location header */
    buffer_append_string(resp, SEC_WEBSOCKET_LOCATION_STR ": ");
    if (((server_socket *)(hctx->con->srv_socket))->is_ssl) {

# ifdef	USE_OPENSSL
        buffer_append_string(resp, WSS_SCHEME_STR);
# else	/* SSL is not available */
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "wss scheme is not available");
        return MOD_WEBSOCKET_BAD_REQUEST;
# endif	/* USE_OPENSSL */

    } else {
        buffer_append_string(resp, WS_SCHEME_STR);
    }
    buffer_append_string_buffer(resp, hctx->handshake.host);
    buffer_append_string_buffer(resp, hctx->con->uri.path);
    buffer_append_string(resp, CRLF_STR);
    buffer_append_string(resp, CRLF_STR);
    /* MD5 sum in body */
    if (create_MD5_sum(md5sum, hctx) < 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "invalid Sec-WebSocket-Key");
        return MOD_WEBSOCKET_BAD_REQUEST;
    }
    buffer_append_string_len(resp, (char *)md5sum, MD5_STRLEN);
    return MOD_WEBSOCKET_OK;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
mod_websocket_errno_t
create_response_rfc_6455(handler_ctx *hctx) {
    const char *const_hdrs =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n";
    buffer *resp = NULL;
    unsigned char accept_body[ACCEPT_BODY_STRLEN];

    resp = chunkqueue_get_append_buffer(hctx->tocli);
    buffer_append_string(resp, const_hdrs);

    /* Sec-WebSocket-Protocol header if exists */
    if (!buffer_is_empty(hctx->handshake.subproto)) {
        buffer_append_string(resp, SEC_WEBSOCKET_PROTOCOL_STR ": ");
        buffer_append_string_buffer(resp, hctx->ext->key);
        buffer_append_string(resp, CRLF_STR);
    }
    /* Sec-WebSocket-Accept header */
    memset(accept_body, 0, sizeof(accept_body));
    if (create_accept_body(accept_body, hctx) < 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,
                  "s", "invalid Sec-WebSocket-Key");
        return MOD_WEBSOCKET_BAD_REQUEST;
    }
    buffer_append_string(resp, SEC_WEBSOCKET_ACCEPT_STR ": ");
    buffer_append_string_len(resp,
                             (char *)accept_body, strlen((char *)accept_body));
    buffer_append_string(resp, CRLF_STR);
    buffer_append_string(resp, CRLF_STR);
    return MOD_WEBSOCKET_OK;
}
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

mod_websocket_errno_t
mod_websocket_handshake_create_response(handler_ctx *hctx) {
    if (!hctx) {
        return MOD_WEBSOCKET_INTERNAL_SERVER_ERROR;
    }

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    if (hctx->handshake.version == 0) {
        return create_response_ietf_00(hctx);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_00_ */

#if defined _MOD_WEBSOCKET_SPEC_IETF_08_ || \
    defined _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->handshake.version >= 8) {
        return create_response_rfc_6455(hctx);
    }
#endif	/* _MOD_WEBSOCKET_SPEC_IETF_08_ */

    return MOD_WEBSOCKET_BAD_REQUEST;
}

/* EOF */
