/**
 * $Id$
 **/

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket_new.h"

#define	KEY1	"18x 6]8vM;54 *(5:  {   U1]8  z [  8"
#define	KEY2	"1_ tx7X d  <  nw  334J702) 7]o}` 0"
#define	KEY3	"Tm[K T2u"
#define	KEY		"dGhlIHNhbXBsZSBub25jZQ=="

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# define	RESP1	"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Origin: http://hoge.com\r\n"\
					"Sec-WebSocket-Location: ws://localhost/chat\r\n"\
					"\r\n"\
					"fQJ,fN/4F4!~K~MH"

# define	RESP2	"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Protocol: chat\r\n"\
					"Sec-WebSocket-Origin: http://hoge.com\r\n"\
					"Sec-WebSocket-Location: ws://localhost/chat\r\n"\
					"\r\n"\
					"fQJ,fN/4F4!~K~MH"
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
# define	RESP1	"HTTP/1.1 101 Switching Protocols\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"\
					"\r\n"

# define	RESP2	"HTTP/1.1 101 Switching Protocols\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Protocol: chat\r\n"\
					"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"\
					"\r\n"
#endif

CU_TestFunc
mod_websocket_handshake_check_request_test() {
    server_socket srv_sock;
    server srv;
    connection con;
    data_array *ext;
    plugin_data pd;
    handler_ctx hctx;
    mod_websocket_errno_t ret;
    data_array *origins;
    data_string *origin;
    data_string *subproto;
    data_string *header;
    int pipefd[2];
    ssize_t siz;

    fprintf(stderr, "check_request TEST\n");
    ret = check_request(NULL);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_INTERNAL_SERVER_ERROR);

    memset(&hctx, 0, sizeof(hctx));
    con.fd = -1;
    con.read_queue = chunkqueue_init();
    con.request.request = buffer_init();
    con.request.uri = buffer_init();
    con.request.headers = array_init();
    srv_sock.is_ssl = 0;
    con.srv_socket = &srv_sock;
    con.uri.path = buffer_init_string("/");
    pd.conf.debug = 1;

    hctx.handshake.host = NULL;
    hctx.handshake.origin = NULL;
    hctx.handshake.subproto = NULL;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    hctx.handshake.key1 = NULL;
    hctx.handshake.key2 = NULL;
    hctx.handshake.key3 = buffer_init();

    hctx.srv = &srv;
    hctx.con = &con;
    ext = data_array_init();
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    array_insert_unique(ext->value, (data_unset *)origins);

    hctx.ext = ext;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();

    header = data_string_init();
    buffer_copy_string(header->key, "Connection");
    buffer_copy_string(header->value, "Upgrade");
    array_insert_unique(con.request.headers, (data_unset *)header);

    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_NOT_WEBSOCKET);

    header = data_string_init();
    buffer_copy_string(header->key, "Upgrade");
    buffer_copy_string(header->value, "WebSocket");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Host");
    buffer_copy_string(header->value, "localhost");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key1");
    buffer_copy_string(header->value, KEY1);
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key2");
    buffer_copy_string(header->value, KEY2);
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    chunkqueue_append_mem(con.read_queue, KEY3, strlen(KEY3) + 1);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    origin = data_string_init();
    buffer_copy_string(origin->key, "origins");
    buffer_copy_string(origin->value, "hoge.com");
    array_insert_unique(origins->value, (data_unset *)origin);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Origin");
    buffer_copy_string(header->value, "http://hoge2.com");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_FORBIDDEN);

    header = data_string_init();
    buffer_copy_string(header->key, "Origin");
    buffer_copy_string(header->value, "http://hoge.com");
    array_replace(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Protocol");
    buffer_copy_string(header->value, "chat");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_NOT_FOUND);

    subproto = data_string_init();
    buffer_copy_string(subproto->key, "chat");
    array_insert_unique(ext->value, (data_unset *)subproto);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);

    hctx.ext = ext;
    chunkqueue_reset(con.read_queue);
    if (pipe(pipefd) < 0) {
        CU_FAIL("fail to create pipe");
        return 0;
    }
    if (fork() == 0) {
        close(pipefd[0]);
        siz = write(pipefd[1], KEY3, strlen(KEY3));
        if (siz < 0) {
            CU_FAIL("fail to write pipe");
            fprintf(stderr, "%d, %s\n", pipefd[1], strerror(errno));
        }
        close(pipefd[1]);
        _exit(0);
    } else {
        wait(NULL);
        con.fd = pipefd[0];
        close(pipefd[1]);
        ret = check_request(&hctx);
        close(pipefd[0]);
        CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    }
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    hctx.handshake.key = NULL;

    hctx.srv = &srv;
    hctx.con = &con;
    ext = data_array_init();
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    array_insert_unique(ext->value, (data_unset *)origins);

    hctx.ext = ext;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();

    header = data_string_init();
    buffer_copy_string(header->key, "Connection");
    buffer_copy_string(header->value, "Upgrade");
    array_insert_unique(con.request.headers, (data_unset *)header);

    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_NOT_WEBSOCKET);

    header = data_string_init();
    buffer_copy_string(header->key, "Upgrade");
    buffer_copy_string(header->value, "websocket");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Host");
    buffer_copy_string(header->value, "localhost");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key");
    buffer_copy_string(header->value, KEY);
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    origin = data_string_init();
    buffer_copy_string(origin->key, "origins");
    buffer_copy_string(origin->value, "hoge.com");
    array_insert_unique(origins->value, (data_unset *)origin);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Origin");
    buffer_copy_string(header->value, "http://hoge2.com");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_BAD_REQUEST);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Origin");
    buffer_copy_string(header->value, "http://hoge2.com");
    array_replace(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_FORBIDDEN);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Origin");
    buffer_copy_string(header->value, "http://hoge.com");
    array_replace(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Protocol");
    buffer_copy_string(header->value, "chat");
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_NOT_FOUND);

    subproto = data_string_init();
    buffer_copy_string(subproto->key, "chat");
    array_insert_unique(ext->value, (data_unset *)subproto);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);

    hctx.ext = ext;
    chunkqueue_reset(con.read_queue);
    if (pipe(pipefd) < 0) {
        CU_FAIL("fail to create pipe");
        return 0;
    }
    if (fork() == 0) {
        close(pipefd[0]);
        siz = write(pipefd[1], KEY3, strlen(KEY3));
        if (siz < 0) {
            CU_FAIL("fail to write pipe");
        }
        close(pipefd[1]);
        _exit(0);
    } else {
        wait(NULL);
        con.fd = pipefd[0];
        close(pipefd[1]);
        ret = check_request(&hctx);
        close(pipefd[0]);
        CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    }
#endif

    return 0;
}

void
check_response(chunkqueue *q, char *exp) {
    chunk *c = NULL;
    buffer *b = NULL;

    for (c = q->first; c; c = c->next) {
        if (!b) {
            b = buffer_init_buffer(c->mem);
        } else {
            buffer_append_memory(b, c->mem->ptr, c->mem->used);
        }
    }
    if (memcmp(b->ptr, exp, strlen(exp)) != 0) {
        CU_FAIL("invalid response");
        fprintf(stderr, "exp:\n%s", exp);
        fprintf(stderr, "---");
        fprintf(stderr, "res:\n%s", b->ptr);
        fprintf(stderr, "---");
    }
}

CU_TestFunc
mod_websocket_handshake_create_response_test() {
    server_socket srv_sock;
    server srv;
    connection con;
    data_array *ext;
    plugin_data pd;
    handler_ctx hctx;
    mod_websocket_errno_t ret;
    data_array *origins;
    data_string *origin;
    data_string *subproto;
    data_string *header;

    fprintf(stderr, "create_response TEST\n");
    ret = create_response(NULL);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_INTERNAL_SERVER_ERROR);

    memset(&hctx, 0, sizeof(hctx));
    con.fd = -1;
    con.read_queue = chunkqueue_init();
    con.request.request = buffer_init();
    con.request.uri = buffer_init();
    con.request.headers = array_init();
    srv_sock.is_ssl = 0;
    con.srv_socket = &srv_sock;
    con.uri.path = buffer_init_string("/chat");
    pd.conf.debug = 1;

    hctx.handshake.host = NULL;
    hctx.handshake.origin = NULL;
    hctx.handshake.subproto = NULL;

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
    hctx.handshake.key1 = NULL;
    hctx.handshake.key2 = NULL;
    hctx.handshake.key3 = buffer_init();

    hctx.srv = &srv;
    hctx.con = &con;
    ext = data_array_init();
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    array_insert_unique(ext->value, (data_unset *)origins);

    hctx.ext = ext;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();

    header = data_string_init();
    buffer_copy_string(header->key, "Connection");
    buffer_copy_string(header->value, "Upgrade");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Upgrade");
    buffer_copy_string(header->value, "WebSocket");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Host");
    buffer_copy_string(header->value, "localhost");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key1");
    buffer_copy_string(header->value, KEY1);
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key2");
    buffer_copy_string(header->value, KEY2);
    array_insert_unique(con.request.headers, (data_unset *)header);
    chunkqueue_append_mem(con.read_queue, KEY3, strlen(KEY3) + 1);
    origin = data_string_init();
    buffer_copy_string(origin->key, "origins");
    buffer_copy_string(origin->value, "hoge.com");
    array_insert_unique(origins->value, (data_unset *)origin);
    header = data_string_init();
    buffer_copy_string(header->key, "Origin");
    buffer_copy_string(header->value, "http://hoge.com");
    array_replace(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    chunkqueue_reset(hctx.tocli);
    ret = create_response(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    check_response(hctx.tocli, RESP1);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Protocol");
    buffer_copy_string(header->value, "chat");
    array_insert_unique(con.request.headers, (data_unset *)header);
    subproto = data_string_init();
    buffer_copy_string(subproto->key, "chat");
    array_insert_unique(ext->value, (data_unset *)subproto);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    chunkqueue_reset(hctx.tocli);
    ret = create_response(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    check_response(hctx.tocli, RESP2);

#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_08_
    hctx.handshake.key = NULL;

    hctx.srv = &srv;
    hctx.con = &con;
    ext = data_array_init();
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    array_insert_unique(ext->value, (data_unset *)origins);

    hctx.ext = ext;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();

    header = data_string_init();
    buffer_copy_string(header->key, "Connection");
    buffer_copy_string(header->value, "Upgrade");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Upgrade");
    buffer_copy_string(header->value, "websocket");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Host");
    buffer_copy_string(header->value, "localhost");
    array_insert_unique(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key");
    buffer_copy_string(header->value, KEY);
    array_insert_unique(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    origin = data_string_init();
    buffer_copy_string(origin->key, "origins");
    buffer_copy_string(origin->value, "hoge.com");
    array_insert_unique(origins->value, (data_unset *)origin);
    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Origin");
    buffer_copy_string(header->value, "http://hoge.com");
    array_replace(con.request.headers, (data_unset *)header);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    ret = create_response(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    check_response(hctx.tocli, RESP1);

    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Key");
    buffer_copy_string(header->value, KEY);
    array_replace(con.request.headers, (data_unset *)header);
    header = data_string_init();
    buffer_copy_string(header->key, "Sec-WebSocket-Protocol");
    buffer_copy_string(header->value, "chat");
    array_insert_unique(con.request.headers, (data_unset *)header);
    subproto = data_string_init();
    buffer_copy_string(subproto->key, "chat");
    array_insert_unique(ext->value, (data_unset *)subproto);
    ret = check_request(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    chunkqueue_reset(hctx.tocli);
    hctx.ext = ext;
    buffer_copy_string(ext->key, "chat");
    ret = create_response(&hctx);
    CU_ASSERT_EQUAL(ret, MOD_WEBSOCKET_OK);
    check_response(hctx.tocli, RESP2);

#endif

    return 0;
}

int
main() {
    CU_ErrorCode ret;
    CU_pSuite suite;

    ret = CU_initialize_registry();
    if (ret != CUE_SUCCESS) {
        return -1;
    }
    CU_basic_set_mode(CU_BRM_SILENT);
    suite = CU_add_suite("mod_websocket_handshake_suite", NULL, NULL);
    CU_ADD_TEST(suite, mod_websocket_handshake_check_request_test);
    CU_ADD_TEST(suite, mod_websocket_handshake_create_response_test);
    CU_basic_run_tests();
    ret = CU_get_number_of_failures();
    if (ret != 0) {
        CU_basic_show_failures(CU_get_failure_list());
        fprintf(stderr, "\n");
    }
    return ret;
}

/* EOF */
