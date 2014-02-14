#include <sys/unistd.h>
#include <sys/wait.h>

#include <gtest/gtest.h>

#include "mod_websocket.h"

#ifdef HAVE_PCRE_H
# define	ALLOWED_ORIGIN	"http:\\/\\/bar\\.com\\/.*"
#else
# define	ALLOWED_ORIGIN	"http://bar.com/foo"
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_IETF_00_
# define	SEC_WEBSOCKET_KEY1	"18x 6]8vM;54 *(5:  {   U1]8  z [  8"
# define	SEC_WEBSOCKET_KEY2	"1_ tx7X d  <  nw  334J702) 7]o}` 0"
# define	SEC_WEBSOCKET_KEY3	"Tm[K T2u"

# define	REQ_IETF_00		"GET /chat HTTP/1.1\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Host: bar.com\r\n"\
					"Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Key1: " SEC_WEBSOCKET_KEY1 "\r\n"\
					"Sec-WebSocket-Key2: " SEC_WEBSOCKET_KEY2 "\r\n"\
					"X-Forwarded-Proto: http\r\n"\
					"X-Forwarded-For: unknown:unknown\r\n"\
					"X-Forwarded-Port: unknown\r\n\r\n"\
					SEC_WEBSOCKET_KEY3

# define	REQ_IETF_00_MULTI	"GET /chat HTTP/1.1\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Host: bar.com\r\n"\
					"Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Key1: " SEC_WEBSOCKET_KEY1 "\r\n"\
					"Sec-WebSocket-Key2: " SEC_WEBSOCKET_KEY2 "\r\n"\
					"X-Forwarded-Proto: http, http\r\n"\
					"X-Forwarded-For: 192.168.0.1, unknown:unknown\r\n"\
					"X-Forwarded-Port: 80, unknown\r\n\r\n"\
					SEC_WEBSOCKET_KEY3

# define	RESP_WS_IETF_00		"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Location: ws://bar.com/chat\r\n"\
					"\r\n"\
					"fQJ,fN/4F4!~K~MH"

# define	RESP_WSS_IETF_00	"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"\
					"Upgrade: WebSocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Location: wss://bar.com/chat\r\n"\
					"\r\n"\
					"fQJ,fN/4F4!~K~MH"
#endif

#ifdef	_MOD_WEBSOCKET_SPEC_RFC_6455_
# define	SEC_WEBSOCKET_KEY	"dGhlIHNhbXBsZSBub25jZQ=="

# define	REQ_RFC_6455		"GET /chat HTTP/1.1\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Host: bar.com\r\n"\
					"Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Key: " SEC_WEBSOCKET_KEY "\r\n"\
					"Sec-WebSocket-Version: 13\r\n"\
					"X-Forwarded-Proto: http\r\n"\
					"X-Forwarded-For: unknown:unknown\r\n"\
					"X-Forwarded-Port: unknown\r\n\r\n"

# define	REQ_RFC_6455_MULTI	"GET /chat HTTP/1.1\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Host: bar.com\r\n"\
					"Origin: http://bar.com/foo\r\n"\
					"Sec-WebSocket-Key: " SEC_WEBSOCKET_KEY "\r\n"\
					"Sec-WebSocket-Version: 13\r\n"\
					"X-Forwarded-Proto: http, http\r\n"\
					"X-Forwarded-For: 192.168.0.1, unknown:unknown\r\n"\
					"X-Forwarded-Port: 80, unknown\r\n\r\n"

# define	RESP_RFC_6455		"HTTP/1.1 101 Switching Protocols\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"\
					"\r\n"
# define	RESP_RFC_6455_SUBPROTO	"HTTP/1.1 101 Switching Protocols\r\n"\
					"Upgrade: websocket\r\n"\
					"Connection: Upgrade\r\n"\
					"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"\
					"Sec-WebSocket-Protocol: subprotocol2\r\n" \
					"\r\n"
#endif

class ModWebsocketHandshakeCheckRequestTest : public testing::Test {
protected:
  ModWebsocketHandshakeCheckRequestTest() {}
  ~ModWebsocketHandshakeCheckRequestTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init server_socket
    srv_sock.is_ssl = 0;

    // init connection
    con.fd = -1;
    con.read_queue = chunkqueue_init();
    con.request.request = buffer_init();
    con.request.uri = buffer_init();
    con.request.headers = array_init();
    con.srv_socket = &srv_sock;
    con.uri.path = buffer_init_string("/chat");

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_DEBUG;

    // init extension: "/chat" => ( "host" => "...", ... , "origins" => () ), ... )
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    ext = data_array_init();
    buffer_copy_string(ext->key, "/chat");
    array_insert_unique(ext->value, (data_unset *)origins);

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.ext = ext;
    hctx.handshake.host = NULL;
    hctx.handshake.origin = NULL;
    hctx.handshake.version = -1;
    hctx.tocli = chunkqueue_init();

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    hctx.handshake.key1 = NULL;
    hctx.handshake.key2 = NULL;
    hctx.handshake.key3 = buffer_init();
#endif
#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
    hctx.handshake.key = NULL;
#endif

  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    chunkqueue_free(con.read_queue);
    buffer_free(con.request.request);
    buffer_free(con.request.uri);
    array_free(con.request.headers);
    buffer_free(con.uri.path);
    buffer_free(ext->key);
    array_free(ext->value);
    free(ext);
    chunkqueue_free(hctx.tocli);

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx.handshake.key3);
#endif

  }

public:
  server_socket srv_sock;
  connection con;
  plugin_data pd;
  data_array* ext;
  data_array* origins;
  server srv;
  handler_ctx hctx;
};

class ModWebsocketHandshakeCreateResponseTest : public testing::Test {
protected:
  ModWebsocketHandshakeCreateResponseTest() {}
  ~ModWebsocketHandshakeCreateResponseTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init server_socket
    srv_sock.is_ssl = 0;

    // init connection
    con.fd = -1;
    con.read_queue = chunkqueue_init();
    con.request.request = buffer_init();
    con.request.uri = buffer_init();
    con.request.headers = array_init();
    con.srv_socket = &srv_sock;
    con.uri.path = buffer_init_string("/chat");

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_DEBUG;

    // init extension: "/chat" => ( "host" => "...", ... , "origins" => () ), ... )
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    ext = data_array_init();
    buffer_copy_string(ext->key, "/chat");
    array_insert_unique(ext->value, (data_unset *)origins);

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.ext = ext;
    hctx.handshake.host = NULL;
    hctx.handshake.origin = NULL;
    hctx.handshake.version = -1;
    hctx.tocli = chunkqueue_init();

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    hctx.handshake.key1 = NULL;
    hctx.handshake.key2 = NULL;
    hctx.handshake.key3 = buffer_init();
#endif
#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
    hctx.handshake.key = NULL;
#endif

  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    chunkqueue_free(con.read_queue);
    buffer_free(con.request.request);
    buffer_free(con.request.uri);
    array_free(con.request.headers);
    buffer_free(con.uri.path);
    buffer_free(ext->key);
    array_free(ext->value);
    free(ext);
    chunkqueue_free(hctx.tocli);

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx.handshake.key3);
#endif

  }

public:
  server_socket srv_sock;
  connection con;
  plugin_data pd;
  data_array* ext;
  data_array* origins;
  server srv;
  handler_ctx hctx;
};

class ModWebsocketHandshakeForwardRequestTest : public testing::Test {
protected:
  ModWebsocketHandshakeForwardRequestTest() {}
  ~ModWebsocketHandshakeForwardRequestTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init server_socket
    srv_sock.is_ssl = 0;

    // init connection
    con.fd = -1;
    con.read_queue = chunkqueue_init();
    con.request.request_line = buffer_init();
    con.request.request = buffer_init();
    con.request.uri = buffer_init();
    con.request.headers = array_init();
    con.srv_socket = &srv_sock;
    con.uri.path = buffer_init_string("/chat");

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_DEBUG;

    // init extension: "/chat" => ( "host" => "...", ... , "origins" => () ), ... )
    origins = data_array_init();
    buffer_copy_string(origins->key, "origins");
    ext = data_array_init();
    buffer_copy_string(ext->key, "/chat");
    array_insert_unique(ext->value, (data_unset *)origins);

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.ext = ext;
    hctx.handshake.host = NULL;
    hctx.handshake.origin = NULL;
    hctx.handshake.version = -1;
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    hctx.handshake.key1 = NULL;
    hctx.handshake.key2 = NULL;
    hctx.handshake.key3 = buffer_init();
#endif
#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
    hctx.handshake.key = NULL;
#endif

  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    chunkqueue_free(con.read_queue);
    buffer_free(con.request.request_line);
    buffer_free(con.request.request);
    buffer_free(con.request.uri);
    array_free(con.request.headers);
    buffer_free(con.uri.path);
    buffer_free(ext->key);
    array_free(ext->value);
    free(ext);
    chunkqueue_free(hctx.tocli);
    chunkqueue_free(hctx.tosrv);

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    buffer_free(hctx.handshake.key3);
#endif

  }

public:
  server_socket srv_sock;
  connection con;
  plugin_data pd;
  data_array* ext;
  data_array* origins;
  server srv;
  handler_ctx hctx;
};

static void print_headers(array *a) {
#if 0
  array_print(a, 1);
  std::cout << std::endl;
#endif
};

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
TEST_F(ModWebsocketHandshakeCheckRequestTest, IETF_00) {
  mod_websocket_errno_t ret;
  data_string *header;
  data_string *origin;
  int pipefd[2];

  ret = mod_websocket_handshake_check_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_PRECONDITION_FAILED, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "WebSocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key1");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY1);
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key2");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY2);
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  chunkqueue_append_mem(con.read_queue, SEC_WEBSOCKET_KEY3, sizeof(SEC_WEBSOCKET_KEY3));
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  // not allowed origin
  origin = data_string_init();
  buffer_copy_string(origin->value, "http:\\/\\/foo\\.com\\/.*");
  array_insert_unique(origins->value, (data_unset *)origin);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_FORBIDDEN, ret);

  // allowed origin
  origin = data_string_init();
  buffer_copy_string(origin->value, ALLOWED_ORIGIN);
  array_insert_unique(origins->value, (data_unset *)origin);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);

  // check chunked key-3
  chunkqueue_reset(con.read_queue);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);
  if (pipe(pipefd) != 0) {
    ASSERT_FALSE(true) << "fail to create pipe";
  }
  if (fork() == 0) {
    close(pipefd[0]);
    if (write(pipefd[1], SEC_WEBSOCKET_KEY3, strlen(SEC_WEBSOCKET_KEY3)) < 0) {
      ASSERT_FALSE(true) << "fail to write";
    }
    close(pipefd[1]);
    _exit(0);
  } else {
    wait(NULL);
    con.fd = pipefd[0];
    close(pipefd[1]);
    ret = mod_websocket_handshake_check_request(&hctx);
    ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
    close(pipefd[0]);
  }
}
#endif

#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
TEST_F(ModWebsocketHandshakeCheckRequestTest, RFC_6455) {
  mod_websocket_errno_t ret;
  data_string *header;
  data_string *origin;

  ret = mod_websocket_handshake_check_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Version");
  buffer_copy_string(header->value, "13");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_PRECONDITION_FAILED, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_PRECONDITION_FAILED, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "WebSocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY);
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_BAD_REQUEST, ret);

  // not allowed origin
  origin = data_string_init();
  buffer_copy_string(origin->value, "http:\\/\\/foo\\.com\\/.*");
  array_insert_unique(origins->value, (data_unset *)origin);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_FORBIDDEN, ret);

  // allowed origin
  origin = data_string_init();
  buffer_copy_string(origin->value, ALLOWED_ORIGIN);
  array_insert_unique(origins->value, (data_unset *)origin);
  print_headers(con.request.headers);
  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
}
#endif

static int check_response(chunkqueue *q, const char *exp) {
  chunk *c = NULL;
  buffer *b = NULL;

  for (c = q->first; c; c = c->next) {
    if (!b) {
      b = buffer_init_buffer(c->mem);
    } else {
      buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
  }
  if (b) {
    if (memcmp(b->ptr, exp, strlen(exp)) != 0 || b->used - 1 != strlen(exp)) {
      std::cerr << "invalid response" << std::endl << std::endl
                << "exp:" << std::endl
                << "[" << exp << "], size = " << strlen(exp) << std::endl << std::endl
                << "res:" << std::endl
                << "[" << b->ptr << "], size = " << b->used - 1 << std::endl;
      return -1;
    }
  } else {
    std::cerr << "null response" << std::endl << std::endl
              << "exp:" << std::endl
              << "[" << exp << "], size = " << strlen(exp) << std::endl;
    return -1;
  }
  return 0;
}

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
TEST_F(ModWebsocketHandshakeCreateResponseTest, IETF_00) {
  mod_websocket_errno_t ret;
  data_string *header;
  data_string *origin;
  int pipefd[2];

  ret = mod_websocket_handshake_create_response(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  // create request
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
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key1");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY1);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key2");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY2);
  array_insert_unique(con.request.headers, (data_unset *)header);
  chunkqueue_append_mem(con.read_queue, SEC_WEBSOCKET_KEY3, sizeof(SEC_WEBSOCKET_KEY3));
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);

  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);

  ret = mod_websocket_handshake_create_response(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  check_response(hctx.tocli, RESP_WS_IETF_00);

  chunkqueue_reset(hctx.tocli);
  srv_sock.is_ssl = 1;
  ret = mod_websocket_handshake_create_response(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  check_response(hctx.tocli, RESP_WSS_IETF_00);
}
#endif

#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
TEST_F(ModWebsocketHandshakeCreateResponseTest, RFC_6455) {
  mod_websocket_errno_t ret;
  data_string *header;
  data_string *origin;

  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Version");
  buffer_copy_string(header->value, "13");
  array_insert_unique(con.request.headers, (data_unset *)header);
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
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);

  ret = mod_websocket_handshake_check_request(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);

  ret = mod_websocket_handshake_create_response(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_response(hctx.tocli, RESP_RFC_6455));

  chunkqueue_reset(hctx.tocli);
  srv_sock.is_ssl = 1;
  ret = mod_websocket_handshake_create_response(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_response(hctx.tocli, RESP_RFC_6455));

  // check subproto
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Protocol");
  buffer_copy_string(header->value, "subprotocol1, subprotocol2");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);
  data_string* subproto = data_string_init();
  buffer_copy_string(subproto->key, "subproto");
  buffer_copy_string(subproto->value, "subprotocol2");
  array_insert_unique(ext->value, (data_unset *)subproto);
  chunkqueue_reset(hctx.tocli);
  ret = mod_websocket_handshake_create_response(&hctx);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_response(hctx.tocli, RESP_RFC_6455_SUBPROTO));
}
#endif

static int check_forward(chunkqueue *q, const char *exp) {
  chunk *c = NULL;
  buffer *b = NULL;

  for (c = q->first; c; c = c->next) {
    if (!b) {
      b = buffer_init_buffer(c->mem);
    } else {
      buffer_append_memory(b, c->mem->ptr, c->mem->used);
    }
  }
  if (b) {
    if (memcmp(b->ptr, exp, strlen(exp)) != 0 || b->used - 1 != strlen(exp)) {
      std::cerr << "invalid request" << std::endl << std::endl
                << "exp:" << std::endl
                << "[" << exp << "], size = " << strlen(exp) << std::endl << std::endl
                << "res:" << std::endl
                << "[" << b->ptr << "], size = " << b->used - 1 << std::endl;
      return -1;
    }
  } else {
    std::cerr << "null request" << std::endl << std::endl
              << "exp:" << std::endl
              << "[" << exp << "], size = " << strlen(exp) << std::endl;
    return -1;
  }
  return 0;
}

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
TEST_F(ModWebsocketHandshakeForwardRequestTest, IETF_00) {
  mod_websocket_errno_t ret;
  data_string *header;

  ret = mod_websocket_handshake_forward_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  buffer_copy_string(con.request.request_line, "GET /chat HTTP/1.1");
  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "WebSocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key1");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY1);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key2");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY2);
  array_insert_unique(con.request.headers, (data_unset *)header);
  buffer_copy_string(hctx.handshake.key3, SEC_WEBSOCKET_KEY3);

  ret = mod_websocket_handshake_forward_request(&hctx);
  print_headers(con.request.headers);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_forward(hctx.tosrv, REQ_IETF_00));
}

TEST_F(ModWebsocketHandshakeForwardRequestTest, IETF_00_MULTI) {
  mod_websocket_errno_t ret;
  data_string *header;

  ret = mod_websocket_handshake_forward_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  buffer_copy_string(con.request.request_line, "GET /chat HTTP/1.1");
  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "WebSocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key1");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY1);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key2");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY2);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-Proto");
  buffer_copy_string(header->value, "http");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-For");
  buffer_copy_string(header->value, "192.168.0.1");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-Port");
  buffer_copy_string(header->value, "80");
  array_insert_unique(con.request.headers, (data_unset *)header);

  buffer_copy_string(hctx.handshake.key3, SEC_WEBSOCKET_KEY3);

  ret = mod_websocket_handshake_forward_request(&hctx);
  print_headers(con.request.headers);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_forward(hctx.tosrv, REQ_IETF_00_MULTI));
}
#endif

#ifdef  _MOD_WEBSOCKET_SPEC_RFC_6455_
TEST_F(ModWebsocketHandshakeForwardRequestTest, RFC_6455) {
  mod_websocket_errno_t ret;
  data_string *header;

  ret = mod_websocket_handshake_forward_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  buffer_copy_string(con.request.request_line, "GET /chat HTTP/1.1");
  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "websocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Version");
  buffer_copy_string(header->value, "13");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);

  ret = mod_websocket_handshake_forward_request(&hctx);
  print_headers(con.request.headers);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_forward(hctx.tosrv, REQ_RFC_6455));
}

TEST_F(ModWebsocketHandshakeForwardRequestTest, RFC_6455_MULTI) {
  mod_websocket_errno_t ret;
  data_string *header;

  ret = mod_websocket_handshake_forward_request(NULL);
  ASSERT_EQ(MOD_WEBSOCKET_INTERNAL_SERVER_ERROR, ret);

  buffer_copy_string(con.request.request_line, "GET /chat HTTP/1.1");
  header = data_string_init();
  buffer_copy_string(header->key, "Upgrade");
  buffer_copy_string(header->value, "websocket");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Connection");
  buffer_copy_string(header->value, "Upgrade");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Host");
  buffer_copy_string(header->value, "bar.com");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Origin");
  buffer_copy_string(header->value, "http://bar.com/foo");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Key");
  buffer_copy_string(header->value, SEC_WEBSOCKET_KEY);
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "Sec-WebSocket-Version");
  buffer_copy_string(header->value, "13");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-Proto");
  buffer_copy_string(header->value, "http");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-For");
  buffer_copy_string(header->value, "192.168.0.1");
  array_insert_unique(con.request.headers, (data_unset *)header);
  header = data_string_init();
  buffer_copy_string(header->key, "X-Forwarded-Port");
  buffer_copy_string(header->value, "80");
  array_insert_unique(con.request.headers, (data_unset *)header);
  print_headers(con.request.headers);

  ret = mod_websocket_handshake_forward_request(&hctx);
  print_headers(con.request.headers);
  ASSERT_EQ(MOD_WEBSOCKET_OK, ret);
  ASSERT_EQ(0, check_forward(hctx.tosrv, REQ_RFC_6455_MULTI));
}
#endif

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
