#include <iomanip>
#include <gtest/gtest.h>

#include "mod_websocket.h"
#include "mod_websocket_base64.h"

class ModWebsocketFrameSendTest : public testing::Test {
protected:
  ModWebsocketFrameSendTest() {}
  ~ModWebsocketFrameSendTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init connection
    con.fd = -1;
    con.read_queue = chunkqueue_init();

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_NONE;

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.mode = MOD_WEBSOCKET_TCP_PROXY;
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.tocli = chunkqueue_init();
    hctx.fromcli = con.read_queue;
  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    chunkqueue_free(con.read_queue);
    chunkqueue_free(hctx.tocli);
  }

public:
  connection con;
  plugin_data pd;
  server srv;
  handler_ctx hctx;
};

class ModWebsocketFrameRecvTest : public testing::Test {
protected:
  ModWebsocketFrameRecvTest() {}
  ~ModWebsocketFrameRecvTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init connection
    con.fd = -1;

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_NONE;

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.mode = MOD_WEBSOCKET_TCP_PROXY;
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.frame.payload = buffer_init();
    hctx.tocli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    buffer_free(hctx.frame.payload);
    chunkqueue_free(hctx.tocli);
    chunkqueue_free(hctx.tosrv);
  }

public:
  connection con;
  plugin_data pd;
  server srv;
  handler_ctx hctx;
};

class ModWebsocketFrameForwardTest : public testing::Test {
protected:
  ModWebsocketFrameForwardTest() {}
  ~ModWebsocketFrameForwardTest() {}

  virtual void SetUp() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // init connection
    con.fd = -1;

    // init plugin_data
    pd.conf.debug = MOD_WEBSOCKET_LOG_NONE;

    // init handler_ctx
    memset(&hctx, 0, sizeof(hctx));
    hctx.mode = MOD_WEBSOCKET_WEBSOCKET_PROXY;
    hctx.srv = &srv;
    hctx.con = &con;
    hctx.pd = &pd;
    hctx.frame.payload = buffer_init();
    hctx.tocli = chunkqueue_init();
    hctx.fromcli = chunkqueue_init();
    hctx.tosrv = chunkqueue_init();
  }
  virtual void TearDown() {
    std::cerr << __PRETTY_FUNCTION__ << std::endl;

    buffer_free(hctx.frame.payload);
    chunkqueue_free(hctx.tocli);
    chunkqueue_free(hctx.fromcli);
    chunkqueue_free(hctx.tosrv);
  }

public:
  connection con;
  plugin_data pd;
  server srv;
  handler_ctx hctx;
};

static void print_frame(buffer* b) {
#if 0
  size_t i;

  std::cout ;
  std::cout << "[ ";
  for (i = 0; i < b->used - 1; i++) {
    std::cout << std::setw(2) << std::setfill('0')
              << std::hex << (static_cast<int>(b->ptr[i]) & 0xff) << ", ";
  }
  std::cout  << std::setw(2) << std::setfill('0')
             << std::hex << (static_cast<int>(b->ptr[i]) & 0xff);
  std::cout << " ]" << std::endl;
#endif
}

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
static void check_frame_ietf_00(const char* exp, size_t exp_siz, chunkqueue* q) {
  chunk* c = NULL;
  buffer* frame = NULL;

  for (c = q->first; c; c = c->next) {
    if (NULL == frame) {
      frame = buffer_init();
      buffer_copy_memory(frame, c->mem->ptr, c->mem->used);
    } else {
      buffer_append_memory(frame, c->mem->ptr, c->mem->used);
    }
  }
  print_frame(frame);
  if (frame->ptr[0] != 0x00) {
    ASSERT_FALSE(true) << "frame start bit invalid";
  }
  if (static_cast<unsigned char>(frame->ptr[frame->used - 2]) != 0xff) {
    ASSERT_FALSE(true) << "frame end bit invalid";
  }
  if (frame->ptr[frame->used - 1] != 0) {
    ASSERT_FALSE(true) << "end of frame invalid";
  }
  ASSERT_EQ(exp_siz, frame->used - 3);
  ASSERT_EQ(0, memcmp(exp, &frame->ptr[1], frame->used - 3));
}

static void check_close_frame_ietf_00(chunkqueue* q) {
  chunk* c = NULL;
  buffer* frame = NULL;

  for (c = q->first; c; c = c->next) {
    if (NULL == frame) {
      frame = buffer_init();
      buffer_copy_memory(frame, c->mem->ptr, c->mem->used);
    } else {
      buffer_append_memory(frame, c->mem->ptr, c->mem->used);
    }
  }
  print_frame(frame);
  if (static_cast<unsigned char>(frame->ptr[0]) != 0xff) {
    ASSERT_FALSE(true) << "frame start bit invalid";
  }
  if (frame->ptr[1] != 0x00) {
    ASSERT_FALSE(true) << "frame end bit invalid";
  }
  if (frame->ptr[2] != 0) {
    ASSERT_FALSE(true) << "end of frame invalid";
  }
}

TEST_F(ModWebsocketFrameSendTest, IETF_00) {
  static const char* text = "foo";
  unsigned char binary[256];
  unsigned char* base64;
  size_t base64_siz;

  hctx.handshake.version = 0;
  // INVALID
  ASSERT_EQ(-1, mod_websocket_frame_send(NULL, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         const_cast<char*>(text),
                                         strlen(text)));
  ASSERT_EQ(-1, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         NULL, 0));
  ASSERT_EQ(-1, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                         NULL, 0));

  // TEXT
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        const_cast<char *>(text),
                                        strlen(text)));
  check_frame_ietf_00(text, strlen(text), hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // BINARY
  for (int i = 0; i < sizeof(binary); i++) {
    binary[i] = i;
  }
  ASSERT_EQ(0, mod_websocket_base64_encode(&base64, &base64_siz,
                                           binary, sizeof(binary)));
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        reinterpret_cast<char *>(binary),
                                        sizeof(binary)));
  check_frame_ietf_00(reinterpret_cast<char *>(base64), base64_siz, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // CLOSE
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                        NULL, 0));
  check_close_frame_ietf_00(hctx.tocli);
  chunkqueue_reset(hctx.tocli);
}
#endif

#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
static void check_frame_rfc_6455(mod_websocket_frame_type_t exp_type, const char* exp, size_t exp_siz, chunkqueue* q) {
  chunk* c = NULL;
  buffer* frame = NULL;
  uint64_t idx, payload_siz;

  for (c = q->first; c; c = c->next) {
    if (NULL == frame) {
      frame = buffer_init();
      buffer_copy_memory(frame, c->mem->ptr, c->mem->used);
    } else {
      buffer_append_memory(frame, c->mem->ptr, c->mem->used);
    }
  }
  //print_frame(frame);
  // check FIN and RSV1-4 bit
  ASSERT_EQ(0x80, (frame->ptr[0] & 0xf0));
  // check opcode
  switch(exp_type) {
  case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
    ASSERT_EQ(0x01, (frame->ptr[0] & 0x0f));
    break;
  case MOD_WEBSOCKET_FRAME_TYPE_BIN:
    ASSERT_EQ(0x02, (frame->ptr[0] & 0x0f));
    break;
  case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
    ASSERT_EQ(0x08, (frame->ptr[0] & 0x0f));
    break;
  case MOD_WEBSOCKET_FRAME_TYPE_PING:
    ASSERT_EQ(0x09, (frame->ptr[0] & 0x0f));
    break;
  case MOD_WEBSOCKET_FRAME_TYPE_PONG:
    ASSERT_EQ(0x0a, (frame->ptr[0] & 0x0f));
    break;
  default:
    ASSERT_FALSE(true) << "unknown type";
  }
  // get siz
  idx = static_cast<size_t>(frame->ptr[1] & 0x7f);
  if (idx < 0x7e) {
    payload_siz = idx;
    ASSERT_LT(exp_siz, 0x7e);
    if (exp_siz != 0) {
      ASSERT_EQ(0, memcmp(&frame->ptr[2], exp, exp_siz));
    }
  } else if (idx == 0x7e) {
    std::cerr << std::hex << std::setw(2)
              << "[2]:" << ((int)frame->ptr[2] & 0xff) << ", [3]:" << ((int)frame->ptr[3] & 0xff) << std::endl;
    payload_siz = (static_cast<size_t>(frame->ptr[2] & 0xff) << 8) + static_cast<size_t>(frame->ptr[3] & 0xff);
    ASSERT_LE(0x7e, exp_siz);
    ASSERT_LE(exp_siz, UINT16_MAX);
    ASSERT_EQ(0, memcmp(&frame->ptr[4], exp, exp_siz));
  } else if (idx == 0x7f) {
    std::cerr << std::setw(2) << std::hex
              << "[2]:" << ((int)frame->ptr[2] & 0xff) << ", [3]:" << ((int)frame->ptr[3] & 0xff)
              << ", [4]:" << ((int)frame->ptr[4] & 0xff) << ", [5]:" << ((int)frame->ptr[5] & 0xff)
              << ", [6]:" << ((int)frame->ptr[6] & 0xff) << ", [7]:" << ((int)frame->ptr[7] & 0xff)
              << ", [8]:" << ((int)frame->ptr[8] & 0xff) << ", [9]:" << ((int)frame->ptr[9] & 0xff) << std::endl;
     ASSERT_EQ(0x00, frame->ptr[2]);
     ASSERT_EQ(0x00, frame->ptr[3]);
     ASSERT_EQ(0x00, frame->ptr[4]);
     ASSERT_EQ(0x00, frame->ptr[5]);
     payload_siz =
       ((static_cast<size_t>(frame->ptr[6]) & 0xff) << 24) + ((static_cast<size_t>(frame->ptr[7]) & 0xff) << 16) +
       ((static_cast<size_t>(frame->ptr[8]) & 0xff) << 8) + ((static_cast<size_t>(frame->ptr[9]) & 0xff));
     ASSERT_LT(UINT16_MAX, exp_siz);
     ASSERT_EQ(0, memcmp(&frame->ptr[10], exp, exp_siz));
  }
  ASSERT_EQ(exp_siz, payload_siz);
}

TEST_F(ModWebsocketFrameSendTest, RFC_6455) {
  char* data = (char *)malloc(UINT32_MAX);

  hctx.handshake.version = 13;
  // INVALID
  ASSERT_EQ(-1, mod_websocket_frame_send(NULL, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         data, 1));
  ASSERT_EQ(-1, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         NULL, 0));
  ASSERT_EQ(-1, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                         NULL, 0));

  // TEXT <= 125 bytes
  memset(data, 'a', 125);
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        data, 125));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_TEXT, data, 125, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // TEXT >= 126 and TEXT <= UINT16_MAX bytes
  memset(data, 'a', 126);
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        data, 126));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_TEXT, data, 126, hctx.tocli);
  chunkqueue_reset(hctx.tocli);
  memset(data, 'a', UINT16_MAX);
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        data, UINT16_MAX));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_TEXT, data, UINT16_MAX, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // TEXT = UINT16_MAX + 1 bytes
  memset(data, 'a', UINT16_MAX + 1);
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        data, UINT16_MAX + 1));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_TEXT, data, UINT16_MAX + 1, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // BINARY <= 125 bytes
  for (size_t i = 0; i < 125; i++) {
    data[i] = static_cast<char>(i);
  }
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        data, 125));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_BIN, data, 125, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // BINARY >= 126 and BINARY <= UINT16_MAX bytes
  for (size_t i = 0; i < 126; i++) {
    data[i] = static_cast<char>(i);
  }
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        data, 126));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_BIN, data, 126, hctx.tocli);
  chunkqueue_reset(hctx.tocli);
  for (size_t i = 0; i < UINT16_MAX; i++) {
    data[i] = static_cast<char>(i);
  }
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        data, UINT16_MAX));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_BIN, data, UINT16_MAX, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // BINARY = UINT16_MAX + 1 bytes
  for (size_t i = 0; i < UINT16_MAX + 1; i++) {
    data[i] = static_cast<char>(i);
  }
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        data, UINT16_MAX + 1));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_BIN, data, UINT16_MAX + 1, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // PING
  strcpy(data, const_cast<char*>("ping"));
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PING,
                                        data, strlen("ping")));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_PING, data, strlen("ping"), hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PING,
                                        NULL, 0));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_PING, NULL, 0, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // PONG
  strcpy(data, const_cast<char*>("pong"));
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                        data, strlen("pong")));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_PONG, data, strlen("pong"), hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                        NULL, 0));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_PONG, NULL, 0, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // CLOSE
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                        NULL, 0));
  check_frame_rfc_6455(MOD_WEBSOCKET_FRAME_TYPE_CLOSE, NULL, 0, hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  free(data);
}
#endif

static void check_payload(const char* exp, size_t exp_siz, chunkqueue* q) {
  chunk* c = NULL;
  buffer* frame = NULL;

  for (c = q->first; c; c = c->next) {
    if (NULL == frame) {
      frame = buffer_init();
      buffer_copy_memory(frame, c->mem->ptr, c->mem->used);
    } else {
      buffer_append_memory(frame, c->mem->ptr, c->mem->used);
    }
  }
  if (frame->ptr[frame->used - 1] != 0) {
    ASSERT_FALSE(true) << "end of frame invalid";
  }
  ASSERT_EQ(exp_siz, frame->used - 1);
  ASSERT_EQ(0, memcmp(exp, frame->ptr, frame->used - 1));
}

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
TEST_F(ModWebsocketFrameRecvTest, IETF_00) {
  static const char* text = "foo";
  unsigned char binary[256];
  unsigned char* base64;
  size_t base64_siz;

  hctx.handshake.version = 0;
  // INVALID
  ASSERT_EQ(-1, mod_websocket_frame_recv(NULL));

  hctx.fromcli = hctx.tocli;

  // TEXT
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        const_cast<char *>(text),
                                        strlen(text)));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(text, strlen(text), hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // BINARY
  hctx.frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
  for (int i = 0; i < sizeof(binary); i++) {
    binary[i] = i;
  }
  ASSERT_EQ(0, mod_websocket_base64_encode(&base64, &base64_siz,
                                           binary, sizeof(binary)));
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                        reinterpret_cast<char *>(binary),
                                        sizeof(binary)));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(reinterpret_cast<char *>(binary), sizeof(binary), hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // CLOSE
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE,
                                        NULL, 0));
  ASSERT_EQ(-1, mod_websocket_frame_recv(&hctx));
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);
}
#endif

#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
# define        MOD_WEBSOCKET_OPCODE_CONT       (0x00)
# define        MOD_WEBSOCKET_OPCODE_TEXT       (0x01)
# define        MOD_WEBSOCKET_OPCODE_BIN        (0x02)
# define        MOD_WEBSOCKET_OPCODE_CLOSE      (0x08)
# define        MOD_WEBSOCKET_OPCODE_PING       (0x09)
# define        MOD_WEBSOCKET_OPCODE_PONG       (0x0A)

# define        MOD_WEBSOCKET_FRAME_LEN16       (0x7E)
# define        MOD_WEBSOCKET_FRAME_LEN63       (0x7F)
# define        MOD_WEBSOCKET_FRAME_LEN16_CNT   (2)
# define        MOD_WEBSOCKET_FRAME_LEN63_CNT   (8)
# define        MOD_WEBSOCKET_MASK_CNT          (4)

static void mask_payload(char *buf, size_t siz, const char *mask) {
    size_t i;

    for (i = 0; i < siz; i++) {
        buf[i] = buf[i] ^ mask[i % 4];
    }
    return;
}

static int send_rfc_6455_masked(chunkqueue *q, mod_websocket_frame_type_t type, char *payload, size_t siz, char *mask) {
    const char endl = '\0';
    char c, sizbuf[MOD_WEBSOCKET_FRAME_LEN63 + 1];
    buffer *b = NULL;

    /* allowed null payload for ping, pong, close frame */
    if (payload == NULL && (type == MOD_WEBSOCKET_FRAME_TYPE_TEXT || type == MOD_WEBSOCKET_FRAME_TYPE_BIN)) {
        return -1;
    }
    b = chunkqueue_get_append_buffer(q);
    if (!b) {
        return -1;
    }
    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_TEXT);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_BIN);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PING:
        c = (char) (0x80 | MOD_WEBSOCKET_OPCODE_PING);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PONG:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_PONG);
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
    default:
        c = (char)(0x80 | MOD_WEBSOCKET_OPCODE_CLOSE);
        break;
    }
    buffer_append_memory(b, &c, 1);

    if (siz < MOD_WEBSOCKET_FRAME_LEN16) {
        sizbuf[0] = siz | 0x80;
        buffer_append_memory(b, sizbuf, 1);
    } else if (siz <= UINT16_MAX) {
        sizbuf[0] = MOD_WEBSOCKET_FRAME_LEN16 | 0x80;
        sizbuf[1] = (siz >> 8) & 0xff;
        sizbuf[2] = siz & 0xff;
        buffer_append_memory(b, sizbuf, MOD_WEBSOCKET_FRAME_LEN16_CNT + 1);
    } else {
        memset(sizbuf, 0, sizeof(sizbuf));
        sizbuf[0] = MOD_WEBSOCKET_FRAME_LEN63 | 0x80;
        sizbuf[5] = (siz >> 24) & 0xff;
        sizbuf[6] = (siz >> 16) & 0xff;
        sizbuf[7] = (siz >> 8) & 0xff;
        sizbuf[8] = siz & 0xff;
        buffer_append_memory(b, sizbuf, MOD_WEBSOCKET_FRAME_LEN63_CNT + 1);
    }
    buffer_append_memory(b, mask, MOD_WEBSOCKET_MASK_CNT);
    if (siz == 0) {
        /* needs '\0' char to send */
        buffer_append_memory(b, &endl, 1);
        return 0;
    }
    mask_payload(payload, siz, mask);
    buffer_append_memory(b, payload, siz);
    /* needs '\0' char to send */
    buffer_append_memory(b, &endl, 1);
    return 0;
}

TEST_F(ModWebsocketFrameRecvTest, RFC_6455) {
  char* data = (char *)malloc(UINT32_MAX);
  char* mask_data = (char *)malloc(UINT32_MAX);
  char mask[4] = {0x11, 0x22, 0x33, 0x44};

  hctx.handshake.version = 13;
  // INVALID
  ASSERT_EQ(-1, mod_websocket_frame_recv(NULL));

  hctx.fromcli = chunkqueue_init();

  // TEXT <= 125 bytes
  memset(data, 'a', 125);
  memcpy(mask_data, data, 125);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_TEXT, mask_data, 125, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, 125, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // TEXT >= 126 and TEXT <= UINT16_MAX bytes
  memset(data, 'a', 126);
  memcpy(mask_data, data, 126);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_TEXT, mask_data, 126, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, 126, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  memset(data, 'a', UINT16_MAX);
  memcpy(mask_data, data, UINT16_MAX);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_TEXT, mask_data, UINT16_MAX, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, UINT16_MAX, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // TEXT = UINT16_MAX + 1 bytes
  memset(data, 'a', UINT16_MAX + 1);
  memcpy(mask_data, data, UINT16_MAX + 1);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_TEXT, mask_data, UINT16_MAX + 1, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, UINT16_MAX + 1, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // BINARY <= 125 bytes
  for (size_t i = 0; i < 125; i++) {
    data[i] = static_cast<char>(i);
  }
  memcpy(mask_data, data, 125);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_BIN, mask_data, 125, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, 125, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // BINARY >= 126 and BINARY <= UINT16_MAX bytes
  for (size_t i = 0; i < 126; i++) {
    data[i] = static_cast<char>(i);
  }
  memcpy(mask_data, data, 126);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_BIN, mask_data, 126, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, 126, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  for (size_t i = 0; i < UINT16_MAX; i++) {
    data[i] = static_cast<char>(i);
  }
  memcpy(mask_data, data, UINT16_MAX);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_BIN, mask_data, UINT16_MAX, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, UINT16_MAX, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // BINARY = UINT16_MAX + 1 bytes
  for (size_t i = 0; i < UINT16_MAX + 1; i++) {
    data[i] = static_cast<char>(i);
  }
  memcpy(mask_data, data, UINT16_MAX + 1);
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_BIN, mask_data, UINT16_MAX + 1, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(data, UINT16_MAX + 1, hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // PING
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_PING, NULL, 0, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  ASSERT_EQ(1, chunkqueue_is_empty(hctx.tosrv));
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // PONG
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_PONG, NULL, 0, mask));
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  ASSERT_EQ(1, chunkqueue_is_empty(hctx.tosrv));
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  // CLOSE
  ASSERT_EQ(0, send_rfc_6455_masked(hctx.fromcli, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, NULL, 0, mask));
  ASSERT_EQ(-1, mod_websocket_frame_recv(&hctx));
  chunkqueue_reset(hctx.tosrv);
  chunkqueue_reset(hctx.tocli);

  free(data);
  free(mask_data);
}
#endif

TEST_F(ModWebsocketFrameForwardTest, all) {
  static const char* text = "foo";

  // send: INVALID
  ASSERT_EQ(-1, mod_websocket_frame_send(NULL, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         const_cast<char*>(text),
                                         strlen(text)));
  // send: null payload
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                         NULL, 0));
  ASSERT_EQ(1, chunkqueue_is_empty(hctx.tocli));
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_BIN,
                                         NULL, 0));
  ASSERT_EQ(1, chunkqueue_is_empty(hctx.tocli));

  // send: normal
  ASSERT_EQ(0, mod_websocket_frame_send(&hctx, MOD_WEBSOCKET_FRAME_TYPE_TEXT,
                                        const_cast<char *>(text),
                                        strlen(text)));
  check_payload(text, strlen(text), hctx.tocli);
  chunkqueue_reset(hctx.tocli);

  // recv: INVALID
  ASSERT_EQ(-1, mod_websocket_frame_recv(NULL));

  // send: normal
  buffer *b = chunkqueue_get_append_buffer(hctx.fromcli);
  buffer_copy_string(b, text);
  ASSERT_EQ(0, mod_websocket_frame_recv(&hctx));
  check_payload(text, strlen(text), hctx.tosrv);
  chunkqueue_reset(hctx.tosrv);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
