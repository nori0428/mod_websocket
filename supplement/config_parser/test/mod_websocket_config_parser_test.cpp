#include <gtest/gtest.h>

#include <string>

#include "mod_websocket_config.h"

class ModWebsocketConfigParserTest : public testing::Test {
protected:
  ModWebsocketConfigParserTest() {}
  ~ModWebsocketConfigParserTest() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
};

void check_ipv4_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.1";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_ipv6_resource(mod_websocket_backend_t *backend) {
  static const char* host = "::1";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_portnum_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.2";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_comment_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.3";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_regexp_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.4";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_origins_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.5";
  static const char* origin1 = "^http:\\/\\/192\\.168\\.0\\..*";
  static const char* origin2 = "^http:\\/\\/res2\\.com\\/.*";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins != NULL);
  mod_websocket_origin_t *origin = backend->origins;
  ASSERT_STREQ(origin2, origin->origin);
  ASSERT_TRUE(origin->next != NULL);
  origin = origin->next;
  ASSERT_STREQ(origin1, origin->origin);
  ASSERT_TRUE(origin->next == NULL);
}

void check_tcp_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.6";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 0, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_tcp_bin_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.7";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 1, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_tcp_bin2_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.8";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 1, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_tcp_bin3_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.9";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP, 1, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins == NULL);
}

void check_websocket_resource(mod_websocket_backend_t *backend) {
  static const char* host = "192.168.0.10";
  static const char* origin = "^http:\\/\\/192\\.168\\.0\\..*";
  mod_websocket_backend_t test_backend = {
    const_cast<char*>(host), 10000, MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET, 1, NULL
  };
  ASSERT_TRUE(backend != NULL);
  ASSERT_STREQ(test_backend.host, backend->host);
  ASSERT_EQ(test_backend.port, backend->port);
  ASSERT_EQ(test_backend.proto, backend->proto);
  ASSERT_EQ(test_backend.binary, backend->binary);
  ASSERT_TRUE(backend->origins != NULL);
  ASSERT_STREQ(origin, backend->origins->origin);
  ASSERT_TRUE(backend->origins->next == NULL);
}

TEST_F(ModWebsocketConfigParserTest, all) {
  mod_websocket_origin_t *origin = NULL;
  mod_websocket_backend_t *backend = NULL;
  mod_websocket_resource_t *resource = NULL;
  mod_websocket_config_t* config = NULL;
  std::string key;
  int checked = 0;

  config = mod_websocket_config_parse("./test.conf");
  ASSERT_TRUE(config != NULL);
  for (resource = config->resources; resource; resource = resource->next) {
    ASSERT_TRUE(resource->key != NULL);
    key = resource->key;
    if (key == "/ipv4") {
      check_ipv4_resource(resource->backend);
      checked++;
    } else if (key == "/ipv6") {
      check_ipv6_resource(resource->backend);
      checked++;
    } else if (key == "/portnum") {
      check_portnum_resource(resource->backend);
      checked++;
    } else if (key == "/comment") {
      check_comment_resource(resource->backend);
      checked++;
    } else if (key == "^\\/regExp\\/.*") {
      check_regexp_resource(resource->backend);
      checked++;
    } else if (key == "/origins") {
      check_origins_resource(resource->backend);
      checked++;
    } else if (key == "/tcp") {
      check_tcp_resource(resource->backend);
      checked++;
    } else if (key == "/tcp-bin") {
      check_tcp_bin_resource(resource->backend);
      checked++;
    } else if (key == "/websocket") {
      check_websocket_resource(resource->backend);
      checked++;
    } else {
      ASSERT_FALSE(true);
    }
  }
  ASSERT_EQ(9, checked);
  ASSERT_EQ(20, config->ping_interval);
  ASSERT_EQ(200, config->timeout);
  ASSERT_EQ(2, config->debug);
  mod_websocket_config_print(config);
  mod_websocket_config_free(config);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
