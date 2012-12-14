## $Id$

if WITH_LIBICU
TESTS = \
	base64_test.sh sha1_test \
	mod_websocket_conv_test mod_websocket_connector_test \
	mod_websocket_handshake_test mod_websocket_frame_test \
	mod_websocket_config_test
else
TESTS = \
	base64_test.sh sha1_test \
	mod_websocket_connector_test \
	mod_websocket_handshake_test mod_websocket_frame_test \
	mod_websocket_config_test
endif

INCLUDES = \
	-I${top_srcdir}/stub/ \
	-I${top_srcdir}/src/

LDADD = \
	${top_srcdir}/src/libwebsocket.la \
	${top_srcdir}/stub/libtest.la

if WITH_LIBICU
noinst_PROGRAMS = \
	base64_encode_test base64_decode_test sha1_test \
	mod_websocket_conv_test \
	mod_websocket_connector_test \
	mod_websocket_handshake_test \
	mod_websocket_frame_test \
	mod_websocket_config_test
else
noinst_PROGRAMS = \
	base64_encode_test base64_decode_test sha1_test \
	mod_websocket_connector_test \
	mod_websocket_handshake_test \
	mod_websocket_frame_test \
	mod_websocket_config_test
endif

sha1_test_SOURCES = \
	sha1_test.c

base64_encode_test_SOURCES = \
	base64_encode_test.c

base64_decode_test_SOURCES = \
	base64_decode_test.c

if WITH_LIBICU
mod_websocket_conv_test_SOURCES = \
	mod_websocket_conv_test.c
endif

mod_websocket_connector_test_SOURCES = \
	mod_websocket_connector_test.c

mod_websocket_handshake_test_SOURCES = \
	mod_websocket_handshake_test.c

mod_websocket_frame_test_SOURCES = \
	mod_websocket_frame_test.c

mod_websocket_config_test_SOURCES = \
	mod_websocket_config_test.c

include $(top_srcdir)/m4/Makefile.rules

## EOF
