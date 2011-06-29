## $Id$

TESTS = \
	base64_test.sh sha1_test \
	mod_websocket_conv_test mod_websocket_connector_test \
	mod_websocket_handshake_test mod_websocket_frame_test

INCLUDES = \
	-I${top_srcdir}/stub/ \
	-I${top_srcdir}/src/ \
	-I/usr/local/include/ \
	-I/opt/local/include/ \
	-I.

LDADD = \
	-L/opt/local/lib \
	-licui18n -licuuc -lcunit -lev \
	${LIBNCURSES} \
	${top_srcdir}/src/libwebsocket.la \
	${top_srcdir}/stub/libtest.la

CFLAGS = -Wall -g ${WEBSOCKET_VERSION_CFLAGS}

noinst_PROGRAMS = \
	base64_test sha1_test \
	mod_websocket_conv_test \
	mod_websocket_connector_test \
	mod_websocket_handshake_test \
	mod_websocket_frame_test

sha1_test_SOURCES = \
	sha1_test.c

base64_test_SOURCES = \
	base64_test.c

mod_websocket_conv_test_SOURCES = \
	mod_websocket_conv_test.c

mod_websocket_connector_test_SOURCES = \
	mod_websocket_connector_test.c

mod_websocket_handshake_test_SOURCES = \
	mod_websocket_handshake_test.c

mod_websocket_frame_test_SOURCES = \
	mod_websocket_frame_test.c

include $(top_srcdir)/config/Makefile.rules

## EOF
