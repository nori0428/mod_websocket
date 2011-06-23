## $Id$

TESTS = \
	base64_test.sh sha1_test mod_websocket_conv_test

INCLUDES = \
	-I${top_srcdir}/src/ \
	-I/opt/local/include/ \
	-I.

LDADD = \
	-L/opt/local/lib \
	-licui18n -licuuc -lcunit \
	${top_srcdir}/src/libwebsocket.la

CFLAGS = -Wall -g

noinst_PROGRAMS = \
	base64_test sha1_test mod_websocket_conv_test

sha1_test_SOURCES = \
	sha1_test.c

base64_test_SOURCES = \
	base64_test.c

mod_websocket_conv_test_SOURCES = \
	mod_websocket_conv_test.c

include $(top_srcdir)/config/Makefile.rules

## EOF
