## $Id$

if WITH_TEST
TESTS_DIR = tests
endif

if WITH_SAMPLE
SAMPLES_DIR = samples
endif

SUBDIRS = \
	. $(TESTS_DIR) $(SAMPLES_DIR)

INCLUDES = \
	-I${top_srcdir}/stub

noinst_LTLIBRARIES = libwebsocket.la

if WITH_LIBICU
libwebsocket_la_SOURCES = \
	base64.h \
	base64.c \
	sha1.h \
	sha1.c \
	mod_websocket.h \
	mod_websocket_conv.c \
	mod_websocket_connector.c \
	mod_websocket_handshake.c \
	mod_websocket_frame.c
libwebsocket_la_CFLAGS = $(MODULE_CFLAGS)
else
libwebsocket_la_SOURCES = \
	base64.h \
	base64.c \
	sha1.h \
	sha1.c \
	mod_websocket.h \
	mod_websocket_connector.c \
	mod_websocket_handshake.c \
	mod_websocket_frame.c
libwebsocket_la_CFLAGS = $(MODULE_CFLAGS)
endif

include $(top_srcdir)/m4/Makefile.rules

## EOF
