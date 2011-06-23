## $Id$

SUBDIRS = \
	. tests

INCLUDES = \
	-I${top_src_dir}/src \
	-I/opt/local/include \
	-I .

noinst_LTLIBRARIES = libwebsocket.la

libwebsocket_la_SOURCES = \
	base64.h \
	base64.c \
	sha1.h \
	sha1.c \
	mod_websocket_types.h \
	mod_websocket_conv.h \
	mod_websocket_conv.c

include $(top_srcdir)/config/Makefile.rules

## EOF
