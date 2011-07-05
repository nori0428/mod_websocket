## $Id$

SUBDIRS = \
	. tests samples

INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/stub \
	-I${top_srcdir}/src \
	-I/usr/local/include \
	-I/opt/local/include \
	-I.

noinst_LTLIBRARIES = libwebsocket.la

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

include $(top_srcdir)/m4/Makefile.rules

## EOF
