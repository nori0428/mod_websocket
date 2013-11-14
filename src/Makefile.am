noinst_LTLIBRARIES = libmod_websocket.la

libmod_websocket_la_SOURCES = \
	mod_websocket_base64.h \
	mod_websocket_base64.c \
	mod_websocket_sha1.h \
	mod_websocket_sha1.c \
	mod_websocket.h \
	mod_websocket_socket.h \
	mod_websocket_socket.c \
	mod_websocket_handshake.c \
	mod_websocket_frame.c

libmod_websocket_la_CFLAGS = -I$(top_srcdir)/stub $(MODULE_CFLAGS)

clean-local:
	${RM} -f *~
