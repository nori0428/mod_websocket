TESTS = \
	mod_websocket_base64_test.sh mod_websocket_sha1_test mod_websocket_handshake_test

AM_CPPFLAGS = \
	-I$(top_srcdir)/stub/ \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/contrib/gtest-1.7.0/include \
	$(SUPPORT_VERSION_CFLAGS)

LDADD = \
	$(top_srcdir)/src/libmod_websocket.la \
	$(top_srcdir)/stub/libstub.la \
	$(top_srcdir)/contrib/gtest-1.7.0/lib/libgtest.la

noinst_PROGRAMS = \
	mod_websocket_base64_encode_test mod_websocket_base64_decode_test mod_websocket_sha1_test \
	mod_websocket_handshake_test

mod_websocket_base64_encode_test_SOURCES = \
	mod_websocket_base64_encode_test.c

mod_websocket_base64_decode_test_SOURCES = \
	mod_websocket_base64_decode_test.c

mod_websocket_sha1_test_SOURCES = \
	mod_websocket_sha1_test.cpp

mod_websocket_handshake_test_SOURCES = \
	mod_websocket_handshake_test.cpp

clean-local:
	${RM} -f *~
