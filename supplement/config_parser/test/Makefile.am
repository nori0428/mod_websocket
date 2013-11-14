TESTS = \
	mod_websocket_config_parser_test

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/../../contrib/gtest-1.7.0/include

LDADD = \
	$(top_srcdir)/src/libmod_websocket_config_parser.la \
	$(top_srcdir)/../../contrib/gtest-1.7.0/lib/libgtest.la

check_PROGRAMS = \
	mod_websocket_config_parser_test

mod_websocket_config_parser_test_SOURCES = \
	mod_websocket_config_parser_test.cpp

clean-local:
	${RM} -f *~

distclean-local:
	${RM} -f Makefile.in

