BUILT_SOURCES = mod_websocket_config_parser.h
AM_YFLAGS = -d
AM_LFLAGS = -i

SUBDIRS = .

noinst_LTLIBRARIES = libmod_websocket_config_parser.la

libmod_websocket_config_parser_la_SOURCES = \
	mod_websocket_config_scanner.l \
	mod_websocket_config_parser.y

libmod_websocket_config_parser_la_CFLAGS = \
	$(ADDITIONAL_CFLAGS)

noinst_PROGRAMS = mod_websocket_config_validator

mod_websocket_config_validator_SOURCES = \
        mod_websocket_config_validator.c

mod_websocket_config_validator_CFLAGS = \
        $(ADDITIONAL_CFLAGS)

mod_websocket_config_validator_LDADD = \
        libmod_websocket_config_parser.la

clean-local:
	${RM} -f *~

distclean-local:
	${RM} -f Makefile.in config.h.in
	${RM} -f mod_websocket_config_scanner.c
	${RM} -f mod_websocket_config_parser.{h,c}
