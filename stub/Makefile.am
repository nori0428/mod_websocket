## $Id$

SUBDIRS = \
	.

INCLUDES = \
	-I${top_srcdir} \
	-I/opt/local/include \
	-I/usr/local/include \
	-I.

noinst_LTLIBRARIES = libtest.la

libtest_la_SOURCES = \
	settings.h \
	buffer.h \
	buffer.c \
	array.h \
	array.c \
	chunk.h \
	chunk.c \
	data_string.c \
	data_array.c \
	log.h \
	log.c \
	md5.h \
	md5.c

include $(top_srcdir)/m4/Makefile.rules

## EOF
