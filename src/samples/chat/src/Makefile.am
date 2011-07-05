## $Id$

INCLUDES = \
        -I/usr/local/include/ \
        -I/opt/local/include/ \
        -I.

LDADD = \
        -L/usr/local/lib \
        -L/opt/local/lib \
        -lev

CFLAGS = -Wall -g

noinst_PROGRAMS = \
	chat

ws_chat_SOURCES = \
        chat.c

include $(top_srcdir)/config/Makefile.rules

## EOF
