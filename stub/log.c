/**
 * $Id$
 * log.c for test
 */

#include <stdio.h>
#include <stdarg.h>

#include "buffer.h"
#include "log.h"

int
log_error_write(void *dummy, const char *fname, unsigned int line,
                const char *fmt, ...) {
    va_list ap;
    buffer *log = buffer_init();

    dummy = dummy;
    buffer_append_string(log, "LOG4TEST: ");
    buffer_append_string(log, fname);
    buffer_append_string_len(log, CONST_STR_LEN(":"));
    buffer_append_long(log, line);
    buffer_append_string_len(log, CONST_STR_LEN(" "));
    for(va_start(ap, fmt); *fmt; fmt++) {
        int d;
        char *s;
        buffer *b;
        off_t o;

        switch(*fmt) {
        case 's':           /* string */
            s = va_arg(ap, char *);
            buffer_append_string(log, s);
            buffer_append_string_len(log, CONST_STR_LEN(" "));
            break;
        case 'b':           /* buffer */
            b = va_arg(ap, buffer *);
            buffer_append_string_buffer(log, b);
            buffer_append_string_len(log, CONST_STR_LEN(" "));
            break;
        case 'd':           /* int */
            d = va_arg(ap, int);
            buffer_append_long(log, d);
            buffer_append_string_len(log, CONST_STR_LEN(" "));
            break;
        case 'o':           /* off_t */
            o = va_arg(ap, off_t);
            buffer_append_off_t(log, o);
            buffer_append_string_len(log, CONST_STR_LEN(" "));
            break;
        case 'x':           /* int (hex) */
            d = va_arg(ap, int);
            buffer_append_string_len(log, CONST_STR_LEN("0x"));
            buffer_append_long_hex(log, d);
            buffer_append_string_len(log, CONST_STR_LEN(" "));
            break;
        case 'S':           /* string */
            s = va_arg(ap, char *);
            buffer_append_string(log, s);
            break;
        case 'B':           /* buffer */
            b = va_arg(ap, buffer *);
            buffer_append_string_buffer(log, b);
            break;
        case 'D':           /* int */
            d = va_arg(ap, int);
            buffer_append_long(log, d);
            break;
        case 'O':           /* off_t */
            o = va_arg(ap, off_t);
            buffer_append_off_t(log, o);
            break;
        case 'X':           /* int (hex) */
            d = va_arg(ap, int);
            buffer_append_string_len(log, CONST_STR_LEN("0x"));
            buffer_append_long_hex(log, d);
            break;
        case '(':
        case ')':
        case '<':
        case '>':
        case ',':
        case ' ':
            buffer_append_string_len(log, fmt, 1);
            break;
        }
    }
    va_end(ap);
    buffer_append_string_len(log, CONST_STR_LEN("\n"));
    fprintf(stderr, "%s", log->ptr);
    return 0;
}

/* EOF */

