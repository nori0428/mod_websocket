#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([mod_websocket], [0.1], [nori.0428@gmail.com])
AC_CONFIG_SRCDIR([src/mod_websocket.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# AC_CHECK_LIB([json], [main])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unicode/ucnv.h unicode/ucsdet.h CUnit/CUnit.h CUnit/Basic.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
   CFLAGS="$CFLAGS -DWORDS_BIGENDIAN"
fi

# Checks for basic programs
AC_PROG_LN_S
AC_PROG_LIBTOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strcasecmp])

CFLAGS="-g -Werror -W -Wall -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wsign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"

AC_OUTPUT(\
	Makefile \
	src/Makefile \
	src/tests/Makefile \
)

# EOF
