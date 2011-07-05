#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([mod_websocket], [0.1], [nori.0428@gmail.com])
AC_CONFIG_SRCDIR([src/mod_websocket.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unicode/ucnv.h unicode/ucsdet.h CUnit/CUnit.h CUnit/Basic.h])

# Checks for libraries.
CFLAGS="$CFLAGS -I/usr/local/lib -I/opt/local/inclue"
LDFLAGS="$LDFLAGS -L/usr/local/lib -L/opt/local/lib"
LIBS="-licui18n"
AC_CHECK_LIB(ev, ev_io_start, has_libev=yes, AC_MSG_ERROR([cant test mod_websocket]))
AC_CHECK_LIB(cunit, CU_basic_run_tests, has_libcunit=yes, AC_MSG_ERROR([cant test mod_websocket]))
AC_MSG_CHECKING([libicui18n exists])
AC_TRY_LINK([#include <unicode/ucnv.h>], [int err; ucnv_open("utf-8", &err)],
            AC_MSG_RESULT(yes),
            [AC_MSG_RESULT(no); AC_MSG_ERROR([needs ICU libs])])
CFLGAS=""
LDFLAGS=""
LIBS=""

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(size_t)

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

# Check for websocket version
AC_MSG_CHECKING(whether --with-websocket option specified)
AC_ARG_WITH(
        websocket,
        [  --with-websocket@<:@=IETF-{00,08}@:>@
                                  specify draft version : default=IETF-00],
        [ websocket=$withval ],
        [ websocket=yes ])
AC_MSG_RESULT(${websocket})
if test "x${websocket}" == "xyes" ||
   test "x${websocket}" == "xietf-00" ||
   test "x${websocket}" == "xIETF-00"; then
   WEBSOCKET_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_00_"
elif test "x${websocket}" == "xietf-08" ||
     test "x${websocket}" == "xIETF-08"; then
   WEBSOCKET_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_08_"
elif test "x${websocket}" != "xno"; then
   AC_MSG_ERROR([websocket option is invalid. plz specify IETF-{00,08}])
fi
AC_SUBST(WEBSOCKET_VERSION_CFLAGS)
CFLAGS="$CFLAGS $WEBSOCKET_VERSION_CFLAGS"

case $host_os in
     *darwin* ) LIBNCURSES="-lncurses";;
     * ) LIBNCURSES=;;
esac
AC_SUBST(LIBNCURSES)

# Check for websocket version
AC_MSG_CHECKING(whether --with-lighttpd option specified)
AC_ARG_WITH(
        lighttpd,
        [  --with-lighttpd
                                  specify lighttpd location : default=no],
        [ lighttpd=$withval ],
        [ lighttpd=no ])
AC_MSG_RESULT(${lighttpd})
if test "x${lighttpd}" != "xno"; then
   LIGHTTPD_LOCATION=${lighttpd}
   AC_SUBST(LIGHTTPD_LOCATION)
fi

AC_OUTPUT(\
	Makefile \
	stub/Makefile \
	src/Makefile \
	src/tests/Makefile \
)

# EOF
