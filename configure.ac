#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([mod_websocket], [0.1], [nori.0428@gmail.com])
AC_CONFIG_SRCDIR([src/mod_websocket.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_AUX_DIR(m4)

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unicode/ucnv.h unicode/ucsdet.h CUnit/CUnit.h CUnit/Basic.h])

# Checks for libraries.
CFLAGS="$CFLAGS -I/usr/local/include/ -I/opt/local/include/"
LDFLAGS="$LDFLAGS -L/usr/local/lib/ -L/opt/local/lib/"
LIBS="-licui18n -licuuc"
AC_CHECK_LIB(ev, ev_io_start, has_libev=yes, AC_MSG_ERROR([cant test mod_websocket]))
AC_CHECK_LIB(cunit, CU_basic_run_tests, has_libcunit=yes, AC_MSG_ERROR([cant test mod_websocket]))
AC_MSG_CHECKING([for ucnv_open in -licui18n])
AC_TRY_LINK([#include <unicode/ucnv.h>], [int err; ucnv_open("utf-8", &err);],
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
        AC_HELP_STRING([--with-websocket@<:@={RFC-6455, IETF-{00,08}}@:>@],
                       [specify draft version@<:@default=RFC-6455@:>@]),
        [ websocket=$withval ],
        [ websocket=yes ])
AC_MSG_RESULT(${websocket})
if test "x${websocket}" == "xyes" ||
   test "x${websocket}" == "xrfc-6455" ||
   test "x${websocket}" == "xRFC-6455"; then
   websocket="RFC-6455"
   WEBSOCKET_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" == "xietf-00" ||
     test "x${websocket}" == "xIETF-00"; then
   WEBSOCKET_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_00_"
elif test "x${websocket}" == "xietf-08" ||
     test "x${websocket}" == "xIETF-08"; then
   WEBSOCKET_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_08_"
elif test "x${websocket}" != "xno"; then
   AC_MSG_ERROR([websocket option is invalid. plz specify IETF-{00,08}, RFC-6455])
fi
AC_SUBST(WEBSOCKET_VERSION_CFLAGS)
CFLAGS="$CFLAGS $WEBSOCKET_VERSION_CFLAGS"

dnl check for icu lib
AC_MSG_CHECKING(whether --with-libicu option specified)
AC_ARG_WITH(
        libicu,
        AC_HELP_STRING([--with-libicu],
                       [use ICU lib for websocket@<:@default=yes@:>@]),
        [ with_icu=$withval ],
        [ with_icu=yes ])
AC_MSG_RESULT(${with_icu})
if test "x${with_icu}" != "xno"; then
   WEBSOCKET_ICU_CFLAGS="-D_MOD_WEBSOCKET_WITH_ICU_"
   WEBSOCKET_ICU_LIBS="-licui18n -licuuc"
else
   WEBSOCKET_ICU_CFLAGS=
   WEBSOCKET_ICU_LIBS=
fi
AC_SUBST(WEBSOCKET_ICU_CFLAGS)
AC_SUBST(WEBSOCKET_ICU_LIBS)
AM_CONDITIONAL(WITH_LIBICU, test x$with_icu != xno)
CFLAGS="$CFLAGS $WEBSOCKET_ICU_CFLAGS"

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
	src/samples/Makefile \
	src/samples/chat/Makefile \
	src/samples/chat/src/Makefile \
)

# EOF
