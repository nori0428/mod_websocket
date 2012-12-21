#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([mod_websocket], [1.0], [nori.0428@gmail.com])
AC_CONFIG_SRCDIR([src/mod_websocket.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_AUX_DIR(m4)
AM_INIT_AUTOMAKE

AC_CANONICAL_HOST
case $host_os in
     *darwin* )
              CFLAGS="$CFLAGS -I/opt/local/include/"
              LDFLAGS="$LDFLAGS -L/opt/local/lib/"
              LIBS="$LIBS -lncurses";;
     * )
              CFLAGS="$CFLAGS -I/usr/local/include/"
              LDFLAGS="$LDFLAGS -L/usr/local/lib/"
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_LEX
AC_PROG_YACC

# Checks for making test
AC_MSG_CHECKING(whether --with-test option specified)
AC_ARG_WITH(
        test,
        AC_HELP_STRING([--with-test],
                       [make test of mod_websocket@<:@default=no@:>@]),
        [ with_test=$withval ],
        [ with_test=yes ])
AC_MSG_RESULT(${with_test})
if test "x${with_test}" = "xyes" ; then
   AC_CHECK_LIB(ev, ev_io_start, has_libev=yes, AC_MSG_ERROR([needs libev]))
   AC_CHECK_LIB(cunit, CU_basic_run_tests, has_cunit=yes, AC_MSG_ERROR([needs libcunit]))
   LDFLAGS="$LDFLAGS -lev -lcunit"
fi
AM_CONDITIONAL(WITH_TEST, test x$with_test != xno)

# Checks for making sample
AC_MSG_CHECKING(whether --with-sample option specified)
AC_ARG_WITH(
        sample,
        AC_HELP_STRING([--with-sample],
                       [make sample of mod_websocket@<:@default=no@:>@]),
        [ with_sample=$withval ],
        [ with_sample=no ])
AC_MSG_RESULT(${with_sample})
if test "x${with_sample}" = "xyes" ; then
   AC_CHECK_LIB(ev, ev_io_start, has_libev=yes, AC_MSG_ERROR([needs libev]))
   LDFLAGS="$LDFLAGS -lev"
fi
AM_CONDITIONAL(WITH_SAMPLE, test x$with_sample = xyes)

# Check for libicu
AC_MSG_CHECKING(whether --with-libicu option specified)
AC_ARG_WITH(
        libicu,
        AC_HELP_STRING([--with-libicu],
                       [use ICU lib for websocket@<:@default=yes@:>@]),
        [ with_libicu=$withval ],
        [ with_libicu=yes ])
AC_MSG_RESULT(${with_libicu})
if test "x${with_libicu}" != "xno"; then
   LIBS="$LIBS -licui18n -licuuc"
   CFLAGS="$CFLAGS -D_MOD_WEBSOCKET_WITH_ICU_"
   if test "x${with_libicu}" != "xyes"; then
      LDFLAGS="$LDFLAGS -L${with_icu}"
   fi
   AC_MSG_CHECKING([for ucnv_open in -licui18n])
   AC_TRY_LINK([#include <unicode/ucnv.h>],
               [UErrorCode err = U_ZERO_ERROR; ucnv_open("utf-8", &err);],
               AC_MSG_RESULT(yes),
               [AC_MSG_RESULT(no); AC_MSG_ERROR([needs ICU libs])])
fi
AM_CONDITIONAL(WITH_LIBICU, test x$with_libicu != xno)

# Check for websocket version
AC_MSG_CHECKING(whether --with-websocket option specified)
AC_ARG_WITH(
        websocket,
        AC_HELP_STRING([--with-websocket@<:@=ALL/RFC-6455/IETF-00@:>@],
                       [specify draft version@<:@default=ALL@:>@]),
        [ websocket=$withval ],
        [ websocket=ALL ])
AC_MSG_RESULT(${websocket})
if test "x${websocket}" = "xall" -o "x${websocket}" = "xALL" ; then
   CFLAGS="$CFLAGS -D_MOD_WEBSOCKET_SPEC_IETF_00_ -D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xrfc-6455" -o "x${websocket}" = "xRFC-6455" ; then
   CFLAGS="$CFLAGS -D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xietf-00" -o "x${websocket}" = "xIETF-00" ; then
   CFLAGS="$CFLAGS -D_MOD_WEBSOCKET_SPEC_IETF_00_"
elif test "x${websocket}" != "xno" ; then
   AC_MSG_ERROR([websocket option is invalid. plz specify ALL, IETF-00, RFC-6455])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
   CFLAGS="$CFLAGS -DWORDS_BIGENDIAN"
fi

# Check for target lighttpd
AC_MSG_CHECKING(whether --with-lighttpd option specified)
AC_ARG_WITH(
        lighttpd,
        AC_HELP_STRING([--with-lighttpd@<:@=/path/to/lighttpd@:>@],
                       [specify lighttpd location@<:@default=no:>@]),
        [ lighttpd=$withval ],
        [ lighttpd=no ])
AC_MSG_RESULT(${lighttpd})
if test "x${lighttpd}" != "xno"; then
   LIGHTTPD_LOCATION=${lighttpd}
   AC_SUBST(LIGHTTPD_LOCATION)
fi

# additional CFLAGS
# add -Wno-sign-compare and remove -Wundef for flex
if test "x${with_test}" = "xyes" -o "x${with_sample}" = "xyes" ; then
   MODULE_CFLAGS="-g -O3 -Werror -W -Wall -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wno-sign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"
else
   MODULE_CFLAGS="-O3 -Werror -W -Wall -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wno-sign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"
fi
AC_SUBST(MODULE_CFLAGS)

AC_OUTPUT(\
        Makefile \
        src/Makefile \
)
if test "x${with_test}" == "xyes" ; then
   AC_OUTPUT(\
       stub/Makefile \
       src/tests/Makefile \
   )
fi
if test "x${with_sample}" == "xyes" ; then
   AC_OUTPUT(\
       src/samples/Makefile \
       src/samples/chat/Makefile \
       src/samples/chat/src/Makefile \
   )
fi

# EOF
