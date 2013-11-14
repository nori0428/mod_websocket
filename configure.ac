AC_INIT([mod_websocket], [2.7], [nori.0428@gmail.com])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/mod_websocket.h])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([src/config.h])

AC_CANONICAL_HOST
case $host_os in
     *darwin* )
              CFLAGS="$CFLAGS -I/opt/local/include/"
              LDFLAGS="$LDFLAGS -L/opt/local/lib/";;
     * )
              CFLAGS="$CFLAGS -I/usr/local/include/"
              LDFLAGS="$LDFLAGS -L/usr/local/lib/"
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL

# Checks for making test
AC_MSG_CHECKING(whether --enable-debug option specified)
AC_ARG_ENABLE([debug],
              AC_HELP_STRING([--enable-debug], [no optimization@<:@default=no@:>@]),
              [debug="$enableval"], [debug=no])
AC_MSG_RESULT(${debug})
if test "x${debug}" != "xno"; then
   CFLAGS="$CFLAGS -g"
else
   CFLAGS="$CFLAGS -O3"
fi

# Checks for making test
AC_MSG_CHECKING(whether --with-test option specified)
AC_ARG_WITH([test],
            AC_HELP_STRING([--with-test],
                           [make tests of mod_websocket@<:@default=yes@:>@]),
            [with_test="$withval"], [with_test=yes])
AC_MSG_RESULT(${with_test})
AM_CONDITIONAL(WITH_TEST, test x$with_test != xno)

# Check for websocket version
AC_MSG_CHECKING(whether --with-websocket option specified)
AC_ARG_WITH([websocket],
            AC_HELP_STRING([--with-websocket@<:@=ALL/RFC-6455/IETF-00@:>@],
                           [support WebSocket version@<:@default=ALL@:>@]),
            [websocket="$withval"], [websocket=ALL])
AC_MSG_RESULT(${websocket})
if test "x${websocket}" = "xall" -o "x${websocket}" = "xALL" ; then
   MODULE_CFLAGS="$MODULE_CFLAGS -D_MOD_WEBSOCKET_SPEC_IETF_00_ -D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xrfc-6455" -o "x${websocket}" = "xRFC-6455" ; then
   MODULE_CFLAGS="$MODULE_CFLAGS -D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xietf-00" -o "x${websocket}" = "xIETF-00" ; then
   MODULE_CFLAGS="$MODULE_CFLAGS -D_MOD_WEBSOCKET_SPEC_IETF_00_"
elif test "x${websocket}" != "xno" ; then
   AC_MSG_ERROR([websocket option is invalid. plz specify ALL, IETF-00, RFC-6455])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
   MODULE_CFLAGS="$MODULE_CFLAGS -DWORDS_BIGENDIAN"
fi

# Check for target lighttpd
AC_MSG_CHECKING(whether --with-lighttpd option specified)
AC_ARG_WITH([lighttpd],
            AC_HELP_STRING([--with-lighttpd@<:@=/path/to/lighttpd@:>@],
                           [specify lighttpd location@<:@default=no:>@]),
            [lighttpd="$withval"],[lighttpd=no])
AC_MSG_RESULT(${lighttpd})
if test "x${lighttpd}" != "xno"; then
   LIGHTTPD_LOCATION=${lighttpd}
   AC_SUBST(LIGHTTPD_LOCATION)
fi

# additional CFLAGS
# add -Wno-sign-compare and remove -Wundef for flex
MODULE_CFLAGS="$MODULE_CFLAGS -Werror -W -Wall -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wno-sign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"
AC_SUBST(MODULE_CFLAGS)

AC_CONFIG_FILES([Makefile \
                 stub/Makefile \
                 src/Makefile \
                 test/Makefile])

if test "x${with_test}" = "xyes" ; then
   AC_CONFIG_SUBDIRS(contrib/gtest-1.7.0)
fi

AC_OUTPUT

