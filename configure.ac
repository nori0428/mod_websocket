AC_INIT([mod_websocket], [3.1], [nori.0428@gmail.com])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/mod_websocket.h])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([src/config.h])

AC_CANONICAL_HOST
case $host_os in
     *darwin* )
              CFLAGS="$CFLAGS -I/opt/local/include/"
              CXXFLAGS="$CXXFLAGS -I/opt/local/include/"
              LDFLAGS="$LDFLAGS -L/opt/local/lib/";;
     * )
              CFLAGS="$CFLAGS -I/usr/local/include/"
              CXXFLAGS="$CXXFLAGS -I/usr/local/include/"
              LDFLAGS="$LDFLAGS -L/usr/local/lib/"
esac

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL

AC_MSG_CHECKING(whether --enable-debug option specified)
AC_ARG_ENABLE([debug],
              AC_HELP_STRING([--enable-debug], [no optimization@<:@default=no@:>@]),
              [debug="$enableval"], [debug=no])
AC_MSG_RESULT(${debug})
if test "x${debug}" != "xno"; then
   CFLAGS="$CFLAGS -g"
   CXXFLAGS="$CXXFLAGS -g"
else
   CFLAGS="$CFLAGS -O3"
   CXXFLAGS="$CXXFLAGS -O3"
fi

AC_MSG_CHECKING(whether --with-test option specified)
AC_ARG_WITH([test],
            AC_HELP_STRING([--with-test],
                           [make tests of mod_websocket@<:@default=yes@:>@]),
            [with_test="$withval"], [with_test=yes])
AC_MSG_RESULT(${with_test})
AM_CONDITIONAL(WITH_TEST, test x$with_test != xno)

AC_MSG_CHECKING(whether --with-websocket option specified)
AC_ARG_WITH([websocket],
            AC_HELP_STRING([--with-websocket@<:@=all/rfc-6455/ietf-00@:>@],
                           [support WebSocket version@<:@default=all@:>@]),
            [websocket="$withval"], [websocket=all])
AC_MSG_RESULT(${websocket})
if test "x${websocket}" = "xall" -o "x${websocket}" = "xALL" ; then
   SUPPORT_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_00_ -D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xrfc-6455" -o "x${websocket}" = "xRFC-6455" ; then
   SUPPORT_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_RFC_6455_"
elif test "x${websocket}" = "xietf-00" -o "x${websocket}" = "xIETF-00" ; then
   SUPPORT_VERSION_CFLAGS="-D_MOD_WEBSOCKET_SPEC_IETF_00_"
elif test "x${websocket}" != "xno" ; then
   AC_MSG_ERROR([websocket option is invalid. plz specify all, ietf-00, rfc-6455])
fi
AC_SUBST(SUPPORT_VERSION_CFLAGS)

AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
   ENDIAN_CFLAGS="-DWORDS_BIGENDIAN"
fi
AC_CHECK_HEADERS([stdint.h pcre.h])
AC_CHECK_LIB([pcre], [pcre_compile])
AC_CHECK_LIB([pthread], [pthread_create])

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

MODULE_CFLAGS="$SUPPORT_VERSION_CFLAGS $ENDIAN_CFLAGS -Werror -W -Wall -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wno-sign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"
AC_SUBST(MODULE_CFLAGS)

AC_CONFIG_FILES([Makefile \
                 src/Makefile \
                 test/Makefile \
                 test/stub/Makefile \
                 ])

if test "x${with_test}" = "xyes" ; then
   AC_CONFIG_SUBDIRS(contrib/gtest-1.7.0)
fi

AC_OUTPUT

