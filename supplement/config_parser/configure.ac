AC_INIT([mod_websocket_config_parser], [1.0], [nori.0428@gmail.com])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/mod_websocket_config.h])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([src/config.h])

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
AC_PROG_CXX
AC_PROG_LIBTOOL
AM_PROG_LEX
if test "x$LEX" = "x"; then
   AC_MSG_ERROR([plz install flex etc.])
fi
AC_PROG_YACC
if test "x$YACC" = "x"; then
   AC_MSG_ERROR([plz install bison etc.])
fi

# Checks for --enable-debug
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

# Checks for --with-test
AC_MSG_CHECKING(whether --with-test option specified)
AC_ARG_WITH([test],
            AC_HELP_STRING([--with-test],
                           [make tests of mod_websocket_config_parser@<:@default=no@:>@]),
            [test="$withval"], [test=no])
AC_MSG_RESULT(${test})
AM_CONDITIONAL(WITH_TEST, test x$test != xno)

# additional CFLAGS
# add -Wno-sign-compare and remove -Wundef for flex
ADDITIONAL_CFLAGS="-Werror -W -Wall -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wno-sign-compare -Waggregate-return -Wnested-externs -Wno-long-long -Wunused -Wfloat-equal -Wformat -fno-strict-aliasing"
AC_SUBST(ADDITIONAL_CFLAGS)

AC_CONFIG_FILES([Makefile \
                 src/Makefile \
                 test/Makefile])

AC_OUTPUT
