#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([restmbmaster], [4], [jiri@resnulli.us])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)], [])
AM_PROG_AR

CFLAGS="$CFLAGS -Wall"

# Checks for programs.
AC_PROG_CC
LT_INIT

PKG_CHECK_MODULES([LIBMODBUS], [libmodbus])
PKG_CHECK_MODULES([LIBMICROHTTPD], [libmicrohttpd])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile
src/Makefile \
man/Makefile])
AC_OUTPUT
