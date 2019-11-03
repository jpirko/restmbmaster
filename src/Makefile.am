MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

restmbmaster_CFLAGS= $(LIBMODBUS_CFLAGS) $(LIBMICROHTTPD_CFLAGS) -D_GNU_SOURCE
restmbmaster_LDADD = $(LIBMODBUS_LIBS) $(LIBMICROHTTPD_LIBS)

bin_PROGRAMS=restmbmaster
restmbmaster_SOURCES=restmbmaster.c
