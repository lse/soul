
EXTRA_DIST = soul-wizard soul.conf.example
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-D_GNU_SOURCE \
	-I${top_srcdir}/src

AM_CFLAGS = ${my_CFLAGS}

AM_LDFLAGS = -lbsd

bin_SCRIPTS = soul-wizard
bin_PROGRAMS = soul

soul_SOURCES = \
		      src/soul.c
