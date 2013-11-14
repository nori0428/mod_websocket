SUBDIRS = src

if WITH_TEST
SUBDIRS += test
endif

clean-local:
	${RM} -f *~

distclean-local:
	${RM} -f aclocal.m4 Makefile.in configure m4/*
	${RM} -fr autom4te.cache
