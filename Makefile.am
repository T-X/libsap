ACLOCAL_AMFLAGS = -I m4 --install

lib_LTLIBRARIES = libsap-0.1.la
libsap_0_1_la_SOURCES = src/libsap.c src/init.c src/libsap_priv.h src/libsap.h

include_HEADERS = src/libsap.h

bin_PROGRAMS = sap
sap_SOURCES = src/main.c
sap_LDADD = $(lib_LTLIBRARIES)
