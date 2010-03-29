AM_CFLAGS = @KRB5_CFLAGS@ @KRB4_CFLAGS@
LIBS = @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

testdir = `cd $(builddir); /bin/pwd`

EXTRA_DIST = klist_4.in

noinst_PROGRAMS = pam_harness klist_a klist_f klist_t klist_c

pam_harness_SOURCES = pam_harness.c
pam_harness_LDADD = -lpam -ldl
