AM_CFLAGS = @KRB5_CFLAGS@ @KRB4_CFLAGS@
LIBS = @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

testdir = `cd $(builddir); /bin/pwd`

noinst_PROGRAMS = pam_harness klist_a klist_a0 klist_f klist_t klist_c
if USE_KRB4
noinst_PROGRAMS += klist_4
endif
klist_a_LDADD = \
	../../src/libpam_krb5.la \
	../../src/logstdio.lo \
	../../src/noitems.lo \
	$(LIBS)
klist_a0_LDADD = \
	../../src/libpam_krb5.la \
	../../src/logstdio.lo \
	../../src/noitems.lo \
	$(LIBS)

pam_harness_SOURCES = pam_harness.c
pam_harness_LDADD = -lpam -ldl
