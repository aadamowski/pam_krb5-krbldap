EXTRA_DIST = pam_krb5.spec

SUBDIRS = src pam.d tests

VERSION=$(shell rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{version}\n' | head -n1)
RELEASE=$(shell rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{release}\n' | head -n1)
CVSTAG=pam_krb5-$(shell echo $(VERSION) | tr . _)-$(shell echo $(RELEASE) | tr . _)
distdir=$(PACKAGE)-$(VERSION)-$(RELEASE)

tag:
	cvs tag -c $(CVSTAG)

force-tag:
	cvs tag -cF $(CVSTAG)
