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

CVSROOT=$(shell test -d CVS && cat CVS/Root)
REPOSITORY=$(shell test -d CVS && cat CVS/Repository)

archive:
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX` \
	if test -d "$$tmpdir" ; then \
		cd $$tmpdir \
		cvs -d $(CVSROOT) co -d $(distdir) -r $(CVSTAG) $(REPOSITORY) \
		cd $(distdir) \
		./autogen \
		make dist \
		cp -v $(distdir).tar.gz $(top_srcdir)/ \
		rm -fr $$tmpdir \
	fi
