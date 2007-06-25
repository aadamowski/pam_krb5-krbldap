EXTRA_DIST = pam_krb5.spec TODO README README.winbind

CONFIGURE_DEPENDENCIES = $(top_srcdir)/pam_krb5.spec

SUBDIRS = src tests

VERSION=`rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{version}\n' | head -n1`
RELEASE=`rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{release}\n' | head -n1`
CVSTAG=pam_krb5-`rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{version}-%{release}\n' | tail -n 1 | tr . _`
distdir=$(PACKAGE)-$(VERSION)-$(RELEASE)
DISTCLEANFILES = tests/kdc/krb5cc_* tests/kdc/tkt*

tag:
	cvs tag -c $(CVSTAG)

force-tag:
	cvs tag -cF $(CVSTAG)

CVSROOT=`test -d CVS && cat CVS/Root`
REPOSITORY=`test -d CVS && cat CVS/Repository`
ARCHIVEOUTDIR=`cd $(top_srcdir) && pwd`

archive:
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`;\
	if test -d "$$tmpdir" ; then \
		cd $$tmpdir;\
		cvs -d $(CVSROOT) co -d $(distdir) -r $(CVSTAG) $(REPOSITORY);\
		cd $(distdir);\
		./autogen;\
		make dist;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
