EXTRA_DIST = pam_krb5.spec TODO README README.heimdal-pkinit README.mit-pkinit README.winbind

CONFIGURE_DEPENDENCIES = $(top_srcdir)/pam_krb5.spec

SUBDIRS = src tests po

SVERSION=$(shell awk '/^Version:/ {print $$NF}' $(top_srcdir)/pam_krb5.spec | sed 's,%.*,,' | head -n 1)
SRELEASE=$(shell awk '/^Release:/ {print $$NF}' $(top_srcdir)/pam_krb5.spec | sed 's,%.*,,' | head -n 1)
GITTAG=$(PACKAGE)-$(VERSION)-$(SRELEASE)
distdir=$(GITTAG)
DISTCLEANFILES = tests/kdc/krb5cc_* tests/kdc/tkt*

tag:
	test $(GITTAG) = $(PACKAGE)-$(SVERSION)-$(SRELEASE)
	tx pull
	git tag $(GITTAG)

force-tag:
	git tag -f $(GITTAG)

ORIGIN=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

local-archive:
	$(MAKE) archive ORIGIN=$(ARCHIVEOUTDIR)

archive:
	repo=`pwd`; \
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`; \
	if test -d "$$tmpdir" ; then \
		git clone $(ORIGIN) $$tmpdir/pam_krb5;\
		cd $$tmpdir/pam_krb5;\
		git checkout $(GITTAG);\
		./autogen;\
		tx pull;\
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

ACLOCAL_AMFLAGS = -I m4
