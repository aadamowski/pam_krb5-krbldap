Summary: A Pluggable Authentication Module for Kerberos 5.
Name: pam_krb5
Version: 1.28
Release: 1
Source0: pam_krb5-%{version}-%{release}.tar.gz
Copyright: LGPL
Group: System Environment/Base
BuildPrereq: byacc, flex, krb5-devel, /usr/include/security/pam_modules.h
BuildRoot: %{_tmppath}/%{name}-root
Requires: krbafs >= 1.0

%description 
This is pam_krb5, a pluggable authentication module that can be used with
Linux-PAM and Kerberos 5. This module supports password checking, ticket
creation, and optional TGT verification and conversion to Kerberos IV tickets.
The included pam_krb5afs module also gets AFS tokens if so configured.

%prep
%setup -q -n pam_krb5-%{version}-%{release}

%build
%configure --with-krb5=/usr/kerberos --with-krbafs=/usr/kerberos
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT mandir=%{_mandir}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/lib/security/pam_krb5.so
/lib/security/pam_krb5afs.so
%{_mandir}/man5/*
%{_mandir}/man8/*
%doc README COPYING ChangeLog TODO pam.d krb5afs-pam.d

%changelog
* Thu Feb 22 2001 Nalin Dahyabhai <nalin@redhat.com>
- fixup the man page
- log return code from k_setpag() when debugging
- create credentials and get tokens when setcred is called for REINITIALIZE

* Wed Feb 21 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't twiddle ownerships until after we get AFS tokens
- use the current time instead of the issue time when storing v4 creds, since
  we don't know the issuing host's byte order
- depend on a PAM development header again instead of pam-devel

* Tue Feb 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- add a separate config file parser for compatibility with settings that
  predate the appdefault API
- use a version script under Linux to avoid polluting the global namespace
- don't have a default for afs_cells
- need to close the file when we succeed in fixing permissions (noted by
  jlkatz@eos.ncsu.edu)

* Mon Feb 19 2001 Nalin Dahyabhai <nalin@redhat.com>
- use the appdefault API to read krb5.conf if available
- create v4 tickets in such a way as to allow 1.2.2 to not think there's
  something fishy going on

* Tue Feb 13 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't log unknown user names to syslog -- they might be sensitive information

* Fri Feb  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- handle cases where krb5_init_context() fails

* Wed Jan 17 2001 Nalin Dahyabhai <nalin@redhat.com>
- be more careful around memory allocation (fixes from David J. MacKenzie)

* Mon Jan 15 2001 Nalin Dahyabhai <nalin@redhat.com>
- no fair trying to make me authenticate '(null)'

* Tue Dec  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Fri Dec  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Wed Nov  8 2000 Nalin Dahyabhai <nalin@redhat.com>
- only try to delete ccache files once
- ignore extra data in v4 TGTs, but log that we got some
- require "validate" to be true to try validating, and fail if validation fails

* Thu Oct 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- catch and ignore errors reading keys from the keytab (for xscreensaver, vlock)

* Wed Oct 18 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix prompting when the module's first in the stack and the user does not have
  a corresponding principal in the local realm
- properly implement TGT validation
- change a few non-error status messages into debugging messages
- sync the README and the various man pages up

* Mon Oct  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix "use_authtok" logic when password was not set by previous module
- require pam-devel to build

* Sun Aug 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix errors with multiple addresses (#16847)

* Wed Aug 16 2000 Nalin Dahyabhai <nalin@redhat.com>
- change summary

* Thu Aug 10 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix handling of null passwords

* Wed Jul  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- fixes for Solaris 7 from Trevor Schroeder

* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- add Seth Vidal's no_user_check flag
- document no_user_check and skip_first_pass options in the man pages
- rebuild against Kerberos 5 1.2 (release 15)

* Mon Jun  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- move man pages to %{_mandir}

* Wed May 17 2000 Nalin Dahyabhai <nalin@redhat.com>
- Make errors chown()ing ccache files non-fatal if (getuid() != 0), suggested
  by Steve Langasek.

* Mon May 15 2000 Nalin Dahyabhai <nalin@redhat.com>
- Attempt to get initial Kerberos IV credentials when we get Kerberos 5 creds

* Thu Apr 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- Chris Chiappa's modifications for customizing the ccache directory

* Wed Apr 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- Mark Dawson's fix for krb4_convert not being forced on when afs_cells defined

* Thu Mar 23 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix problem with leftover ticket files after multiple setcred() calls

* Mon Mar 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- add proper copyright statements
- save password for modules later in the stack

* Fri Mar 03 2000 Nalin Dahyabhai <nalin@redhat.com>
- clean up prompter

* Thu Mar 02 2000 Nalin Dahyabhai <nalin@redhat.com>
- add krbafs as a requirement

* Fri Feb 04 2000 Nalin Dahyabhai <nalin@redhat.com>
- pick up non-afs PAM config files again

* Wed Feb 02 2000 Nalin Dahyabhai <nalin@redhat.com>
- autoconf and putenv() fixes for broken apps
- fix for compressed man pages

* Fri Jan 14 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak passwd, su, and vlock configuration files

* Fri Jan 07 2000 Nalin Dahyabhai <nalin@redhat.com>
- added both modules to spec file

* Wed Dec 22 1999 Nalin Dahyabhai <nalin@redhat.com>
- adapted the original spec file from pam_ldap
