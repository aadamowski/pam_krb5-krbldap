Summary: A Pluggable Authentication Module for Kerberos 5.
Name: pam_krb5
Version: 1.50
Release: 1
Source0: pam_krb5-%{version}-%{release}.tar.gz
License: LGPL
Group: System Environment/Base
BuildPrereq: byacc, flex, krb5-devel, krbafs-devel, pam-devel
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

# $Id$
%changelog
* Fri Feb 15 2002 Nalin Dahyabhai <nalin@redhat.com> 1.50-1
- documentation updates (no code changes)

* Tue Feb 12 2002 Nalin Dahyabhai <nalin@redhat.com> 1.49-1
- set PAM_USER using the user's parsed name, converted back to a local name
- add account management service (checks for key expiration and krb5_kuserok())
- handle account expiration errors

* Fri Jan 25 2002 Nalin Dahyabhai <nalin@redhat.com> 1.48-1
- autoconf fixes

* Fri Oct 26 2001 Nalin Dahyabhai <nalin@redhat.com> 1.47-2
- bump release number and rebuild to link with new version of krbafs

* Tue Sep 25 2001 Nalin Dahyabhai <nalin@redhat.com> 1.47-1
- fix parsing of options which have multiple whitespace-separated values,
  like afs_cells

* Wed Sep  5 2001 Nalin Dahyabhai <nalin@redhat.com> 1.46-1
- link with libresolv to get res_search, tip from Justin McNutt, who
  built it statically
- explicitly link with libdes425
- handle cases where getpwnam_r fails but still sets the result pointer
- if use_authtok is given and there is no authtok, error out

* Mon Aug 27 2001 Nalin Dahyabhai <nalin@redhat.com> 1.45-1
- set the default realm when a default realm is specified

* Thu Aug 23 2001 Nalin Dahyabhai <nalin@redhat.com> 1.44-1
- only use Kerberos error codes when there is no PAM error yet

* Wed Aug 22 2001 Nalin Dahyabhai <nalin@redhat.com> 1.43-1
- add minimum UID support (#52358)
- don't link pam_krb5 with libkrbafs
- make all options in krb5.conf available as PAM config arguments

* Tue Jul 31 2001 Nalin Dahyabhai <nalin@redhat.com>
- merge patch from Chris Chiappa for building with Heimdal

* Mon Jul 24 2001 Nalin Dahyabhai <nalin@redhat.com>
- note that we had to prepend the current directory to a given path in
  dlopen.c when we had to (noted by Onime Clement)

* Tue Jul 17 2001 Nalin Dahyabhai <nalin@redhat.com> 1.42-1
- return PAM_NEW_AUTHTOK_REQD when attempts to get initial credentials
  fail with KRB5KDC_ERR_KEY_EXP (noted by Onime Clement)

* Thu Jul 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- add info about accessing the CVS repository to the README
- parser cleanups (thanks to Dane Skow for a more complicated sample)

* Wed Jul 11 2001 Nalin Dahyabhai <nalin@redhat.com>
- buildprereq the krbafs-devel package

* Fri Jul  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't set forwardable and assorted other flags when getting password-
  changing service ticket (noted, and fix supplied, by Onime Clement)
- try __posix_getpwnam_r on Solaris before we try getpwnam_r, which may
  or may not be expecting the same number/type of arguments (noted by
  Onime Clement)
- use krb5_aname_to_localname to convert the principal to a login name
  and set PAM_USER to the result when authenticating
- some autoconf fixes for failure cases

* Wed Jun 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- use krb5_change_password() to change passwords

* Tue Jun 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- use getpwnam_r instead of getpwnam when available

* Fri Jun  8 2001 Nalin Dahyabhai <nalin@redhat.com>
- cleanup some autoconf checks

* Thu Jun  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't call initialize_krb5_error_table() or initialize_ovk_error_table()
  if they're not found at compile-time (reported for RHL 6.x by Chris Riley)

* Thu May 31 2001 Nalin Dahyabhai <nalin@redhat.com>
- note that [pam] is still checked in addition to [appdefaults]
- note that AFS and Kerberos IV support requires working Kerberos IV
  configuration files (i.e., kinit -4 needs to work) (doc changes
  suggested by Martin Schulz)

* Tue May 29 2001 Nalin Dahyabhai <nalin@redhat.com>
- add max_timeout, timeout_shift, initial_timeout, and addressless options
  (patches from Simon Wilkinson)
- fix the README to document the [appdefaults] section instead of [pam]
- change example host and cell names in the README to use example domains

* Wed May  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't delete tokens unless we're also removing ticket files (report and
  patch from Sean Dilda)
- report initialization errors better

* Thu Apr 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- treat semicolons as a comment character, like hash marks (bug reported by
  Greg Francis at Gonzaga University)
- use the [:blank:] equivalence class to simplify the configuration file parser
- don't mess with the real environment
- implement mostly-complete aging support

* Sat Apr  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- tweak the man page (can't use italics and bold simultaneously)

* Fri Apr  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- restore the default TGS value (#35015)

* Wed Mar 28 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix a debug message
- fix uninitialized pointer error

* Mon Mar 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't fail to fixup the krb5 ccache if something goes wrong obtaining
  v4 credentials or creating a krb4 ticket file (#33262)

* Thu Mar 22 2001 Nalin Dahyabhai <nalin@redhat.com>
- fixup the man page
- log return code from k_setpag() when debugging
- create credentials and get tokens when setcred is called for REINITIALIZE

* Wed Mar 21 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't twiddle ownerships until after we get AFS tokens
- use the current time instead of the issue time when storing v4 creds, since
  we don't know the issuing host's byte order
- depend on a PAM development header again instead of pam-devel

* Tue Mar 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- add a separate config file parser for compatibility with settings that
  predate the appdefault API
- use a version script under Linux to avoid polluting the global namespace
- don't have a default for afs_cells
- need to close the file when we succeed in fixing permissions (noted by
  jlkatz@eos.ncsu.edu)

* Mon Mar 19 2001 Nalin Dahyabhai <nalin@redhat.com>
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
