Summary: Kerberos 5 Pluggable Authentication Module
Name: pam_krb5
Version: 1
Release: 4
Source0: pam_krb5-%{version}.tar.gz
Copyright: LGPL
Group: System Environment/Base
BuildPrereq: krb5-devel
BuildRoot: %{_tmppath}/%{name}-root

%description 
This is pam_krb5, a pluggable authentication module that can be used with
Linux-PAM and Kerberos 5. This module supports password checking, ticket
creation, and optional TGT verification and conversion to Kerberos IV tickets.
The included pam_krb5afs module also gets AFS tokens if so configured.

%prep
%setup -q
ln -s krb5-pam.d pam.d

%build
%configure --with-krb5=/usr/kerberos
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/lib/security/pam_krb5.so
/lib/security/pam_krb5afs.so
/usr/man/man5/*
/usr/man/man8/*
%doc README ChangeLog TODO pam.d krb5afs-pam.d

%changelog
* Fri Feb  4 2000 Nalin Dahyabhai <nalin@redhat.com>
- pick up non-afs PAM config files again

* Wed Feb  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- autoconf and putenv() fixes for broken apps
- fix for compressed man pages

* Fri Jan 14 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak passwd, su, and vlock configuration files

* Fri Jan  7 2000 Nalin Dahyabhai <nalin@redhat.com>
- added both modules to spec file

* Wed Dec 22 1999 Nalin Dahyabhai <nalin@redhat.com>
- adapted the original spec file from pam_ldap
