Summary: Kerberos 5 Pluggable Authentication Module
Name: pam_krb5
Version: 1
Release: 1
Source0: pam_krb5-%{version}.tar.gz
Copyright: LGPL
Group: System Environment/Base
BuildPrereq: krb5-devel
BuildRoot: %{_tmppath}/%{name}-root

%description 
This is pam_krb5, a pluggable authentication module that can be used with
Linux-PAM and Kerberos 5. This module supports password checking, ticket
creation, and optional TGT verification and conversion to Kerberos IV tickets.

%prep
%setup -q -n pam_krb5

%build
%configure --with-krb5=/usr/kerberos
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
ln -s -f krb5-pam.d pam.d

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/lib/security/pam_krb5.so
/usr/man/man5/pam_krb5.5
/usr/man/man8/pam_krb5.8
%doc README ChangeLog TODO pam.d

%changelog
* Wed Dec 22 1999 Nalin Dahyabhai <nalin@redhat.com>
- adapted the original spec file from pam_ldap
