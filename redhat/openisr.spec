### begin RPM spec
%define name openisr
%define version 0.8.4

Summary: 	OpenISR Internet Suspend-Resume client
Name: 		%name
Version: 	%version
Release: 	1%{?redhatvers:.%{redhatvers}}
Group: 		Applications/Internet
License:	Eclipse Public License	
BuildRequires: 	curl-devel, kernel-devel
Requires: 	openssh, rsync, pv, dkms
BuildRoot: 	/var/tmp/%{name}-buildroot
Packager:	Matt Toups <mtoups@cs.cmu.edu>

URL:		http://isr.cmu.edu
Source0: 	http://isr.cmu.edu/software/openisr-%{version}.tar.gz
# line below is working around an annoying rpm "feature"
Source1:	Makefile.dkms
Source2:	dkms.conf
Provides:	perl(IsrRevision)

%description
 OpenISR is the latest implementation of Internet Suspend/Resume, which
 combines a virtual machine with distributed storage to provide the user
 with both mobility and consistent state without the need for mobile hardware.
 This package contains a client (isr), a parcel manager (Vulpes), a wrapper
 library for VMware (libvdisk), and the source to the openisr kernel module
 (Nexus).  A virtual machine monitor (VMware, Xen, KVM, etc) is not included
 in this package and should also be installed.  OpenISR is developed at 
 Carnegie Mellon University.

%prep
%setup -q

%build
./configure --enable-client --disable-modules --prefix=/usr --sysconfdir=/etc --mandir=/usr/share/man --with-kbuild-wrapper=dkms && make DESTDIR=%{buildroot}

%install
make install DESTDIR=%{buildroot}
make dist-gzip
mkdir -p %{buildroot}%{_usrsrc}
mv openisr-%{version}.tar.gz %{buildroot}%{_usrsrc}
cd %{buildroot}%{_usrsrc}
tar zxf openisr-%{version}.tar.gz
cp %{SOURCE1} %{SOURCE2} %{buildroot}%{_usrsrc}/openisr-%{version}

%clean
rm -rf %{buildroot}

%pre

%post
/sbin/ldconfig
dkms add -m openisr -v %{version}
/usr/sbin/openisr-config

%preun
/etc/init.d/openisr stop
dkms remove -m openisr -v %{version} --all

%postun
/sbin/ldconfig

%files
%dir /etc/openisr
%dir /usr/share/openisr
%dir /usr/lib/openisr
/usr/src/openisr-%{version}
/usr/src/openisr-%{version}.tar.gz
/usr/bin/isr
/usr/sbin/openisr-config
/usr/lib/openisr/vulpes
/usr/lib/openisr/readstats
/usr/lib/openisr/nexus_debug
/usr/share/man/man1/isr.1.gz
/usr/share/man/man8/openisr-config.8.gz
/usr/share/openisr/config
/usr/share/openisr/HTTPSSH.pm
/usr/share/openisr/IsrConfigTie.pm
/usr/share/openisr/Isr.pm
/usr/share/openisr/IsrRevision.pm
/usr/lib/libvdisk.so.0
%config /etc/udev/openisr.rules
%config /etc/udev/rules.d/openisr.rules
%doc README CHANGES LICENSE.*
%defattr(4644,root,root)
/usr/lib/libvdisk.so.0.0.0
%defattr(0755,root,root)
/etc/init.d/openisr


%changelog
* Tue Nov 13 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.4-1
- soon to be new upstream release
- DKMS support (thanks to Adam Goode)

* Wed Jul 11 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.3-1
- New upstream release

* Mon Apr 16 2007 Benjamin Gilbert <bgilbert@cs.cmu.edu> 0.8.2-1
- New upstream release

* Tue Apr 10 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.1-2
- fix spec file bugs
- fix permissions on doc files

* Wed Mar 28 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.1-1
- improve spec file
- patch to work around broken system headers on fc5/fc6
- only build client stuff for this package

* Fri Feb 23 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8-1
- starting to RPM-ify

### eof
