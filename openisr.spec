### begin RPM spec
%define name openisr
%define version 0.8.1

Summary: 	OpenISR Internet Suspend-Resume client
Name: 		%name
Version: 	%version
Release: 	1
Group: 		Applications/Internet
License: 	Eclipse
BuildRequires: 	curl-devel
Requires: 	openssh, rsync
BuildRoot: 	/var/tmp/%{name}-buildroot
Packager:	Matt Toups <mtoups@cs.cmu.edu>

Source: 	http://isr.cmu.edu/software/openisr-0.8.1.tar.gz
# patch below needed to compile on fc5/fc6 systems
Patch:		libvdisk-lba_capacity_2.patch
# line below is working around an annoying rpm "feature"
Provides:	perl(IsrRevision)

%description
 OpenISR is the latest implementation of Internet Suspend/Resume, which
 combines a virtual machine with distributed storage to provide the user
 with both mobility and consistent state without the need for mobile hardware.
 This package contains a client (isr), a parcel manager (Vulpes), a wrapper
 library for VMware (libvdisk), and the source to the openisr kernel module
 (Nexus).  A virtual machine monitor (VMware, Xen, KVM, etc) should also be
 installed.   OpenISR is developed at Carnegie Mellon University.

%prep
%setup -q
%patch

%build
./configure --enable-client --disable-modules --prefix=/usr --sysconfdir=/etc && make DESTDIR=%{buildroot}

%install
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

#pre-install script
%pre

#post-install
%post
/sbin/ldconfig

#pre-remove
%preun

#post-remove
%postun
/sbin/ldconfig

%files
%dir /etc/openisr
%dir /usr/share/openisr
%dir /usr/lib/openisr
/usr/bin/isr
/usr/lib/openisr/vulpes
/usr/lib/openisr/readstats
/usr/lib/openisr/nexus_debug
/usr/share/man/man1/isr.1.gz
/usr/share/openisr/config
/usr/share/openisr/HTTPSSH.pm
/usr/share/openisr/IsrConfigTie.pm
/usr/share/openisr/Isr.pm
/usr/share/openisr/IsrRevision.pm
/usr/lib/libvdisk.so.0
%defattr(4644,root,root)
/usr/lib/libvdisk.so.0.0.0
/etc/udev/openisr.rules
/etc/udev/rules.d/openisr.rules
/etc/init.d/openisr
%doc README CHANGES LICENSE.*

%changelog
* Wed Mar 28 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.1-1
- improve spec file
- patch to work around broken system headers on fc5/fc6
- only build client stuff for this package
* Fri Feb 23 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8-1
- starting to RPM-ify

### eof
