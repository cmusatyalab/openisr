### begin RPM spec
%define name openisr
%define version 0.8

Summary: 	OpenISR Internet Suspend-Resume client
Name: 		%name
Version: 	%version
Release: 	1
Group: 		Applications/Internet
License: 	Eclipse
BuildPrereq: 	curl-devel
Requires: 	ssh, rsync
BuildRoot: 	/var/tmp/%{name}-buildroot
Packager:	Matt Toups <mtoups@cs.cmu.edu>

Source: 	openisr-0.8.tar.gz

%description
OpenISR is blah blah blah

%prep
#%setup -n openisr-0.8
%setup -q
#tar zxvf openisr-0.8.tar.gz && cd openisr-0.8

%build
#./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc && make DESTDIR=%{buildroot}

%install
make install DESTDIR=%{buildroot}
# tidy up after?

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Fri Feb 23 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8-1
- stuff

# below: ldconfig .. ?
#pre-install script
%pre

#post-install
%post

#pre-remove
%preun

#post-remove
%postun

%files
%dir /etc/openisr
%dir /usr/share/openisr
%dir /usr/lib/openisr
/usr/bin/isr
/usr/lib/openisr/vulpes
/usr/lib/openisr/readstats
/usr/lib/openisr/nexus_debug
/usr/man/man1/isr.1.gz
/usr/share/openisr/config
/usr/share/openisr/HTTPSSH.pm
/usr/share/openisr/IsrConfigTie.pm
/usr/share/openisr/Isr.pm
/usr/share/openisr/IsrRevision.pm
/usr/lib/libvdisk.so.0
%defattr(4644,root,root)
/usr/lib/libvdisk.so.0.0.0
#TODO: docs, udev

### eof
