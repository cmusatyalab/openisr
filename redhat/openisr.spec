### begin RPM spec
%define name openisr
%define version 0.9.1

Summary: 	OpenISR Internet Suspend-Resume client
Name: 		%name
Version: 	%version
Release: 	1%{?redhatvers:.%{redhatvers}}
Group: 		Applications/Internet
License:	Eclipse Public License	
BuildRequires:	curl-devel, openssl-devel, kernel-devel, uuid-devel
Requires: 	openssh, rsync, pv, dkms
BuildRoot: 	/var/tmp/%{name}-buildroot
Packager:	Matt Toups <mtoups@cs.cmu.edu>

URL:		http://isr.cmu.edu
Source0: 	http://isr.cmu.edu/software/openisr-%{version}.tar.gz
Source1:	Makefile.dkms
Source2:	dkms.conf

%description
 OpenISR is the latest implementation of Internet Suspend/Resume, which
 combines a virtual machine with distributed storage to provide the user
 with both mobility and consistent state without the need for mobile hardware.
 This package contains a client (isr), a parcel manager (Parcelkeeper), a 
 wrapper library for VMware (libvdisk), and the source to the OpenISR kernel 
 modules (Nexus and a SHA-1 accelerator).  A virtual machine monitor (VMware,
 Xen, KVM, etc.) is not included in this package and should also be installed.  
 OpenISR is developed at Carnegie Mellon University.

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
/sbin/udevcontrol reload_rules ||:
dkms add -m openisr -v %{version}
/usr/sbin/openisr-config ||:
/sbin/chkconfig --add openisr
GROUP=isrusers
GID=$(grep ${GROUP} /etc/group | cut -d ':' -f 3)
if [ -z "$GID" ]; then
    /usr/sbin/groupadd -r ${GROUP}
    if [ $? -ne 0 ]; then
        echo >&2 "Error: failed to add the group ${GROUP}."
        exit 4
    else
        echo >2 "Group \"$GROUP\" (gid $GID) added."
    fi
else
    echo >&2 "openisr: Using the existing group \"$GROUP\" (gid $GID) for device nodes."
fi
echo "Any user who will use OpenISR must be added to the \"$GROUP\" group."

%preun
/etc/init.d/openisr stop
dkms remove -m openisr -v %{version} --all
/sbin/chkconfig --del openisr

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
/usr/lib/openisr/parcelkeeper
/usr/lib/openisr/readstats
/usr/lib/openisr/nexus_debug
/usr/lib/openisr/query
/usr/lib/openisr/libsqlite-3.5.4.so
/usr/lib/openisr/libsqlite.la
/usr/lib/openisr/libsqlite.so
/usr/share/man/man1/isr.1.gz
/usr/share/man/man8/openisr-config.8.gz
/usr/share/openisr/config
/usr/lib/libvdisk.so.0
%ifarch x86_64
/usr/lib64/libvdisk.so.0
%endif
%config /etc/udev/openisr.rules
%config /etc/udev/rules.d/openisr.rules
%doc README CHANGES LICENSE.*
%defattr(4644,root,root)
/usr/lib/libvdisk.so.0.0.0
%ifarch x86_64
/usr/lib64/libvdisk.so.0.0.0
%endif
%defattr(0755,root,root)
/etc/init.d/openisr
/etc/bash_completion.d/openisr

%changelog
* Tue Feb 12 2008 Matt Toups <mtoups@cs.cmu.edu> 0.9.1-1
- new upstream release (see CHANGES):
  * Various performance improvements
  * udev rules / group / bash completion (included in previous RPMs)
- eliminate Provides: perl(IsrRevision) (no longer necessary)

* Fri Jan 25 2008 Matt Toups <mtoups@cs.cmu.edu> 0.9-3
- create group in post
- display message directing user to add self to group
- add bash completion rule to files

* Thu Jan 17 2008 Matt Toups <mtoups@cs.cmu.edu> 0.9-2
- add lines to init script, and call chkconfig, so that
  the init scripts get executed on boot.

* Mon Dec 17 2007 Matt Toups <mtoups@cs.cmu.edu> 0.9-1
- New upstream release (see CHANGES):
  * Server changes -- this client can NOT be used with the same server
    used for 0.8.4, so do not upgrade until you are prepared to switch
    servers.
  * Vulpes replaced by Parcelkeeper
  * Parcel format changes: AES encryption, SQLite keyring, UUID
  * New hoard cache implementation
     * hoard cache is shared across parcels, data downloaded only once
     * new hoard cache management commands: lshoard, rmhoard, checkhoard
  * ~/.openisr.conf is now ~/.openisrrc
- updated BuildRequires (uuid-devel)
- post: udevcontrol reload_rules

* Tue Nov 20 2007 Matt Toups <mtoups@cs.cmu.edu> 0.8.4-1
- New upstream release (see CHANGES):
  * use pv (dependency added)
  * openisr-config
  * 64 bit host support for libvdisk
  * AES support
  * 'dirtometer' support
  * and more fixes
- DKMS support (thanks to Adam Goode)
- postinst calls dkms to automate module build
- updated BuildRequires (kernel-devel, openssl-devel)

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
