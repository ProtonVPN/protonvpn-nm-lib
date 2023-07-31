%define unmangled_name protonvpn-nm-lib
%define version 3.15.0
%define release 1

Prefix: %{_prefix}

Name: python3-protonvpn-nm-lib
Version: %{version}
Release: %{release}%{?dist}
Summary: Official Proton VPN NetworkManager library

Group: ProtonVPN
License: GPLv3
Vendor: Proton Technologies AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/%{unmangled_name}
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-devel
BuildRequires: python3-pip
BuildRequires: python3-pyxdg
BuildRequires: python3-setuptools
Requires: libsecret
Requires: dbus-x11
Requires: openvpn
Requires: NetworkManager
Requires: NetworkManager-openvpn
Requires: gtk3
Requires: python3-proton-client
Requires: python3-keyring
Requires: python3-distro
Requires: python3-jinja2
Requires: python3-pyxdg
Requires: python3-dbus
Requires: python3-systemd
Requires: python3-gobject
Requires: xdg-utils
Conflicts: protonvpn-cli < 3.11.0, protonvpn-cli < 1.9.0

%{?python_disable_dependency_generator}

%description
Package installs official Proton VPN NetworkManager library.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES


%files -f INSTALLED_FILES
%{python3_sitelib}/protonvpn_nm_lib/
%{python3_sitelib}/protonvpn_nm_lib-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Mon Jul 31 2023 Proton Technologies AG <opensource@proton.me> 3.15.0-1
- Fix: Fix issue with NM plugin not accepting params for newer openvpn version
- See: https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/issues/112

* Tue Oct 18 2022 Proton Technologies AG <opensource@proton.me> 3.14.0-1
- Fix: When vpn session is invalid, ensure that user is logged out

* Thu Sep 22 2022 Proton Technologies AG <opensource@proton.me> 3.13.0-2
- Drop F34-35 and add F37

* Fri Aug 31 2022 Proton Technologies AG <opensource@proton.me> 3.13.0-1
- Fix: Properly handle session refresh

* Fri Jul 29 2022 Proton Technologies AG <opensource@proton.me> 3.12.0-1
- Fix: Display propper error message when unable to establish VPN tunnel

* Tue May 31 2022 Proton Technologies AG <opensource@proton.me> 3.11.0-2
- Fix: When loading a session from keyring, update the app version and user agent with the current ones

* Fri Apr 22 2022 Proton Technologies AG <opensource@proton.me> 3.10.0-1
- Introducing Proton's refreshed look. As we continue to make privacy accessible to everyone, we've updated our apps to provide you with an even better experience with our services. Proton - Privacy by default

* Wed Apr 20 2022 Proton Technologies AG <opensource@proton.me> 3.9.0-2
- Fix: Crash when attempting to fetch netzone
- Fix: "1000:Permission Denied" error when killswitch is enabled

* Tue Nov 30 2021 Proton Technologies AG <opensource@proton.me> 3.8.0-5
- Improve: Server list
- Improve: Rename exception
- Feature: Moderate NAT, Non Standard Ports

* Thu Nov 11 2021 Proton Technologies AG <opensource@proton.me> 3.7.0-6
- Improve: Handle accounting use cases

* Thu Nov 04 2021 Justin W. Flory <jflory7@fedoraproject.org> - 3.6.1-2
- Improve: Greater conformity to Fedora Linux Packaging Guidelines for Python
  https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/

* Tue Nov 02 2021 Proton Technologies AG <opensource@proton.me> 3.6.1-1
- Hotfix: Update event notifications

* Tue Oct 12 2021 Proton Technologies AG <opensource@proton.me> 3.6.0-5
- Feature: Add notification polling
- Improve: Human verification at login

* Fri Sep 24 2021 Proton Technologies AG <opensource@proton.me> 3.5.0-1
- Handle human verification
- Fix: Remove network interfaces upon reboot/shutdown if kill switch is not set to permanent
- Fix: Wake on suspend has now an additional check to ensure that the reconnector kicks in only when the session is unlocked

* Tue Jul 06 2021 Proton Technologies AG <opensource@proton.me> 3.4.1-3
- More often update server maintenance status
- Feature: Alternative routing
- Fix: Logs should be using UTC time
- Fix: Add missing dependency

* Wed Jun 23 2021 Proton Technologies AG <opensource@proton.me> 3.3.2-1
- Remove IPv6 leak protection when there is no VPN and Kill Switch is disabled

* Tue Jun 22 2021 Proton Technologies AG <opensource@proton.me> 3.3.1-1
- Hotfix: Force disable connectivity check

* Fri Jun 18 2021 Proton Technologies AG <opensource@proton.me> 3.3.0-3
- Feature: Generate logs and open folder with logs

* Tue Jun 08 2021 Proton Technologies AG <opensource@proton.me> 3.2.2-11
- Bugfix: Fix various Kill Switch issues
- Improve: VPN reconnector after suspend

* Fri Jun 04 2021 Proton Technologies AG <opensource@proton.me> 3.2.1-1
- Bugfix: Connect to re-configured Secure Core servers

* Fri May 21 2021 Proton Technologies AG <opensource@proton.me> 3.2.0-5
- Cache all necessary data after successfull authentication
- Bugfix: Select working backend

* Tue May 11 2021 Proton Technologies AG <opensource@proton.me> 3.1.4-2
- Force update systemd service after upgrading the package
- Bugfix: Filter out tor servers from connect fastest and fastest in country

* Fri May 07 2021 Proton Technologies AG <opensource@proton.me> 3.1.3-1
- Fix streaming services icons cache
- Fix client config not properly getting feature flags

* Tue May 04 2021 Proton Technologies AG <opensource@proton.me> 3.1.2-1
- Exclude servers with TOR feature when getting fastest server

* Fri Apr 30 2021 Proton Technologies AG <opensource@proton.me> 3.1.1-1
- Add support for streaming and virtual locations
- Refactor session.py so that clientconfig and streaming are own classes
- Update python3-proton-client dependency version

* Fri Apr 16 2021 Proton Technologies AG <opensource@proton.me> 3.0.0-1
- Treat server features as bitmaps

* Thu Apr 15 2021 Proton Technologies AG <opensource@proton.me> 0.5.2-1
- Cache servers and client configurations upon login

* Mon Mar 01 2021 Proton Technologies AG <opensource@proton.me> 0.5.1-5
- Improve reconnection logic when computer goes to sleep or there is no internet connectivity
- Improve logging
- Impove Kill Switch --on option after reboot
- Improve error handling
- Disconnect after logout
- Return server object after successfully reconnecting
- Add secure core settings for GUI purpose
- Rename Kill Switch always-on to permanent
- Add option to connect to fastest server and fastest server in country based on secure core setting

* Thu Feb 25 2021 Proton Technologies AG <opensource@proton.me> 0.5.0-2
- Refactor library
- Create public API
- Improved library overall stability
- Implement subprocess wrapper

* Wed Feb 24 2021 Proton Technologies AG <opensource@proton.me> 0.4.2-1
- Correctly apply server domain for TLS authentication

* Wed Feb 24 2021 Proton Technologies AG <opensource@proton.me> 0.4.1-1
- Fix bug when connecting to P2P, Secure-Core and TOR due to incorrect subject name for TLS authentication


* Mon Feb 01 2021 Proton Technologies AG <opensource@proton.me> 0.4.0-2
- Improved Kill Switch logic
- Improved reconnection logic after suspend/hibernate
- Add IP server label suffix to username

* Wed Jan 27 2021 Proton Technologies AG <opensource@proton.me> 0.3.0-2
- Update .spec file for public release
