# ProtonVPN NM Library

Copyright (c) 2021 Proton Technologies AG

This repository holds the ProtonVPN NM Library.
For licensing information see [COPYING](COPYING.md).
For contribution policy see [CONTRIBUTING](CONTRIBUTING.md).

## Description
The [ProtonVPN](https://protonvpn.com) NM (NetworkManager) Library is intended for every ProtonVPN service user.

You can download the latest stable release, either from our official repositories or directly on the [official GitHub repository](https://github.com/ProtonVPN/protonvpn-nm-lib/releases/latest).

### Dependencies:

| **Distro**                              | **Command**                                                                                                     |
|:----------------------------------------|:----------------------------------------------------------------------------------------------------------------|
|Fedora/CentOS/RHEL                       | `sudo dnf install -y NetworkManager NetworkManager-openvpn NetworkManager-openvpn-gnome openvpn python3-keyring python3-jinja2 python3-distro python3-gobject libsecret-devel dbus-x11 gnome-keyring` |
|Ubuntu/Linux Mint/Debian and derivatives | `sudo apt install -y network-manager network-manager-openvpn openvpn python3-keyring python3-jinja2 python3-distro gir1.2-nm-1.0 libsecret-tools dbus-x11 gnome-keyring network-manager-openvpn-gnome` |
|Arch Linux/Manjaro                       | `sudo pacman -S networkmanager networkmanager-openvpn openvpn python-keyring python-jinja python-distro dbus-x11 gnome-keyring` |

### Additional dependency:
[Proton Python Client](https://github.com/ProtonMail/proton-python-client)

### Virtual Environment Dependencies:
If you would like to run the the CLI from within a virtual environment (for either development purposes or other), then you can easily do that with the help of <a href="https://pipenv.readthedocs.io/en/latest/">pipenv</a>. Make sure to install pipenv and additional packages before.

| **Distro**                              | **Command**                                                                                                     |
|:----------------------------------------|:----------------------------------------------------------------------------------------------------------------|
|Fedora/CentOS/RHEL                       | `sudo dnf install pkgconf-pkg-config networkmanager networkmanager-openvpn openvpn cairo-devel cairo-gobject-devel libsecret-devel gobject-introspection-devel dbus-x11 gnome-keyring` |
|Ubuntu/Linux Mint/Debian and derivatives | `sudo apt install -y pkg-config network-manager network-manager-openvpn openvpn libcairo2-dev libgirepository1.0-dev gir1.2-nm-1.0 dbus-x11 libsecret-tools gnome-keyring` |
|Arch Linux/Manjaro                       | `sudo pacman -S pkgconf networkmanager networkmanager-openvpn openvpn cairo base-devel gobject-introspection pkgconf dbus-x11 libsecret gnome-keyring gtk3` |


#### Install inside virtual environment:

  1. `cd protonvpn-nm-core`
  2. `pipenv install` (installs virtual environment and all necessary dependencies from Pipfile).
  3. `pipenv shell` (enter virtual environment).
  4. `pip install -e .` (to install).

<br>

# How to use:

### Import
``` from protonvpn_nm_lib.api import protonvpn ```

<br>

### Login
``` protonvpn.login("protonvpn@protonmail.com", "ProtonPassword") ```

<br>

### Logout
``` protonvpn.logout() ```

<br>

### Connect
``` protonvpn.setup_connection(ConnectionTypeEnum.SERVERNAME, "PT#12", ProtocolEnum.TCP) ``` <br>
``` protonvpn.connect() ``` 

<br>

### Disconnect
``` protonvpn.disconnect() ```

<br>

| **API**                              | **Description**                                                                                                     |
|:------------------------------------------------|:----------------------------------------------------------------------------------------------------------------|
| `protonvpn.login(username, password)` | Login with your Proton credentials. |
| `protonvpn.logout()` | Logout user and delete current user session. |
| `protonvpn.setup_connection(connection_type, connection_type_extra_arg, protocol)` | Setup and configure VPN connection prior to calling protonvpn.connect(). |
| `protonvpn.setup_reconnect()` | Setup and configure VPN connection to a previously connected server. Should be called before calling protonvpn.connect(). |
| `protonvpn.connect()` | Should be used either after protonvpn.setup_connection() protonvpn.setup_reconnect(). |
| `protonvpn.disconnect()` | Disconnect from ProtonVPN. |
| `protonvpn.check_session_exists()` | Check if sessions exists. |
| `protonvpn.get_connection_status()` | Get active connection status. |
| `protonvpn.get_settings()` | Get user settings. This object can be used to get and set user settings. |
| `protonvpn.get_session()` | Get user session. This object can be used to get servers list, get keyring data and other. |
| `protonvpn.get_country()` | Get country. |
| `protonvpn.get_connection_metadata()` | Get metadata of an active ProtonVPN connection. |
| `protonvpn.get_non_active_protonvpn_connection()` | Get non active ProtonVPN connection. |
| `protonvpn.get_active_protonvpn_connection()` | Get active ProtonVPN connection. |
| `protonvpn.ensure_connectivity()` | Ensure that there is an internet connection. |
