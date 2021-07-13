# https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
# Save settings in XDG_CONFIG_HOME
# Save cache XDG_CACHE_HOME
# Save logs and other user data in XDG_DATA_HOME

import os

from xdg import BaseDirectory

from .enums import (KillswitchStatusEnum, NetshieldStatusEnum,
                    NetshieldTranslationEnum, ProtocolEnum,
                    ProtocolImplementationEnum, SecureCoreStatusEnum,
                    UserSettingConnectionEnum, UserSettingStatusEnum)

APP_VERSION = "3.3.2"

IPv6_LEAK_PROTECTION_CONN_NAME = "pvpn-ipv6leak-protection"
IPv6_LEAK_PROTECTION_IFACE_NAME = "ipv6leakintrf0"

KILLSWITCH_CONN_NAME = "pvpn-killswitch"
KILLSWITCH_INTERFACE_NAME = "pvpnksintrf0"

ROUTED_CONN_NAME = "pvpn-routed-killswitch"
ROUTED_INTERFACE_NAME = "pvpnroutintrf0"

IPv4_DUMMY_ADDRESS = "100.85.0.1/24"
IPv4_DUMMY_GATEWAY = "100.85.0.1"
IPv6_DUMMY_ADDRESS = "fdeb:446c:912d:08da::/64"
IPv6_DUMMY_GATEWAY = "fdeb:446c:912d:08da::1"

KILLSWITCH_DNS_PRIORITY_VALUE = "-1400"
VPN_DNS_PRIORITY_VALUE = -1500

DEFAULT_KEYRING_SERVICE = "ProtonVPN"
DEFAULT_KEYRING_USERNAME = "AuthData"

ENV_CI_NAME = "protonvpn_ci"
OPENVPN_TEMPLATE = "openvpn_template.j2"
LOGGER_NAME = "protonvpn"
VIRTUAL_DEVICE_NAME = "proton0"

SUPPORTED_PROTOCOLS = {
    ProtocolImplementationEnum.OPENVPN: [ProtocolEnum.TCP, ProtocolEnum.UDP],
}

FLAT_SUPPORTED_PROTOCOLS = [
    proto for proto_list
    in [v for k, v in SUPPORTED_PROTOCOLS.items()]
    for proto in proto_list
]

CONFIG_STATUSES = [
    UserSettingStatusEnum.DISABLED,
    UserSettingStatusEnum.ENABLED,
    UserSettingStatusEnum.CUSTOM,
]
USER_CONFIG_TEMPLATE = {
    UserSettingConnectionEnum.DEFAULT_PROTOCOL: ProtocolEnum.UDP,
    UserSettingConnectionEnum.KILLSWITCH: KillswitchStatusEnum.DISABLED,
    UserSettingConnectionEnum.DNS: {
        UserSettingConnectionEnum.DNS_STATUS: UserSettingStatusEnum.ENABLED,
        UserSettingConnectionEnum.CUSTOM_DNS: []
    },
    UserSettingConnectionEnum.SPLIT_TUNNELING: {
        UserSettingConnectionEnum.SPLIT_TUNNELING_STATUS: UserSettingStatusEnum.DISABLED,
        UserSettingConnectionEnum.IP_LIST: []
    },
    UserSettingConnectionEnum.NETSHIELD: NetshieldTranslationEnum.DISABLED,
    UserSettingConnectionEnum.SECURE_CORE: SecureCoreStatusEnum.OFF,
    UserSettingConnectionEnum.VPN_ACCELERATOR: UserSettingStatusEnum.ENABLED
}
NETSHIELD_STATUS_DICT = {
    NetshieldTranslationEnum.DISABLED: NetshieldStatusEnum.DISABLED,
    NetshieldTranslationEnum.MALWARE: NetshieldStatusEnum.MALWARE,
    NetshieldTranslationEnum.ADS_MALWARE: NetshieldStatusEnum.ADS_MALWARE
}

# Constant folders
XDG_CACHE_HOME = BaseDirectory.xdg_cache_home
XDG_CONFIG_HOME = BaseDirectory.xdg_config_home
PWD = os.path.dirname(os.path.abspath(__file__))
PROTON_XDG_CACHE_HOME = os.path.join(XDG_CACHE_HOME, "protonvpn")
PROTON_XDG_CONFIG_HOME = os.path.join(XDG_CONFIG_HOME, "protonvpn")
PROTON_XDG_CACHE_HOME_LOGS = os.path.join(PROTON_XDG_CACHE_HOME, "logs")
PROTON_XDG_CACHE_HOME_STREAMING_ICONS = os.path.join(PROTON_XDG_CACHE_HOME, "streaming_icons")
XDG_CONFIG_SYSTEMD = os.path.join(XDG_CONFIG_HOME, "systemd")
XDG_CONFIG_SYSTEMD_USER = os.path.join(XDG_CONFIG_SYSTEMD, "user")
TEMPLATES = os.path.join(PWD, "templates")

# Constant filepaths
APP_CONFIG = os.path.join(PWD, "app.cfg")
LOGFILE = os.path.join(PROTON_XDG_CACHE_HOME_LOGS, "protonvpn.log")
NETWORK_MANAGER_LOGFILE = os.path.join(PROTON_XDG_CACHE_HOME_LOGS, "network_manager.service.log")
PROTONVPN_RECONNECT_LOGFILE = os.path.join(PROTON_XDG_CACHE_HOME_LOGS, "protonvpn_reconnect.service.log") # noqa

LOCAL_SERVICE_FILEPATH = os.path.join(
    XDG_CONFIG_SYSTEMD_USER, "protonvpn_reconnect.service"
)
CACHED_SERVERLIST = os.path.join(
    PROTON_XDG_CACHE_HOME, "cached_serverlist.json"
)
CACHED_OPENVPN_CERTIFICATE = os.path.join(
    PROTON_XDG_CACHE_HOME, "ProtonVPN.ovpn"
)
CACHE_METADATA_FILEPATH = os.path.join(
    PROTON_XDG_CACHE_HOME, "cache_metadata.json"
)
CONNECTION_STATE_FILEPATH = os.path.join(
    PROTON_XDG_CACHE_HOME, "connection_metadata.json"
)
LAST_CONNECTION_METADATA_FILEPATH = os.path.join(
    PROTON_XDG_CACHE_HOME, "last_connection_metadata.json"
)
CLIENT_CONFIG = os.path.join(
    PROTON_XDG_CACHE_HOME, "client_config.json"
)
STREAMING_SERVICES = os.path.join(
    PROTON_XDG_CACHE_HOME, "streaming_services.json"
)
STREAMING_ICONS_CACHE_TIME_PATH = os.path.join(
    PROTON_XDG_CACHE_HOME, "streaming_icons_cache.json"
)
USER_CONFIGURATIONS_FILEPATH = os.path.join(
    PROTON_XDG_CONFIG_HOME, "user_configurations.json"
)

# Constant templates
SERVICE_TEMPLATE = """
# v{}

[Unit]
Description=ProtonVPN Reconnector

[Service]
ExecStart=EXEC_START
""".format(APP_VERSION)
