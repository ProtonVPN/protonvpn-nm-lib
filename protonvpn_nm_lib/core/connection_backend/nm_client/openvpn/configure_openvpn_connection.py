from getpass import getuser

from ..... import exceptions
from .....constants import CONFIG_STATUSES, NETSHIELD_STATUS_DICT, VPN_DNS_PRIORITY_VALUE
from .....enums import UserSettingStatusEnum, ClientSuffixEnum
from .....logger import logger
from ....environment import ExecutionEnvironment


class ConfigureOpenVPNConnection:

    def __init__(self):
        self.virtual_device_name = None

        self.__env = ExecutionEnvironment()
        self.username = None
        self.password = None
        self.domain = None
        self.servername = None
        self.dns_status = self.__env.settings.dns
        self.custom_dns = self.__env.settings.dns_custom_ips

        self.connection = None
        self._vpn_settings = None
        self._conn_settings = None

    @staticmethod
    def configure_connection(connection, connection_data):
        setup_connection = ConfigureOpenVPNConnection()

        setup_connection.connection = connection
        user_data = connection_data.get("user_data")
        setup_connection.username = user_data.get("username")
        setup_connection.password = user_data.get("password")
        setup_connection.append_suffixes()

        setup_connection.domain = connection_data.get("domain")
        setup_connection.servername = connection_data.get("servername")

        setup_connection.virtual_device_name = connection_data.get(
            "virtual_device_name"
        )

        setup_connection._vpn_settings = connection.get_setting_vpn()
        setup_connection._conn_settings = connection.get_setting_connection()

        setup_connection.make_vpn_user_owned()
        setup_connection.set_custom_connection_id()
        setup_connection.add_vpn_credentials()
        setup_connection.add_server_certificate_check()
        setup_connection.apply_virtual_device_type()
        setup_connection.dns_configurator()

    def make_vpn_user_owned(self):
        # returns NM.SettingConnection
        # https://lazka.github.io/pgi-docs/NM-1.0/classes/SettingConnection.html#NM.SettingConnection
        logger.info("Making VPN connection be user owned")
        self._conn_settings.add_permission(
            "user",
            getuser(),
            None
        )

    def set_custom_connection_id(self):
        self._conn_settings.props.id = "ProtonVPN " + self.servername

    def append_suffixes(self):
        # append platform suffix
        self.username = self.username + "+{}".format(ClientSuffixEnum.PLATFORM.value)

        # append netshielf suffix
        if self.__env.api_session.clientconfig.features.netshield:
            self.username = self.username + "+{}".format(
                NETSHIELD_STATUS_DICT[self.__env.settings.netshield].value
            )

        # append vpn accelerator suffix
        if (
            self.__env.api_session.clientconfig.features.vpn_accelerator
            and self.__env.settings.vpn_accelerator == UserSettingStatusEnum.DISABLED
        ):
            self.username = self.username + "+nst"

        # append moderate NAT suffix
        if (
            self.__env.api_session.clientconfig.features.moderate_nat
            and self.__env.settings.moderate_nat == UserSettingStatusEnum.ENABLED
        ):
            self.username = self.username + "+nr"

        # append non standard ports (aka safe mode) suffix
        if self.__env.api_session.clientconfig.features.safe_mode:
            if self.__env.settings.non_standard_ports == UserSettingStatusEnum.ENABLED:
                self.username = self.username + "+nsm"
            else:
                self.username = self.username + "+sm"

    def add_vpn_credentials(self):
        """Add OpenVPN credentials to ProtonVPN connection.

        Args:
            openvpn_username (string): openvpn/ikev2 username
            openvpn_password (string): openvpn/ikev2 password
        """
        # returns NM.SettingVpn if the connection contains one, otherwise None
        # https://lazka.github.io/pgi-docs/NM-1.0/classes/SettingVpn.html
        logger.info("Adding OpenVPN credentials")

        try:
            self._vpn_settings.add_data_item(
                "username", self.username
            )
            self._vpn_settings.add_secret(
                "password", self.password
            )
        except Exception as e:
            logger.exception(
                "AddConnectionCredentialsError: {}. ".format(e)
                + "Raising exception."
            )
            # capture_exception(e)
            raise exceptions.AddConnectionCredentialsError(e)

    def add_server_certificate_check(self):
        logger.info("Adding server certificate check")
        logger.debug("Server domain: {}".format(self.domain))
        appened_domain = "name:" + self.domain
        try:
            self._vpn_settings.add_data_item(
                "verify-x509-name", appened_domain
            )
        except Exception as e:
            logger.exception(
                "AddServerCertificateCheckError: {}. ".format(e)
                + "Raising exception."
            )
            # capture_exception(e)
            raise exceptions.AddServerCertificateCheckError(e)

    def apply_virtual_device_type(self):
        """Apply virtual device type and name."""
        logger.info("Applying virtual device type to VPN")

        # Changes virtual tunnel name
        self._vpn_settings.add_data_item("dev", self.virtual_device_name)
        self._vpn_settings.add_data_item("dev-type", "tun")

    def extract_virtual_device_type(self, filename):
        """Extract virtual device type from .ovpn file.

        Args:
            filename (string): path to cached certificate
        Returns:
            string: "tap" or "tun", otherwise raises exception
        """
        logger.info("Extracting virtual device type")
        virtual_dev_type_list = ["tun", "tap"]

        with open(filename, "r") as f:
            content_list = f.readlines()
            dev_type = [dev.rstrip() for dev in content_list if "dev" in dev]

            try:
                dev_type = dev_type[0].split()[1]
            except IndexError as e:
                logger.exception("VirtualDeviceNotFound: {}".format(e))
                raise exceptions.VirtualDeviceNotFound(
                    "No virtual device type was specified in .ovpn file"
                )
            except Exception as e:
                logger.exception("Unknown exception: {}".format(e))
                # capture_exception(e)

            try:
                index = virtual_dev_type_list.index(dev_type)
            except (ValueError, KeyError, TypeError) as e:
                logger.exception("IllegalVirtualDevice: {}".format(e))
                raise exceptions.IllegalVirtualDevice(
                    "Only {} are permitted, though \"{}\" ".format(
                        ' and '.join(virtual_dev_type_list), dev_type
                    ) + " was provided"
                )
            except Exception as e:
                logger.exception("Unknown exception: {}".format(e))
                # capture_exception(e)
            else:
                return virtual_dev_type_list[index]

    def dns_configurator(self):
        """Apply dns configurations to ProtonVPN connection.

        Args:
            dns_setting (tuple(int, [])): contains dns configurations
        """
        logger.info("DNS configs: {} - {}".format(
            self.dns_status, self.custom_dns
        ))

        if self.dns_status not in CONFIG_STATUSES:
            raise Exception("Incorrect status configuration")

        self.enforce_enbled_state_if_disabled()

        ipv4_config = self.connection.get_setting_ip4_config()
        ipv6_config = self.connection.get_setting_ip6_config()

        ipv4_config.props.dns_priority = VPN_DNS_PRIORITY_VALUE
        ipv6_config.props.dns_priority = VPN_DNS_PRIORITY_VALUE
        if self.dns_status == UserSettingStatusEnum.CUSTOM:
            self.apply_custom_dns_configuration(
                ipv4_config, ipv6_config
            )

    def enforce_enbled_state_if_disabled(self):
        if self.dns_status == UserSettingStatusEnum.DISABLED:
            self.dns_status = UserSettingStatusEnum.ENABLED

    def apply_custom_dns_configuration(self, ipv4_config, ipv6_config):
        custom_dns = self.custom_dns
        ipv4_config.props.ignore_auto_dns = True
        ipv6_config.props.ignore_auto_dns = True

        logger.info("Applying custom DNS: {}".format(custom_dns))
        ipv4_config.props.dns = custom_dns
