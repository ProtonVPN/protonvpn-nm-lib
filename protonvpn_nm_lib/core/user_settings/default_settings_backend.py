from ... import exceptions
from ...enums import (DisplayUserSettingsEnum, KillswitchStatusEnum,
                      ProtocolEnum, ServerTierEnum, UserSettingStatusEnum)
from ...logger import logger
from ..environment import ExecutionEnvironment
from .settings_backend import SettingsBackend
from .settings_configurator import SettingsConfigurator


class Settings(SettingsBackend):
    """Settings class.
    Use it to get and set user settings.

    Exposes methods:
        get_user_settings()
        reset_to_default_configs()

    Description:
        get_user_settings()
            Gets user settings, which include NetShield, Kill Switch,
            protocol and dns. Returns a dict with DisplayUserSettingsEnum keys.

        reset_to_default_configs()
            Reset users settings to default values.

    Properties:
        netshield
            Gets/Sets user Netshield setting.

        killswitch
            Gets/Sets user Kill Switch setting.

        protocol
            Gets/Sets user protocol setting.

        dns
            Gets/Sets user DNS setting.

        dns_custom_ips
            Gets/Sets users custom DNS list.
    """
    settings_backend = "default"

    def __init__(self, settings_configurator=None):
        super().__init__()
        self.settings_configurator = settings_configurator or SettingsConfigurator() # noqa

    @property
    def netshield(self):
        """Get user netshield setting.

        Returns:
            NetshieldTranslationEnum
        """
        return self.settings_configurator.get_netshield()

    @netshield.setter
    def netshield(self, netshield_enum):
        """Set netshield to specified option.

        Args:
            netshield_enum (NetshieldTranslationEnum)
        """
        if (
            not netshield_enum
            and (
                ExecutionEnvironment().api_session.vpn_tier
                == ServerTierEnum.FREE
            )
        ):
            raise Exception(
                "\nBrowse the Internet free of malware, ads, "
                "and trackers with NetShield.\n"
                "To use NetShield, upgrade your subscription at: "
                "https://account.protonvpn.com/dashboard"
            )

        self.settings_configurator.set_netshield(netshield_enum)

    @property
    def killswitch(self):
        """Get user Kill Switch setting.

        Returns:
            KillswitchStatusEnum
        """
        return self.settings_configurator.get_killswitch()

    @killswitch.setter
    def killswitch(self, killswitch_enum):
        """Set Kill Switch to specified option.

        Args:
            killswitch_enum (KillswitchStatusEnum)
        """
        _env = ExecutionEnvironment()
        try:
            if (
                not _env.connection_backend.get_active_protonvpn_connection()
                and killswitch_enum == KillswitchStatusEnum.DISABLED
            ):
                _env.ipv6leak.remove_leak_protection()
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            raise Exception(e)

        try:
            _env.killswitch.update_from_user_configuration_menu( # noqa
                killswitch_enum
            )
        except exceptions.DisableConnectivityCheckError as e:
            logger.exception(e)
            raise Exception(
                "\nUnable to set kill switch setting: "
                "Connectivity check could not be disabled.\n"
                "Please disable connectivity check manually to be able to use "
                "the killswitch feature."
            )
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            raise Exception(e)
        except AttributeError:
            pass
        else:
            self.settings_configurator.set_killswitch(killswitch_enum)

    @property
    def secure_core(self):
        """Get Secure Core setting.

        Returns:
            KillswitchStatusEnum
        """
        return self.settings_configurator.get_secure_core()

    @secure_core.setter
    def secure_core(self, newvalue):
        """Get Secure Core setting.

        Returns:
            SecureCoreStatusEnum
        """
        return self.settings_configurator.set_secure_core(newvalue)

    @property
    def protocol(self):
        """Get default protocol.

        Returns:
            ProtocolEnum
        """
        return self.settings_configurator.get_protocol()

    @protocol.setter
    def protocol(self, protocol_enum):
        """Set default protocol setting.

        Args:
            protocol_enum (ProtocolEnum)
        """
        logger.info("Setting protocol to: {}".format(protocol_enum))
        if not isinstance(protocol_enum, ProtocolEnum):
            logger.error("Select protocol is incorrect.")
            raise Exception(
                "\nSelected option \"{}\" is either incorrect ".format(
                    protocol_enum
                ) + "or protocol is (yet) not supported"
            )

        self.settings_configurator.set_protocol(
            protocol_enum
        )

        logger.info("Default protocol has been updated to \"{}\"".format(
            protocol_enum
        ))

    @property
    def dns(self):
        """Get user DNS setting.

        Args:
            custom_dns (bool):
            (optional) should be set to True
            if it is desired to get custom DNS values
            in a list.

        Returns:
            UserSettingStatusEnum
        """
        return self.settings_configurator.get_dns()

    @dns.setter
    def dns(self, setting_status):
        """Set DNS setting.

        Args:
            setting_status (UserSettingStatusEnum)
            custom_dns_ips (list): optional
        """
        if not isinstance(setting_status, UserSettingStatusEnum):
            raise Exception("Invalid setting status \"{}\"".format(
                setting_status
            ))

        try:
            self.settings_configurator.set_dns_status(setting_status)
        except (exceptions.ProtonVPNException, Exception) as e:
            raise Exception(e)

    @property
    def dns_custom_ips(self):
        """Get user DNS setting.

        Returns:
           list with custom DNS servers.
        """
        return self.settings_configurator.get_dns_custom_ip()

    @dns_custom_ips.setter
    def dns_custom_ips(self, custom_dns_ips):
        for dns_server_ip in custom_dns_ips:
            if not self.settings_configurator.is_valid_ip(dns_server_ip):
                logger.error("{} is an invalid IP".format(dns_server_ip))
                raise Exception(
                    "\n{0} is invalid. "
                    "Please provide a valid IP DNS server.".format(
                        dns_server_ip
                    )
                )
        self.settings_configurator.set_dns_custom_ip(custom_dns_ips)

    @property
    def vpn_accelerator(self):
        """Get user VPN Accelerator setting."""
        return self.settings_configurator.get_vpn_accelerator()

    @vpn_accelerator.setter
    def vpn_accelerator(self, setting_status):
        """Set VPN Accelerator setting."""
        if not isinstance(setting_status, UserSettingStatusEnum):
            raise Exception("Invalid setting status \"{}\"".format(
                setting_status
            ))

        try:
            self.settings_configurator.set_vpn_accelerator(setting_status)
        except (exceptions.ProtonVPNException, Exception) as e:
            raise Exception(e)

    def reset_to_default_configs(self):
        """Reset user configuration to default values."""
        # should it disconnect prior to resetting user configurations ?
        try:
            self.settings_configurator.reset_default_configs()
        except (exceptions.ProtonVPNException, Exception) as e:
            raise Exception(e)

        ExecutionEnvironment().killswitch.update_from_user_configuration_menu( # noqa
            KillswitchStatusEnum.DISABLED
        )

    def get_user_settings(self):
        """Get user settings.

        Args:
            readeable_format (bool):
                If true then all content will be returnes in
                human readeable format, else all content is returned in
                enum objects.

        Returns:
            dict:
                Keys: DisplayUserSettingsEnum
        """
        settings_dict = {
            DisplayUserSettingsEnum.PROTOCOL: self.protocol,
            DisplayUserSettingsEnum.KILLSWITCH: self.killswitch,
            DisplayUserSettingsEnum.DNS: self.dns,
            DisplayUserSettingsEnum.CUSTOM_DNS: self.dns_custom_ips,
            DisplayUserSettingsEnum.NETSHIELD: self.netshield,
            DisplayUserSettingsEnum.VPN_ACCELERATOR: self.vpn_accelerator,
        }

        return settings_dict
