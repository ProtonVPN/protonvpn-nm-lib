import json
import os
import re
from enum import Enum

from ...constants import (
    CONFIG_STATUSES,
    PROTON_XDG_CONFIG_HOME,
    USER_CONFIG_TEMPLATE,
    USER_CONFIGURATIONS_FILEPATH,
    NETSHIELD_STATUS_DICT,
)
from ...enums import (
    ProtocolEnum,
    UserSettingConnectionEnum,
    KillswitchStatusEnum,
    SecureCoreStatusEnum,
    NotificationStatusEnum
)


class SettingsConfigurator:
    def __init__(
        self,
        user_config_dir=PROTON_XDG_CONFIG_HOME,
        user_config_fp=USER_CONFIGURATIONS_FILEPATH
    ):
        self.user_config_filepath = user_config_fp
        if not os.path.isdir(user_config_dir):
            os.makedirs(user_config_dir)
        self.initialize_configuration_file()

    def get_protocol(self):
        """Protocol get method."""
        user_configs = self.get_user_configurations()
        return user_configs[UserSettingConnectionEnum.DEFAULT_PROTOCOL]

    def get_dns(self):
        """DNS get method."""
        user_configs = self.get_user_configurations()

        dns_status = user_configs[UserSettingConnectionEnum.DNS][
            UserSettingConnectionEnum.DNS_STATUS
        ]

        return dns_status

    def get_dns_custom_ip(self):
        """Get custom DNS IP list."""
        user_configs = self.get_user_configurations()

        custom_dns = user_configs[UserSettingConnectionEnum.DNS][
            UserSettingConnectionEnum.CUSTOM_DNS
        ]

        return custom_dns

    def get_killswitch(self):
        """Killswitch get method."""
        user_configs = self.get_user_configurations()
        return user_configs[UserSettingConnectionEnum.KILLSWITCH]

    def get_secure_core(self):
        """Secure Core get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.SECURE_CORE]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.SECURE_CORE]

    def get_alternative_routing(self):
        """Secure Core get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.ALTERNATIVE_ROUTING]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.ALTERNATIVE_ROUTING]

    def get_netshield(self):
        """Netshield get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.NETSHIELD]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.NETSHIELD]

    def get_vpn_accelerator(self):
        """VPN Accelerator get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.VPN_ACCELERATOR]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.ALTERNATIVE_ROUTING]

    def get_event_notification(self):
        """Event notification get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.EVENT_NOTIFICATION]
        except KeyError:
            return NotificationStatusEnum.UNKNOWN

    def get_new_brand_notification(self):
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.NEW_BRAND_INFO]
        except KeyError:
            return NotificationStatusEnum.NOT_OPENED

    def get_moderate_nat(self):
        """Moderate NAT get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.MODERATE_NAT]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.MODERATE_NAT]

    def get_non_standard_ports(self):
        """Moderate NAT get method."""
        user_configs = self.get_user_configurations()
        try:
            return user_configs[UserSettingConnectionEnum.NON_STANDARD_PORTS]
        except KeyError:
            return USER_CONFIG_TEMPLATE[UserSettingConnectionEnum.NON_STANDARD_PORTS]

    def set_protocol(self, protocol):
        """Set default protocol method.

        Args:
            protocol (ProtocolEnum): protocol type
        """
        if not isinstance(protocol, ProtocolEnum):
            raise KeyError("Illegal protocol")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.DEFAULT_PROTOCOL] = protocol # noqa
        self.set_user_configurations(user_configs)

    def set_dns_status(self, status):
        """Set DNS setting method.

        Args:
            status (UserSettingStatusEnum): DNS status
            custom_dns (list|None): Either list with IPs or None
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal options")

        user_configs = self.get_user_configurations()

        user_configs[
            UserSettingConnectionEnum.DNS
        ][UserSettingConnectionEnum.DNS_STATUS] = status

        self.set_user_configurations(user_configs)

    def set_dns_custom_ip(self, custom_dns):
        """Set customn DNS IP list method.

        Args:
            custom_dns (list)
        """
        user_configs = self.get_user_configurations()
        user_configs[
            UserSettingConnectionEnum.DNS
        ][UserSettingConnectionEnum.CUSTOM_DNS] = custom_dns

        self.set_user_configurations(user_configs)

    def set_killswitch(self, status):
        """Set Kill Switch setting method.

        Args:
            status (UserSettingStatusEnum): Kill Switch status
        """
        if not isinstance(status, KillswitchStatusEnum):
            raise KeyError("Illegal options")

        user_configs = self.get_user_configurations()
        user_configs[
            UserSettingConnectionEnum.KILLSWITCH
        ] = status # noqa
        self.set_user_configurations(user_configs)

    def set_secure_core(self, status):
        """Set Secure Core setting method.

        Args:
            status (SecureCoreStatusEnum): Secure Core status
        """
        if not isinstance(status, SecureCoreStatusEnum):
            raise KeyError("Illegal options")

        user_configs = self.get_user_configurations()
        user_configs[
            UserSettingConnectionEnum.SECURE_CORE
        ] = status # noqa

        self.set_user_configurations(user_configs)

    def set_alternative_routing(self, status):
        """Set Alternative Routing.

        Args:
            status (UserSettingStatusEnum): DNS status
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal options")

        user_configs = self.get_user_configurations()

        user_configs[UserSettingConnectionEnum.ALTERNATIVE_ROUTING] = status

        self.set_user_configurations(user_configs)

    def set_netshield(self, status):
        """Set NetShield setting method.

        Args:
            status (int): matching value for NetShield
        """
        status_exists = False
        for k, v in NETSHIELD_STATUS_DICT.items():
            if k == status:
                status_exists = True
                break

        if not status_exists:
            raise KeyError("Illegal netshield option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.NETSHIELD] = status
        self.set_user_configurations(user_configs)

    def set_vpn_accelerator(self, status):
        """Set VPN Accelerator setting method.

        Args:
            status (UserSettingStatusEnum)
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.VPN_ACCELERATOR] = status
        self.set_user_configurations(user_configs)

    def set_event_notification(self, status):
        """Set event notification setting method.

        Args:
            status (NotificationStatusEnum)
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.EVENT_NOTIFICATION] = status
        self.set_user_configurations(user_configs)

    def set_new_brand_notification(self, status):
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.NEW_BRAND_INFO] = status
        self.set_user_configurations(user_configs)

    def set_moderate_nat(self, status):
        """Set event notification setting method.

        Args:
            status (UserSettingStatusEnum)
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.MODERATE_NAT] = status
        self.set_user_configurations(user_configs)

    def set_non_standard_ports(self, status):
        """Set event notification setting method.

        Args:
            status (UserSettingStatusEnum)
        """
        if status not in CONFIG_STATUSES:
            raise KeyError("Illegal option")

        user_configs = self.get_user_configurations()
        user_configs[UserSettingConnectionEnum.NON_STANDARD_PORTS] = status
        self.set_user_configurations(user_configs)

    def reset_default_configs(self):
        """Reset user configurations to default values."""
        self.initialize_configuration_file(True)

    def initialize_configuration_file(self, force_init=False):
        """Initialize configurations file.

        Args:
            force_init (bool): if True then overwrites current configs
        """
        if not os.path.isfile(self.user_config_filepath) or force_init: # noqa
            self.set_user_configurations(USER_CONFIG_TEMPLATE)

    def get_user_configurations(self):
        """Get user configurations from file. Reads from file.

        If any keys mismatch, it will attempt to reset
        the configuration file to default values and re-read
        the values.

        Returns:
            dict(json)
        """
        with open(self.user_config_filepath, "r") as f:
            try:
                user_configuration_object = self.transform_dict_to_enum(
                    json.load(f)
                )
            except KeyError:
                pass
            else:
                return user_configuration_object

        self.reset_default_configs()
        with open(self.user_config_filepath, "r") as f:
            return self.transform_dict_to_enum(json.load(f))

    def transform_dict_to_enum(self, json_data):
        """Transform user configuration data
        from json/dict to dict of enum objects.

        Args:
            json_data (dict): user configurations read from file

        Returns:
            Dict(Enum): dict with enums that represent user configurations
        """

        transformed_object = {}
        for json_data_key, json_dict_value in json_data.items():

            _enum_setting_first_key = UserSettingConnectionEnum[
                json_data_key.upper()
            ]
            if isinstance(json_dict_value, dict):
                internal_dict = {}
                for internal_dict_key, internal_dict_value in json_dict_value.items(): # noqa

                    _enum_setting_second_key = UserSettingConnectionEnum[
                        internal_dict_key.upper()
                    ]

                    template_dict_value_enum_object = USER_CONFIG_TEMPLATE[
                        _enum_setting_first_key
                    ][_enum_setting_second_key]

                    enum_object = template_dict_value_enum_object.__class__(
                        internal_dict_value
                    )

                    internal_dict[_enum_setting_second_key] = enum_object

                transformed_object[_enum_setting_first_key] = internal_dict
            else:
                template_dict_value_enum_object = USER_CONFIG_TEMPLATE[
                    _enum_setting_first_key
                ]

                if isinstance(json_dict_value, int):
                    transformed_object[
                        _enum_setting_first_key
                    ] = template_dict_value_enum_object.__class__(
                        json_dict_value
                    )
                elif isinstance(json_dict_value, str):
                    transformed_object[
                        _enum_setting_first_key
                    ] = template_dict_value_enum_object.__class__[
                        json_dict_value.upper()
                    ]
                else:
                    raise TypeError("Object {} is invalid".format(
                        json_dict_value
                    ))
        return transformed_object

    def set_user_configurations(self, config_dict):
        """Set user configurations. Writes to file.

        Args:
            config_dict (dict): user configurations
        """
        object = self.transform_enum_to_dict(config_dict)
        with open(self.user_config_filepath, "w") as f:
            json.dump(object, f, indent=4)

    def transform_enum_to_dict(self, json_data):
        """Transform user configuration data
        from dict of enum objects to dict.

        Args:
            json_data (dict(enum)): dict of enums that
            represent user configurations

        Returns:
            Dict: dict with string representations of enums
        """
        transformed_dict = {}
        for key, dict_value in json_data.items():
            if isinstance(dict_value, dict):
                value = {}
                for _key, _dict_value in dict_value.items():
                    value[_key.value] = (
                        _dict_value.value
                        if isinstance(_dict_value, Enum)
                        else _dict_value
                    )
            else:
                value = dict_value.value
            transformed_dict[key.value] = value
        return transformed_dict

    def is_valid_ip(self, ipaddr):
        """Check if the provided IP is valid IPv4.

        Args:
            ipaddr (string): IPv4

        Returns:
            bool
        """
        if not isinstance(ipaddr, str):
            raise ValueError("Invalid object type")

        valid_ip_re = re.compile(
            r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
            r'(/(3[0-2]|[12][0-9]|[1-9]))?$'  # Matches CIDR
        )

        if valid_ip_re.match(ipaddr):
            return True

        return False
