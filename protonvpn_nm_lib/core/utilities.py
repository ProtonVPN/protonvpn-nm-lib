import subprocess
from ..logger import logger
from .. import exceptions
import requests
from ..enums import KillswitchStatusEnum, ProtocolEnum, ConnectionTypeEnum
from ..constants import FLAT_SUPPORTED_PROTOCOLS
import re
from .environment import ExecutionEnvironment


class Utilities:

    @staticmethod
    def ensure_connectivity():
        utils = Utilities()

        utils.ensure_internet_connection_is_available()

    @staticmethod
    def ensure_internet_connection_is_available():
        logger.info("Checking for internet connectivity")
        if ExecutionEnvironment().settings.killswitch != KillswitchStatusEnum.DISABLED:
            logger.info("Skipping as killswitch is enabled")
            return

        # 192.0.2.1 is used because is a valid IP that won't be in use,
        # since it is reserved for documentation purposes:
        # https://www.rfc-editor.org/rfc/rfc5737.html
        result = subprocess.run(["ip", "route", "get", "192.0.2.1"], check=False, capture_output=True)
        if result.returncode != 0:
            raise exceptions.NetworkConnectionError(
                "No internet connection. "
                "Please make sure you are connected and retry."
            )

    @staticmethod
    def ensure_servername_is_valid(servername):
        """Check if the provided servername is in a valid format.

        Args:
            servername (string): the servername [SE-PT#1]
        Returns:
            bool
        """
        logger.info("Validating servername")
        if not isinstance(servername, str):
            err_msg = "Incorrect object type, "\
                "str is expected but got {} instead".format(type(servername))
            logger.error(
                "[!] TypeError: {}. Raising Exception.".format(err_msg)
            )
            raise TypeError(err_msg)

        re_compile = re.compile(r"^(\w\w)(-\w+)?#(\w+-)?(\w+)$")

        if not re_compile.search(servername):
            raise exceptions.UnexpectedServername(
                "Unexpected servername {}".format(
                    servername
                )
            )

    @staticmethod
    def ensure_ip_is_valid(ipaddr):
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

        if not valid_ip_re.match(ipaddr):
            raise Exception(
                "Invalid IP address \"{}\"".format(
                    ipaddr
                )
            )

    @staticmethod
    def is_protocol_valid(protocol):
        logger.info("Checking if protocol is valid")
        try:
            protocol = ProtocolEnum(protocol)
        except (TypeError, ValueError):
            return False

        if protocol in FLAT_SUPPORTED_PROTOCOLS:
            return True

        return False

    @staticmethod
    def ensure_protocol_is_valid(protocol):
        """Check if provided protocol is a valid protocol.

        Args:
            protocol (ProtocolEnum)

        Returns:
            bool
        """
        logger.info("Ensuring provided protocol is valid")
        if not Utilities.is_protocol_valid(protocol):
            raise Exception(
                "Invalid protocol \"{}\"".format(
                    protocol
                )
            )

    @staticmethod
    def parse_user_input(user_input):
        connection_type = user_input.get("connection_type")
        connection_type_extra_arg = user_input.get("connection_type_extra_arg")
        protocol = user_input.get("protocol")

        utils = Utilities
        if connection_type == ConnectionTypeEnum.COUNTRY:
            from .country import Country
            country = Country()
            country.ensure_country_code_exists(connection_type_extra_arg)
        if connection_type == ConnectionTypeEnum.SERVERNAME:
            utils.ensure_servername_is_valid(
                connection_type_extra_arg
            )

        connection_type = connection_type
        connection_type_extra_arg = connection_type_extra_arg

        if connection_type not in [
            ConnectionTypeEnum.SERVERNAME, ConnectionTypeEnum.COUNTRY
        ]:
            connection_type_extra_arg = connection_type

        if not utils.is_protocol_valid(protocol):
            protocol = ProtocolEnum(
                ExecutionEnvironment().settings.protocol
            )
        else:
            protocol = ProtocolEnum(protocol)

        return connection_type, connection_type_extra_arg, protocol

    @staticmethod
    def post_setup_connection_save_metadata(
        connection_metadata, servername,
        protocol, physical_server
    ):
        connection_metadata.save_servername(servername)
        connection_metadata.save_protocol(protocol)
        connection_metadata.save_display_server_ip(physical_server.exit_ip)
        connection_metadata.save_server_ip(physical_server.entry_ip)
