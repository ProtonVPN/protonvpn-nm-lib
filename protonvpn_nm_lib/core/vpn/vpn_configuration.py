import os
import tempfile
from abc import ABCMeta, abstractmethod

import jinja2
from jinja2 import Environment, FileSystemLoader

from ... import exceptions
from ...constants import OPENVPN_TEMPLATE, PROTON_XDG_CACHE_HOME, TEMPLATES
from ...enums import ProtocolEnum
from ...logger import logger
from .. import capture_exception
from ..environment import ExecutionEnvironment
from ..utils import SubclassesMixin


class VPNConfiguration(SubclassesMixin, metaclass=ABCMeta):
    """VPNConfiguration class.

    Generates VPN configuration that can be used to
    import via NM tool.
    """

    def __init__(self, physical_server):
        self._physical_server = physical_server
        self._configfile = None

    @classmethod
    def factory(cls, protocol, physical_server, *a, **kw):
        if not isinstance(protocol, ProtocolEnum):
            err_msg = "Incorrect object type, "\
                "ProtocolEnum is expected but got {} instead".format(
                    type(protocol)
                )
            logger.error(
                "[!] TypeError: {}. Raising exception.".format(err_msg)
            )
            raise TypeError(err_msg)

        protocol_dict = cls._get_subclasses_dict('protocol')

        if protocol not in protocol_dict:
            logger.exception("Raising IllegalVPNProtocol")
            raise exceptions.IllegalVPNProtocol()

        return protocol_dict[protocol](physical_server, *a, **kw)

    @abstractmethod
    def generate(self):
        pass

    @property
    @abstractmethod
    def config_extn(self):
        """Config file extension"""
        pass

    def __enter__(self):
        # We create the configuration file when we enter,
        # and delete it when we exit.
        # This is a race free way of having temporary files.
        if self._configfile is None:
            self.__delete_existing_ovpn_configuration()
            self._configfile = tempfile.NamedTemporaryFile(
                dir=PROTON_XDG_CACHE_HOME, delete=False,
                prefix='ProtonVPN-', suffix=self.config_extn, mode='w'
            )
            self._configfile.write(self.generate())
            self._configfile.close()
            self._configfile_enter_level = 0

        self._configfile_enter_level += 1

        return self._configfile.name

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._configfile is None:
            return

        self._configfile_enter_level -= 1
        if self._configfile_enter_level == 0:
            os.unlink(self._configfile.name)
            self._configfile = None

    def __delete_existing_ovpn_configuration(self):
        for file in os.listdir(PROTON_XDG_CACHE_HOME):
            if file.endswith(".ovpn"):
                os.remove(
                    os.path.join(PROTON_XDG_CACHE_HOME, file)
                )


class VPNConfigurationOpenVPN(VPNConfiguration):
    """VPNConfiguration class.

    Generates VPN configuration that can be used to
    import via NM tool.
    """

    @property
    def config_extn(self):
        return '.ovpn'

    @property
    @abstractmethod
    def ports(self):
        """Return a list of ports"""
        pass

    @property
    @abstractmethod
    def openvpn_protocol_name(self):
        """Return protocol name for use in OpenVPN config"""
        pass

    def generate(self):
        """Method that generates a vpn certificate.

        Returns:
            string: configuration file
        """

        logger.info("Generating OpenVPN configuration")

        j2_values = {
            "openvpn_protocol": self.openvpn_protocol_name,
            "serverlist": [self._physical_server.entry_ip],
            "openvpn_ports": self.ports,
        }

        j2 = Environment(loader=FileSystemLoader(TEMPLATES))

        template = j2.get_template(OPENVPN_TEMPLATE)

        try:
            return template.render(j2_values)
        except jinja2.exceptions.TemplateNotFound as e:
            logger.exception("[!] jinja2.TemplateNotFound: {}".format(e))
            raise jinja2.exceptions.TemplateNotFound(e)
        except Exception as e:
            logger.exception("[!] Unknown exception: {}".format(e))
            capture_exception(e)


class VPNConfigurationOpenVPNTCP(VPNConfigurationOpenVPN):
    protocol = ProtocolEnum.TCP

    @property
    def ports(self):
        """Return a list of ports"""
        return ExecutionEnvironment().api_session.vpn_ports_openvpn_tcp

    @property
    def openvpn_protocol_name(self):
        return "tcp"


class VPNConfigurationOpenVPNUDP(VPNConfigurationOpenVPN):
    protocol = ProtocolEnum.UDP

    @property
    def ports(self):
        """Return a list of ports"""
        return ExecutionEnvironment().api_session.vpn_ports_openvpn_udp

    @property
    def openvpn_protocol_name(self):
        return "udp"


class VPNConfigurationStrongSwan(VPNConfiguration):
    protocol = ProtocolEnum.IKEV2
    pass


class VPNConfigurationWireguard(VPNConfiguration):
    protocol = ProtocolEnum.WIREGUARD
    pass
