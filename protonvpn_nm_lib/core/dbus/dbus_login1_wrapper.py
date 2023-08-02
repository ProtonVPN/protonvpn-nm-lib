from .dbus_logger import logger

from ...enums import (SystemBusLogin1InterfaceEnum,
                      SystemBusLogin1ObjectPathEnum)
from .dbus_wrapper import DbusWrapper


class Login1UnitWrapper:
    BUS_NAME = "org.freedesktop.login1"

    def __init__(self, bus):
        self.__dbus_wrapper = DbusWrapper(bus)

    def get_properties_current_user_session(self):
        logger.info("Get properties for current user session")
        return self.__dbus_wrapper.get_proxy_object_properties_interface(
            self._get_current_user_session_proxy_object()
        ).GetAll(SystemBusLogin1InterfaceEnum.SESSION.value)

    def connect_user_session_object_to_signal(self, signal_name, method):
        """Connect a signal to user session object.

        Args:
            signal_name (string): the name of the signal to listen to
            method (func): the method that received the signal
        """
        logger.info("Connect user session to signal: {} {}".format(signal_name, method))
        interface = self._get_current_session_interface()
        interface.connect_to_signal(signal_name, method)

    def _get_current_session_interface(self):
        """Get current session interface.

        The current session is usually session/self path.

        Returns:
            dbus.proxies.Interface: org.freedesktop.login1.User interface
        """
        logger.info("Get current user session interface")
        return self.__dbus_wrapper.get_proxy_object_interface(
            self._get_current_user_session_proxy_object(),
            SystemBusLogin1InterfaceEnum.SESSION.value
        )

    def connect_login1_object_to_signal(self, signal_name, method):
        """Connect a signal to user session object.

        Args:
            signal_name (string): the name of the signal to listen to
            method (func): the method that received the signal
        """
        logger.info("Connect prepare for shutdown signal: {} {}".format(signal_name, method))
        interface = self.get_login_manager_interface()
        interface.connect_to_signal(signal_name, method)

    def get_login_manager_interface(self):
        """Get org.freedesktop.login1.Manager interface.

        Returns:
            dbus.proxies.Interface: Get org.freedesktop.login1.Manager interface
        """
        logger.info("Get org.freedesktop.login1.Manager interface")
        return self.__dbus_wrapper.get_proxy_object_interface(
            self.__get_proxy_object(SystemBusLogin1ObjectPathEnum.LOGIN1.value),
            SystemBusLogin1InterfaceEnum.MANAGER.value
        )

    def _get_current_user_session_proxy_object(self):
        """Get current session proxy object.

        The current session is usually session/self path.

        Returns:
            dbus.proxies.ProxyObject
        """
        logger.info("Get current user/session proxy object")
        all_params = self._get_properties_from_user_self()
        return self.__get_proxy_object(all_params["Sessions"][0][1])

    def get_user_interface_from_user_self_proxy_object(self):
        """Get org.freedesktop.login1.User interface.

        Returns:
            dbus.proxies.Interface: org.freedesktop.login1.User interface
        """
        logger.info("Get user/self proxy object")
        return self.__dbus_wrapper.get_proxy_object_interface(
            self._get_user_self_proxy_object(),
            SystemBusLogin1InterfaceEnum.LOGIN1_USER.value
        )

    def _get_properties_from_user_self(self):
        """Get properties from user/self object.

        Returns:
            dict: with user properties
        """
        logger.info("Get user/self properties")
        prop_iface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.get_user_interface_from_user_self_proxy_object()
        )
        return prop_iface.GetAll(SystemBusLogin1InterfaceEnum.LOGIN1_USER.value)

    def _get_user_self_proxy_object(self):
        """Get /org/freedesktop/login1/user/self proxy object.

        Returns:
            dbus.proxies.ProxyObject
        """
        logger.info("Get user/self proxy object")
        return self.__get_proxy_object(SystemBusLogin1ObjectPathEnum.USER_SELF.value)

    def __get_proxy_object(self, path_to_object):
        return self.__dbus_wrapper.get_proxy_object(
            self.BUS_NAME,
            path_to_object
        )
