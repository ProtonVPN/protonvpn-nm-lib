import dbus
from dbus.mainloop.glib import DBusGMainLoop

from ... import exceptions
from ...constants import (IPv6_DUMMY_ADDRESS, IPv6_DUMMY_GATEWAY,
                          IPv6_LEAK_PROTECTION_CONN_NAME,
                          IPv6_LEAK_PROTECTION_IFACE_NAME, KILLSWITCH_DNS_PRIORITY_VALUE)
from ...enums import KillSwitchActionEnum, KillSwitchInterfaceTrackerEnum
from ...logger import logger
from ..dbus.dbus_network_manager_wrapper import NetworkManagerUnitWrapper
from ..subprocess_wrapper import subprocess


class IPv6LeakProtection:
    """Manages IPv6 leak protection connection/interfaces."""
    enable_ipv6_leak_protection = True

    # Additional loop needs to be create since SystemBus automatically
    # picks the default loop, which is intialized with the CLI.
    # Thus, to refrain SystemBus from using the default loop,
    # one extra loop is needed only to be passed, while it is never used.
    # https://dbus.freedesktop.org/doc/dbus-python/tutorial.html#setting-up-an-event-loop
    dbus_loop = DBusGMainLoop()
    bus = dbus.SystemBus(mainloop=dbus_loop)

    def __init__(
        self,
        nm_wrapper=NetworkManagerUnitWrapper,
        iface_name=IPv6_LEAK_PROTECTION_IFACE_NAME,
        conn_name=IPv6_LEAK_PROTECTION_CONN_NAME,
        ipv6_dummy_addrs=IPv6_DUMMY_ADDRESS,
        ipv6_dummy_gateway=IPv6_DUMMY_GATEWAY,
    ):
        self.iface_name = iface_name
        self.conn_name = conn_name
        self.ipv6_dummy_addrs = ipv6_dummy_addrs
        self.ipv6_dummy_gateway = ipv6_dummy_gateway
        self.interface_state_tracker = {
            self.conn_name: {
                KillSwitchInterfaceTrackerEnum.EXISTS: False,
                KillSwitchInterfaceTrackerEnum.IS_RUNNING: False
            }
        }
        self.nm_wrapper = nm_wrapper(self.bus)
        logger.info("Intialized IPv6 leak protection manager")
        self.get_status_connectivity_check()

    def manage(self, action):
        """Manage IPv6 leak protection.

        Args:
            action (string): either enable or disable
        """
        logger.info("Manage IPV6: {}".format(action))
        self._ensure_connectivity_check_is_disabled()
        self.update_connection_status()

        if (
            action == KillSwitchActionEnum.ENABLE
            and self.enable_ipv6_leak_protection
        ):
            self.add_leak_protection()
        elif action == KillSwitchActionEnum.DISABLE:
            try:
                self.remove_leak_protection()
            except: # noqa
                self.deactivate_connection()
        else:
            raise exceptions.IPv6LeakProtectionOptionError(
                "Incorrect option for IPv6 leak manager"
            )

    def add_leak_protection(self):
        """Add leak protection connection/interface."""
        logger.info("Adding IPv6 leak protection")
        subprocess_command = [
            "nmcli", "c", "a", "type", "dummy",
            "ifname", IPv6_LEAK_PROTECTION_IFACE_NAME,
            "con-name", IPv6_LEAK_PROTECTION_CONN_NAME,
            "ipv6.method", "manual",
            "ipv6.addresses", IPv6_DUMMY_ADDRESS,
            "ipv6.gateway", IPv6_DUMMY_GATEWAY,
            "ipv6.route-metric", "95",
            # "ipv4.dns-priority", KILLSWITCH_DNS_PRIORITY_VALUE,
            "ipv6.dns-priority", KILLSWITCH_DNS_PRIORITY_VALUE,
            # "ipv4.ignore-auto-dns", "yes",
            "ipv6.ignore-auto-dns", "yes",
            # "ipv4.dns", "0.0.0.0",
            "ipv6.dns", "::1"
        ]

        if not self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.EXISTS
        ] or self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.EXISTS
        ] and not self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.IS_RUNNING
        ]:
            self.manage(KillSwitchActionEnum.DISABLE)
            self.run_subprocess(
                exceptions.EnableIPv6LeakProtectionError,
                "Unable to add IPv6 leak protection connection/interface",
                subprocess_command
            )

    def remove_leak_protection(self):
        """Remove leak protection connection/interface."""
        logger.info("Removing IPv6 leak protection")
        subprocess_command = "nmcli c delete {}".format(
            IPv6_LEAK_PROTECTION_CONN_NAME
        ).split(" ")

        self.update_connection_status()
        if self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.EXISTS
        ]:
            try:
                self.run_subprocess(
                    exceptions.DisableIPv6LeakProtectionError,
                    "Unable to remove IPv6 leak protection connection/interface",
                    subprocess_command
                )
            except exceptions.DisableIPv6LeakProtectionError as e:
                logger.exception(e)
                self.deactivate_connection()

    def deactivate_connection(self):
        """Deactivate a connection."""
        self.update_connection_status()
        active_conn_dict = self.nm_wrapper.search_for_connection(
            IPv6_LEAK_PROTECTION_CONN_NAME, is_active=True,
            return_active_conn_path=True
        )
        if (
            self.interface_state_tracker[IPv6_LEAK_PROTECTION_CONN_NAME][
                KillSwitchInterfaceTrackerEnum.IS_RUNNING
            ] and active_conn_dict
        ):
            active_conn_path = str(active_conn_dict.get("active_conn_path"))
            try:
                self.nm_wrapper.disconnect_connection(
                    active_conn_path
                )
            except dbus.exceptions.DBusException as e:
                logger.exception(e)
                raise exceptions.DectivateKillswitchError(
                    "Unable to deactivate {}".format(IPv6_LEAK_PROTECTION_CONN_NAME)
                )

    def run_subprocess(self, exception, exception_msg, *args):
        """Run provided input via subprocess.

        Args:
            exception (exceptions.IPv6LeakProtectionError):
                exception based on action
            exception_msg (string): exception message
            *args (list): arguments to be passed to subprocess
        """
        subprocess_outpout = subprocess.run(
            *args, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if (
            subprocess_outpout.returncode != 0
            and subprocess_outpout.returncode != 10
        ):
            logger.error(
                "Interface state tracker: {}".format(
                    self.interface_state_tracker
                )
            )
            logger.error(
                "{}: {}. Raising exception.".format(
                    exception,
                    subprocess_outpout
                )
            )
            raise exception(exception_msg)

    def update_connection_status(self):
        """Update connection/interface status."""
        all_conns = self.nm_wrapper.get_all_connections()
        active_conns = self.nm_wrapper.get_all_active_connections()

        self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.EXISTS
        ] = False

        self.interface_state_tracker[self.conn_name][
            KillSwitchInterfaceTrackerEnum.IS_RUNNING
        ] = False

        for conn in all_conns:
            try:
                conn_name = str(self.nm_wrapper.get_settings_from_connection(
                    conn
                )["connection"]["id"])
            except dbus.exceptions.DBusException:
                conn_name = "None"

            if conn_name in self.interface_state_tracker:
                self.interface_state_tracker[conn_name][
                    KillSwitchInterfaceTrackerEnum.EXISTS
                ] = True

        for active_conn in active_conns:
            try:
                conn_name = str(self.nm_wrapper.get_active_connection_properties(
                    conn
                )["connection"]["id"])
            except dbus.exceptions.DBusException:
                conn_name = "None"

            if conn_name in self.interface_state_tracker:
                self.interface_state_tracker[conn_name][
                    KillSwitchInterfaceTrackerEnum.IS_RUNNING
                ] = True

        logger.info("IPv6 status: {}".format(self.interface_state_tracker))

    def _ensure_connectivity_check_is_disabled(self):
        conn_check = self.connectivity_check()

        if len(conn_check) > 0:
            logger.info("Attempting to disable connectivity check")
            self.disable_connectivity_check(
                conn_check[0], conn_check[1]
            )

    def connectivity_check(self):
        (
            is_conn_check_available,
            is_conn_check_enabled,
        ) = self.get_status_connectivity_check()

        if not is_conn_check_enabled:
            return tuple()

        if not is_conn_check_available:
            logger.error(
                "AvailableConnectivityCheckError: "
                + "Unable to change connectivity check for IPv6 Leak."
                + "Raising exception."
            )
            raise exceptions.AvailableConnectivityCheckError(
                "Unable to change connectivity check for IPv6 Leak"
            )

        return is_conn_check_available, is_conn_check_enabled

    def get_status_connectivity_check(self):
        """Check status of NM connectivity check."""
        nm_props = self.nm_wrapper.get_network_manager_properties()
        is_conn_check_available = nm_props["ConnectivityCheckAvailable"]
        is_conn_check_enabled = nm_props["ConnectivityCheckEnabled"]

        logger.info(
            "Conn check available ({}) - Conn check enabled ({})".format(
                is_conn_check_available,
                is_conn_check_enabled
            )
        )

        return is_conn_check_available, is_conn_check_enabled

    def disable_connectivity_check(
        self, is_conn_check_available, is_conn_check_enabled
    ):
        """Disable NetworkManager connectivity check."""
        if is_conn_check_enabled:
            logger.info("Disabling connectivity check")
            nm_methods = self.nm_wrapper.get_network_manager_properties_interface()
            nm_methods.Set(
                "org.freedesktop.NetworkManager",
                "ConnectivityCheckEnabled",
                False
            )
            nm_props = self.nm_wrapper.get_network_manager_properties()
            if nm_props["ConnectivityCheckEnabled"]:
                logger.error(
                    "DisableConnectivityCheckError: "
                    + "Can not disable connectivity check for IPv6 Leak."
                    + "Raising exception."
                )
                raise exceptions.DisableConnectivityCheckError(
                    "Can not disable connectivity check for IPv6 Leak"
                )

            logger.info("Check connectivity has been 'disabled'")
