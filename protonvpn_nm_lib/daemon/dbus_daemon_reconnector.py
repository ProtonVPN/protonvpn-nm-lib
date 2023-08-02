import os

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
from protonvpn_nm_lib.constants import VIRTUAL_DEVICE_NAME
from protonvpn_nm_lib.core.environment import ExecutionEnvironment
from protonvpn_nm_lib.daemon.daemon_logger import logger
from protonvpn_nm_lib.enums import (KillSwitchActionEnum, KillswitchStatusEnum,
                                    VPNConnectionReasonEnum,
                                    VPNConnectionStateEnum)

env = ExecutionEnvironment()
connection_metadata = env.connection_metadata
killswitch = env.killswitch
ipv6_leak_protection = env.ipv6leak
settings = env.settings

from protonvpn_nm_lib.core.dbus.dbus_login1_wrapper import Login1UnitWrapper
from protonvpn_nm_lib.core.dbus.dbus_network_manager_wrapper import \
    NetworkManagerUnitWrapper


class ProtonVPNReconnector:
    """Reconnects to VPN if disconnected not by user
        or when connecting to a new network.

    Params:
        virtual_device_name (string): Name of virtual device that will be used
        for ProtonVPNReconnector
        max_attempts (int): Maximum number of attempts ofreconnection VPN
        session on failures
        param delay (int): Milliseconds to wait before reconnecting VPN

    """
    def __init__(self, virtual_device_name, loop, max_attempts=100, delay=5000): # noqa
        logger.info(
            "\n\n------------------------"
            " Initializing Dbus daemon manager "
            "------------------------\n"
        )
        self.virtual_device_name = virtual_device_name
        self.loop = loop
        self.max_attempts = max_attempts
        self.delay = delay
        self.failed_attempts = 0
        self.bus = dbus.SystemBus()
        self.nm_wrapper = NetworkManagerUnitWrapper(self.bus)
        self.login1_wrapper = Login1UnitWrapper(self.bus)
        self.is_user_session_locked = False
        self.suspend_lock = None
        self.shutdown_lock = None
        # Auto connect at startup (Listen for StateChanged going forward)
        self.vpn_activator()
        self.connect_signals()

    def connect_signals(self):
        self.login1_wrapper.connect_user_session_object_to_signal(
            "Lock", self.on_session_lock
        )
        self.login1_wrapper.connect_user_session_object_to_signal(
            "Unlock", self.on_session_unlock
        )
        self.login1_wrapper.connect_login1_object_to_signal(
            "PrepareForShutdown", self.on_prepare_for_shutdown
        )
        self.login1_wrapper.connect_login1_object_to_signal(
            "PrepareForSleep", self.on_prepare_for_suspend
        )
        self.nm_wrapper.connect_network_manager_object_to_signal(
            "StateChanged", self.on_network_state_changed
        )
        self._create_on_suspend_lock()
        self._create_on_shutdown_lock()

        self.is_user_session_locked = \
            False \
            if self.login1_wrapper.get_properties_current_user_session()["State"] == "active" \
            else True

    def _create_on_suspend_lock(self):
        if self.suspend_lock:
            return

        login_manager_interface = self.login1_wrapper.get_login_manager_interface()
        try:
            logger.info("Create sleep inhibit lock")
            self.suspend_lock = login_manager_interface.Inhibit(
                "sleep", "ProtonVPN", "Update session lock status", "delay"
            ).take()
            logger.info("Sleep lock created: {} {}".format(
                self.suspend_lock, type(self.suspend_lock)
            ))
        except Exception as e:
            logger.exception(e)

    def _create_on_shutdown_lock(self):
        if self.shutdown_lock:
            return

        login_manager_interface = self.login1_wrapper.get_login_manager_interface()
        try:
            logger.info("Create shutdown inhibit lock")
            self.shutdown_lock = login_manager_interface.Inhibit(
                "shutdown", "ProtonVPN", "Remove VPN interfaces", "delay"
            ).take()
            logger.info("Shutdown lock created: {} {}".format(
                self.shutdown_lock, type(self.shutdown_lock)
            ))
        except Exception as e:
            logger.exception(e)

    def on_session_lock(self):
        self.is_user_session_locked = True
        logger.info("Session state: \"{}\"".format("Locked" if self.is_user_session_locked else "Unlocked"))

    def on_session_unlock(self):
        self.is_user_session_locked = False
        logger.info("Session state: \"{}\"".format("Locked" if self.is_user_session_locked else "Unlocked"))
        self.vpn_activator()

    def on_prepare_for_shutdown(self, *args, **kwargs):
        logger.info("Preparing for shutdown")

        if settings.killswitch != KillswitchStatusEnum.HARD:
            logger.info("Remove Kill Switch interface")
            killswitch.delete_all_connections()

        logger.info("Remove IPv6 leak protection")
        ipv6_leak_protection.remove_leak_protection()

        if not self.shutdown_lock:
            return

        logger.info(
            "Attempting to release shutdown lock: {} {}".format(
                self.shutdown_lock, type(self.shutdown_lock)
            )
        )
        try:
            os.close(self.shutdown_lock)
            self.shutdown_lock = None
        except Exception as e:
            logger.exception(e)
            return

        logger.info("Successuflly released shutdown lock")

    def on_prepare_for_suspend(self, *args, **kwargs):
        logger.info("Preparing for sleep")

        self.is_user_session_locked = True
        logger.info("Session state: \"{}\"".format("Locked" if self.is_user_session_locked else "Unlocked"))

        if not self.suspend_lock:
            return

        logger.info(
            "Attempting to release suspend lock: {} {}".format(
                self.suspend_lock, type(self.suspend_lock)
            )
        )

        try:
            os.close(self.suspend_lock)
            self.suspend_lock = None
        except Exception as e:
            logger.exception(e)
            return

        logger.info("Successuflly released suspend lock")

    def on_network_state_changed(self, state):
        """Network status signal handler.

        Args:
            state (int): connection state (NMState)
        """
        logger.info("Network state changed: {}".format(state))
        if state == 70:
            self.vpn_activator()

    def on_vpn_state_changed(self, state, reason):
        """VPN status signal handler.

        Args:
            state (int): NMVpnConnectionState
            reason (int): NMActiveConnectionStateReason
        """
        state = VPNConnectionStateEnum(state)
        reason = VPNConnectionReasonEnum(reason)
        logger.info(
            "State: {} - ".format(state)
            + "Reason: {}".format(
                reason
            )
        )
        if state == VPNConnectionStateEnum.IS_ACTIVE and not self.is_user_session_locked:
            logger.info(
                "Proton VPN with virtual device '{}' is running.".format(
                    self.virtual_device_name
                )
            )
            self.failed_attempts = 0

            connection_metadata.save_connect_time()

            try:
                if ipv6_leak_protection.enable_ipv6_leak_protection:
                    ipv6_leak_protection.manage(
                        KillSwitchActionEnum.ENABLE
                    )
            except: # noqa
                pass

            if (
                settings.killswitch
                != KillswitchStatusEnum.DISABLED
            ):
                killswitch.manage(
                    KillSwitchActionEnum.POST_CONNECTION
                )
                logger.info("Running killswitch post-connection mode")

        elif (
            state == VPNConnectionStateEnum.DISCONNECTED
            and reason == VPNConnectionReasonEnum.USER_HAS_DISCONNECTED
            and not self.is_user_session_locked
        ):
            logger.info("Proton VPN connection was manually disconnected.")
            self.failed_attempts = 0

            try:
                vpn_iface = self.nm_wrapper.get_vpn_interface()
            except TypeError as e:
                logger.exception(e)

            try:
                vpn_iface.Delete()
            except dbus.exceptions.DBusException as e:
                logger.error(
                    "Unable to remove connection. "
                    + "Exception: {}".format(e)
                )
            except AttributeError:
                pass

            logger.info("Proton VPN connection has been manually removed.")

            try:
                ipv6_leak_protection.manage(
                    KillSwitchActionEnum.DISABLE
                )
            except: # noqa
                pass

            if (
                settings.killswitch
                != KillswitchStatusEnum.HARD
            ):
                killswitch.delete_all_connections()

            loop.quit()

        elif state in [
            VPNConnectionStateEnum.FAILED,
            VPNConnectionStateEnum.DISCONNECTED
        ] and not self.is_user_session_locked:
            # reconnect if haven't reached max_attempts
            if (
                not self.max_attempts
            ) or (
                self.failed_attempts < self.max_attempts
            ):
                logger.info("Connection failed, attempting to reconnect.")
                self.failed_attempts += 1
                glib_reconnect = True
                GLib.timeout_add(
                    self.delay, self.vpn_activator, glib_reconnect
                )
            else:
                logger.warning(
                    "Connection failed, exceeded {} max attempts.".format(
                        self.max_attempts
                    )
                )

    def setup_protonvpn_conn(self, active_connection, vpn_interface):
        """Setup and start new Proton VPN connection.

        Args:
            active_connection (string): path to active connection
            vpn_interface (dbus.Proxy): proxy interface to vpn connection
        """
        logger.info(
            "Setting up Proton VPN connection: {} {}".format(
                active_connection, vpn_interface
            )
        )
        new_con = self.nm_wrapper.activate_connection(
            vpn_interface,
            dbus.ObjectPath("/"),
            active_connection
        )
        self.vpn_signal_handler(new_con)
        logger.info(
            "Starting manually Proton VPN connection with '{}'.".format(
                self.virtual_device_name
            )
        )

    def manually_start_vpn_conn(self, server_ip, vpn_interface):
        logger.info("User ks setting: {}".format(
            settings.killswitch
        ))
        if (
            settings.killswitch
            != KillswitchStatusEnum.DISABLED
        ):
            try:
                killswitch.manage(
                    KillSwitchActionEnum.PRE_CONNECTION,
                    server_ip=server_ip
                )
            except Exception as e:
                logger.exception(
                    "KS manager reconnect exception: {}".format(e)
                )
                return False
        logger.info("Created routed interface")

        try:
            new_active_connection = self.nm_wrapper.get_active_connection()
        except (dbus.exceptions.DBusException, Exception) as e:
            logger.exception(e)
            new_active_connection = None

        logger.info(
            "Active conn prior to "
            "setup manual connection: {} {}".format(
                new_active_connection,
                type(new_active_connection)
            )
        )

        if not new_active_connection:
            logger.info("No active connection, retrying reconnect")
            return False
        else:
            logger.info("Setting up manual connection")

            try:
                self.setup_protonvpn_conn(
                    new_active_connection, vpn_interface
                )
            except dbus.exceptions.DBusException as e:
                logger.exception(
                    "Unable to start VPN connection: {}.".format(e)
                )
                return False
            except Exception as e:
                logger.exception(
                    "Unknown reconnector error: {}.".format(e)
                )
                return False

            logger.info(
                "New Proton VPN connection has been started "
                + "from service."
            )
            return True

    def vpn_activator(self, glib_reconnect=False):
        """Monitor and activate Proton VPN connections."""
        logger.info(
            "\n\n------- "
            "VPN Activator"
            " -------\n"
            + "Virtual device being monitored: {}; ".format(
                self.virtual_device_name
            ) + "Attempt {}/{} with interval of {} ".format(
                self.failed_attempts, self.max_attempts, self.delay
            ) + "ms;\n"
        )
        if self.is_user_session_locked:
            return

        vpn_interface = self.nm_wrapper.get_vpn_interface()

        try:
            active_connection = self.nm_wrapper.get_active_connection()
        except (dbus.exceptions.DBusException, Exception) as e:
            logger.exception(e)
            active_connection = None

        logger.info("VPN interface: {}".format(vpn_interface))
        logger.info("Active connection: {}".format(active_connection))

        if active_connection is None or vpn_interface is None:
            if not glib_reconnect:
                logger.info("Calling manually on vpn state changed")
                self.on_vpn_state_changed(
                    VPNConnectionStateEnum.FAILED,
                    VPNConnectionReasonEnum.UNKNOWN
                )
            else:
                return True

        (
            is_active_conn_vpn,
            all_vpn_settings
        ) = self.nm_wrapper.check_active_vpn_connection(
            active_connection
        )

        # Check if primary active connection was started by Proton VPN client
        if (
            is_active_conn_vpn
        ) and (
            all_vpn_settings["vpn"]["data"]["dev"]
            == self.virtual_device_name
        ):
            logger.info("Primary connection via Proton VPN.")
            self.vpn_signal_handler(active_connection)
            return False

        server_ip = connection_metadata.get_server_ip()
        logger.info("Reconnecting to server IP \"{}\"".format(server_ip))

        try:
            (
                is_protonvpn, state, conn
            ) = self.nm_wrapper.is_protonvpn_being_prepared()
        except dbus.exceptions.DBusException as e:
            logger.exception(e)
        else:

            # Check if connection is being prepared
            if is_protonvpn and state == 1:
                logger.info("Proton VPN connection is being prepared.")
                if (
                    settings.killswitch
                    != KillswitchStatusEnum.DISABLED
                ):
                    killswitch.manage(
                        KillSwitchActionEnum.PRE_CONNECTION,
                        server_ip=server_ip
                    )
                self.vpn_signal_handler(conn)
                return False

        if not self.manually_start_vpn_conn(server_ip, vpn_interface):
            if not glib_reconnect:
                logger.info("Calling manually on vpn state changed")
                self.on_vpn_state_changed(
                    VPNConnectionStateEnum.FAILED,
                    VPNConnectionReasonEnum.UNKNOWN
                )
            else:
                return True

    def vpn_signal_handler(self, conn):
        """Add signal handler to Proton VPN connection.

        Args:
            vpn_conn_path (string): path to Proton VPN connection
        """
        proxy = self.bus.get_object(
            "org.freedesktop.NetworkManager", conn
        )
        iface = dbus.Interface(
            proxy, "org.freedesktop.NetworkManager.VPN.Connection"
        )

        try:
            active_conn_props = self.nm_wrapper.get_active_connection_properties(conn)
            logger.info("Adding listener to active {} connection at {}".format(
                active_conn_props["Id"],
                conn)
            )
        except dbus.exceptions.DBusException:
            logger.info(
                "{} is not an active connection.".format(conn)
            )
        except Exception as e:
            logger.info(
                "Unknown add signal error: {}".format(e)
            )
        else:
            logger.info("Listener added")
            iface.connect_to_signal(
                "VpnStateChanged", self.on_vpn_state_changed
            )


DBusGMainLoop(set_as_default=True)
loop = GLib.MainLoop()
ins = ProtonVPNReconnector(VIRTUAL_DEVICE_NAME, loop)
loop.run()
