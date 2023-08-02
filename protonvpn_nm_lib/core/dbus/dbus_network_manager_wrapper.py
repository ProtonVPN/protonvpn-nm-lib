from .dbus_logger import logger

from dbus import exceptions as dbus_excp

from ...constants import VIRTUAL_DEVICE_NAME
from ...enums import SystemBusNMInterfaceEnum, SystemBusNMObjectPathEnum
from .dbus_wrapper import DbusWrapper


class NetworkManagerUnitWrapper:
    BUS_NAME = "org.freedesktop.NetworkManager"

    def __init__(self, bus):
        self.virtual_device_name = VIRTUAL_DEVICE_NAME
        self.__dbus_wrapper = DbusWrapper(bus)

    def search_for_connection(
        self, conn_name, interface_name=None, is_active=False,
        return_settings_path=False, return_device_path=False,
        return_active_conn_path=False,
    ):
        """Search for specified connection.

        Args:
            conn_name (string): connection/interface conn_name
            interface_name (string): (optional) Interface name.
            is_active (bool): check for active conns
            return_settings_path (bool): return settings path
            return_device_path (bool): return device path
            return_active_conn_path (bool): return active connection
            path. This returns only if is_active is also True.
        Returns:
           Dict: with specified content. Connection ID is returned always.
           To extract contents of dict, use the following keys:
            - connection_id
            - settings_path
            - device_path
            - active_conn_path
        """
        logger.info("Search for connection: ({} {} {} {} {} {})".format(
            conn_name, interface_name, is_active, return_settings_path,
            return_device_path, return_active_conn_path
        ))
        if is_active:
            connection_list = self.get_all_active_connections()
        else:
            connection_list = self.get_all_connections()

        for iterated_connection in connection_list:
            if is_active:
                conn_props = self.get_active_connection_properties(
                    iterated_connection
                )
                iterated_connection = conn_props["Connection"]

            try:
                all_connection_properties = self.get_settings_from_connection(
                    iterated_connection
                )
            except dbus_excp.DBusException as e:
                logger.info(
                    "Couldn't get settings from connection {}: {}".format(
                        iterated_connection, e
                    )
                )
                continue

            connection_id = str(all_connection_properties["connection"]["id"])

            dev_name = None
            if "vpn" in all_connection_properties:
                dev_name = all_connection_properties["vpn"].get("data")
                if dev_name:
                    dev_name = dev_name.get("dev")

            if (
                (
                    conn_name == connection_id
                ) or (
                    conn_name.lower() in connection_id.lower()
                    and interface_name != None
                    and interface_name == dev_name
                )
            ):
                return_dict = {"connection_id": connection_id}
                if return_settings_path:
                    return_dict["settings_path"] = iterated_connection
                if return_device_path:
                    return_dict["device_path"] = self.get_connection_device_path( # noqa
                        iterated_connection
                    )
                if return_active_conn_path and is_active:
                    return_dict["active_conn_path"] = self.get_active_connection( # noqa
                        get_by_settings_path=iterated_connection
                    )

                return return_dict

        return {}

    def get_connection_device_path(self, connection_settings_path):
        """Get path to connection device.

        Args:
            connection_settings_path (string): connection settings path

        Returns:
            string | None: either path to device if found
            or None if device was not found not.
        """
        logger.info("Get connection device path: {}".format(connection_settings_path))
        devices = self._get_all_devices()
        for device in devices:
            device_available_conns = self._get_available_connections_from_device(device)
            if len(device_available_conns) > 0:
                conn_settings_path = str(device_available_conns.pop())
                if connection_settings_path == conn_settings_path:
                    return device

        return None

    def activate_connection(
        self, connection_settings_path, device_path, specific_object=None
    ):
        """Activate existing connection.

        Args:
            connection_settings_path (string): The connection to activate.
                If "/" is given, a valid device path must be given, and
                NetworkManager picks the best connection to activate for the
                given device. VPN connections must alwayspass a valid
                connection path.
            device_path (string): The object path of device to be activated
                for physical connections. This parameter is ignored for VPN
                connections, because the specific_object (if provided)
                specifies the device to use.
            specific_object (string): The path of a connection-type-specific
                object this activation should use. This parameter is currently
                ignored for wired and mobile broadband connections, and the
                value of "/" should be used (ie, no specific object). For
                Wi-Fi connections, pass the object path of a specific AP from
                the card's scan list, or "/" to pick an AP automatically.
                For VPN connections, pass the object path of an
                ActiveConnection object that should serve as the "base"
                connection (to which the VPN connections lifetime
                will be tied), or pass "/" and NM will automatically use
                the current default device.

        Returns:
            string | None: either path to active connection
            if connection was successfully activated
            or None if not.
        """
        logger.info(
            "Activate connection: {} {} {}".format(
                connection_settings_path,
                device_path,
                specific_object
            )
        )
        nm_interface = self._get_network_manager_interface()
        active_conn_path = nm_interface.ActivateConnection(
            connection_settings_path,
            device_path,
            specific_object if specific_object else "/"
        )

        return None if not active_conn_path else active_conn_path

    def disconnect_connection(self, connection_path):
        """Disconnect active connection.

        Args:
            connection_path (string): path to active connection
        """
        logger.info("Disconnect connection: {}".format(connection_path))
        nm_interface = self._get_network_manager_interface()
        nm_interface.DeactivateConnection(connection_path)

    def delete_connection(self, connection_settings_path):
        """Disconnect active connection.

        Args:
            connection_path (string): path to active connection
        """
        logger.info("Delete connection: {}".format(connection_settings_path))
        connection_settings_interface = self._get_connection_settings_interface(
            connection_settings_path
        )
        connection_settings_interface.Delete()

    def check_active_vpn_connection(self, active_conn):
        """Check if active connection is VPN.

        Args:
            active_conn (string): active connection path

        Returns:
            [0]: bool
            [1]: None | dict with all connection settings
        """
        logger.info("Check active VPN connection: {}".format(active_conn))
        active_conn_all_settings = [False, None]

        if active_conn is None or len(active_conn) < 1:
            return active_conn_all_settings

        try:
            active_conn_props = self.get_active_connection_properties(active_conn)
        except dbus_excp.DBusException as e:
            logger.error(
                "Error occurred while getting properties from active "
                + "connection: '{}'. Exception: {}.".format(active_conn, e)
            )
        else:
            if (
                active_conn_props["Type"] == "vpn"
            ) and (
                # NMActiveConnectionState
                # State 1 = a network connection is being prepared
                # State 2 = there is a connection to the network
                active_conn_props["State"] == 2
            ):
                active_conn_all_settings[0] = True
                try:
                    active_conn_all_settings[1] = self.get_settings_from_connection(
                        active_conn_props["Connection"]
                    )
                except dbus_excp.DBusException:
                    active_conn_all_settings[1] = None

        return active_conn_all_settings

    def is_protonvpn_being_prepared(self):
        """Checks Proton VPN connection status.

        Returns:
            [0]: bool
            [1]: None | int (NMActiveConnectionState)
            [2]: None | string (active connection path)
        """
        logger.info("Check if VPN is being prepared")
        all_active_conns = self.get_all_active_connections()

        protonvpn_conn_info = [False, None, None]
        for active_conn in all_active_conns:
            active_conn_props = self.get_active_connection_properties(active_conn)

            try:
                vpn_all_settings = self.get_settings_from_connection(
                    active_conn_props["Connection"]
                )
            except dbus_excp.DBusException as e:
                logger.info(
                    "Couldn't get settings from connection {}: {}".format(
                        active_conn, e
                    )
                )
                continue

            if (
                active_conn_props["Type"] == "vpn"
            ) and (
                vpn_all_settings["vpn"]["data"]["dev"]
                == self.virtual_device_name
            ):
                protonvpn_conn_info[0] = True
                protonvpn_conn_info[1] = active_conn_props["State"]
                protonvpn_conn_info[2] = active_conn

        logger.info("Proton VPN conn info: {}".format(protonvpn_conn_info))
        return tuple(protonvpn_conn_info)

    def get_vpn_interface(self):
        """Get VPN connection interface based on virtual device name.

        Returns:
            dbus.proxies.Interface: to Proton VPN connection
        """
        logger.info(
            "Get connection interface from '{}' virtual device.".format(
                self.virtual_device_name
            )
        )
        connections = self.get_all_connections()
        for connection in connections:
            try:
                iface = self._get_connection_settings_interface(connection)
                all_settings = self.get_settings_from_connection(
                    connection
                )
            except dbus_excp.DBusException as e:
                logger.exception(e)
                continue
            # all_settings[
            #   connection dbus.Dictionary
            #   vpn dbus.Dictionary
            #   ipv4 dbus.Dictionary
            #   ipv6 dbus.Dictionary
            #   proxy dbus.Dictionary
            # ]
            if all_settings["connection"]["type"] == "vpn":
                vpn_virtual_device = False
                try:
                    vpn_virtual_device = all_settings["vpn"]["data"]["dev"]
                except KeyError:
                    logger.debug(
                        "VPN \"{}\" is missing \"dev\" parameter", format(
                            all_settings["connection"]["id"]
                        )
                    )
                    continue
                except Exception as e:
                    logger.exception(
                        "[!] Unhandled exceptions: {}\n".format(e)
                        + "Connection information: {}".format(all_settings)
                    )
                    continue

                if vpn_virtual_device == self.virtual_device_name:
                    logger.info(
                        "Found virtual device "
                        + "'{}'.".format(self.virtual_device_name)
                    )

                    return iface

        logger.error(
            "[!] Could not find interface belonging to '{}'.".format(
                self.virtual_device_name
            )
        )
        return None

    def get_active_connection(
        self, get_by_id=None,
        get_by_settings_path=False, get_by_device_path=False
    ):
        """Get interface of active
        connection with default route(s) if no options
        were specified. Else returns active connection
        for the specified option.
        All options are mutually exclusive.

        Args:
            get_by_id (string): connection id
            get_by_settings_path (string): connection settings path
            get_by_device_path (string): connection device path

        Returns:
            string: active connection path
        """
        logger.info("Getting active connection interface")
        active_connections = self.get_all_active_connections()
        logger.info(
            "All active conns in get_active_connection: {}".format(
                active_connections
            )
        )

        for active_conn in active_connections:
            try:
                active_conn_props = self.get_active_connection_properties(active_conn)
            except TypeError as e:
                logger.error(
                    "No active connections were found. "
                    + "Exception: {}.".format(e)
                )
                return None
            except dbus_excp.DBusException as e:
                logger.exception(e)
                continue

            logger.info("{}".format(active_conn_props))
            if get_by_id and str(active_conn_props["Id"]) == get_by_id:
                return active_conn
            elif get_by_settings_path and str(active_conn_props["Connection"]) == get_by_settings_path: # noqa
                return active_conn
            elif get_by_device_path and str(active_conn_props["Devices"].pop()) == get_by_device_path: # noqa
                return active_conn
            elif (
                active_conn_props["Default"]
            ) or (
                active_conn_props["Default"] and active_conn_props["Default6"]
            ):
                logger.info(
                    "Detected ({}) active ".format(
                        active_conn_props["Id"]
                    )
                    + "connection that has default route(s) "
                    + "IPv4: {} / IPv6: {}.".format(
                        active_conn_props["Default"],
                        active_conn_props["Default6"]
                    )
                )
                return active_conn

        return None

    def _get_connection_settings_interface(self, connection_object):
        logger.info("Getting connection settings interface: {}".format(connection_object))
        iface = self.__dbus_wrapper.get_proxy_object_interface(
            self.__get_proxy_object(connection_object),
            SystemBusNMInterfaceEnum.NM_CONNECTION_SETTINGS.value
        )
        return iface

    def get_active_connection_properties(self, active_conn):
        """Get active connection properties.

        Args:
            active_conn (string): active connection path

        Returns:
            dict: properties of an active connection
        """
        logger.info("Getting active connection properties: {}".format(active_conn))
        iface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.__get_proxy_object(active_conn)
        )
        return iface.GetAll(
            SystemBusNMInterfaceEnum.NM_CONNECTION_ACTIVE.value
        )

    def get_settings_from_connection(self, connection_path):
        """Get all settings of a connection.

        Args:
            conn (string): connection path
            return_iface (bool): also return the interface

        Returns:
            dict | interface:
                dict: only properties are returned
                tuple: dict with properties is returned
                    and also the interface to the connection
        """
        logger.info("Get settings from connection: {}".format(connection_path))
        iface = self._get_connection_settings_interface(connection_path)
        return iface.GetSettings()

    def get_all_connections(self):
        """Get all existing connections.

        Returns:
            list(string): yields path to all connections
        """
        logger.info("Get all connection")
        iface = self.__dbus_wrapper.get_proxy_object_interface(
            self.__get_proxy_object(SystemBusNMObjectPathEnum.NM_SETTINGS.value),
            SystemBusNMInterfaceEnum.NM_SETTINGS.value
        )
        all_conns = iface.ListConnections()
        for conn in all_conns:
            yield conn

    def get_all_active_connections(self):
        """Get all active connections.

        Returns:
            list(string): yields path to active connections
        """
        logger.info("Get all active connections")
        iface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.__get_proxy_object(SystemBusNMObjectPathEnum.NETWORK_MANAGER.value)
        )

        all_active_conns_list = iface.Get(
            SystemBusNMInterfaceEnum.NETWORK_MANAGER.value,
            "ActiveConnections"
        )
        for active_conn in all_active_conns_list:
            yield active_conn

    def get_network_manager_properties(self,):
        """Get all network manager properties.

        Returns:
            Dict: contains all network manager properties
        """
        logger.info("Get NetworkManager properties")
        nm_interface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.get_network_manager_proxy_object()
        )

        nm_properties = nm_interface.GetAll(
            SystemBusNMInterfaceEnum.NETWORK_MANAGER.value
        )

        return nm_properties

    def get_network_manager_properties_interface(self):
        logger.info("Get NetworkManager properties interface")
        nm_interface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.get_network_manager_proxy_object()
        )

        return nm_interface

    def connect_network_manager_object_to_signal(self, signal_name, method):
        """Connect a signal to network manager object.

        Args:
            signal_name (string): the name of the signal to listen to
            method (func): the method that received the signal
        """
        logger.info("Connect network manager to signal: {} {}".format(signal_name, method))
        interface = self._get_network_manager_interface()
        interface.connect_to_signal(
            signal_name, method
        )

    def _get_network_manager_interface(self):
        """Get network manager interface.

        Returns:
            dbus.proxies.Interface: network manager interface
        """
        logger.info("Get NetworkManager interface")
        return self.__dbus_wrapper.get_proxy_object_interface(
            self.get_network_manager_proxy_object(),
            SystemBusNMInterfaceEnum.NETWORK_MANAGER.value
        )

    def get_network_manager_proxy_object(self):
        """Get /org/freedesktop/NetworkManager proxy object.

        Returns:
            dbus.proxies.ProxyObject: network manager proxy object
        """
        logger.info("Get NetworkManager proxy object")
        return self.__get_proxy_object(SystemBusNMObjectPathEnum.NETWORK_MANAGER.value)

    def _get_all_devices(self):
        logger.info("Get all devices")
        nm_interface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.get_network_manager_proxy_object()
        )
        nm_properties = nm_interface.GetAll(
            SystemBusNMInterfaceEnum.NETWORK_MANAGER.value
        )

        return nm_properties["AllDevices"]

    def _get_available_connections_from_device(self, device):
        logger.info("Get available connections from device: {}".format(device))
        device_props_interface = self.__dbus_wrapper.get_proxy_object_properties_interface(
            self.__get_proxy_object(device)
        )
        devices_props = device_props_interface.GetAll(
            SystemBusNMInterfaceEnum.NM_DEVICE.value
        )
        return devices_props.get("AvailableConnections", [])

    def __get_proxy_object(self, path_to_object):
        return self.__dbus_wrapper.get_proxy_object(
            self.BUS_NAME,
            path_to_object
        )
