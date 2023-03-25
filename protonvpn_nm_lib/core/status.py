from ..enums import (ConnectionMetadataEnum, ConnectionStatusEnum,
                     KillSwitchInterfaceTrackerEnum, KillswitchStatusEnum,
                     MetadataEnum, ProtocolEnum)
from .environment import ExecutionEnvironment


class Status:
    """Status Class.
    Use it to get status information about the current
    Proton VPN connection.
    """
    def __init__(self):
        self.user_settings = ExecutionEnvironment().settings
        self.server_list = ExecutionEnvironment().api_session.servers
        self.killswitch_obj = ExecutionEnvironment().killswitch
        self.connection_metadata = ExecutionEnvironment().connection_metadata

    def get_active_connection_status(self):
        """Get active connection status.

        Args:
            readable_format (bool):
                If true then all content will be returned in
                human readable format, else all content is returned in
                enum objects.

        Returns:
            dict:
                Keys: ConnectionStatusEnum
        """
        connection_information = self.connection_metadata\
            .get_connection_metadata(
                MetadataEnum.CONNECTION
            )
        servername = connection_information[
            ConnectionMetadataEnum.SERVER.value
        ]
        protocol = connection_information[
            ConnectionMetadataEnum.PROTOCOL.value
        ]
        connected_time = connection_information[
            ConnectionMetadataEnum.CONNECTED_TIME.value
        ]

        try:
            exit_server_ip = connection_information[
                ConnectionMetadataEnum.DISPLAY_SERVER_IP.value
            ] # noqa
        except KeyError:
            exit_server_ip = None

        server = self.server_list.filter(
            lambda server: server.name.lower() == servername.lower()
        ).get_fastest_server()

        self.killswitch_obj.update_connection_status()

        ks_status = KillswitchStatusEnum.HARD
        if (
            not self.killswitch_obj.interface_state_tracker[self.killswitch_obj.ks_conn_name][ # noqa
                KillSwitchInterfaceTrackerEnum.IS_RUNNING
            ] and self.user_settings.killswitch != KillswitchStatusEnum.DISABLED # noqa
        ):
            # if DISABLED then KS is currently not running,
            # otherwise it's ENABLED
            ks_status = KillswitchStatusEnum.DISABLED

        raw_dict = {
            ConnectionStatusEnum.SERVER_INFORMATION: server,
            ConnectionStatusEnum.PROTOCOL: ProtocolEnum(protocol),
            ConnectionStatusEnum.KILLSWITCH: ks_status,
            ConnectionStatusEnum.TIME: connected_time,
            ConnectionStatusEnum.NETSHIELD: self.user_settings.netshield, # noqa
            ConnectionStatusEnum.SERVER_IP: exit_server_ip,
        }

        return raw_dict
