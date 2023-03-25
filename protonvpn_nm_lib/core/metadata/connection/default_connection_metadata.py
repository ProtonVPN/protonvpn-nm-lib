
import json
import os
import time

from .... import exceptions
from ....constants import (CACHE_METADATA_FILEPATH, CONNECTION_STATE_FILEPATH,
                           LAST_CONNECTION_METADATA_FILEPATH)
from ....enums import (ConnectionMetadataEnum, LastConnectionMetadataEnum,
                       MetadataActionEnum, MetadataEnum)
from ....logger import logger
from .connection_metadata_backend import ConnectionMetadataBackend


class ConnectionMetadata(ConnectionMetadataBackend):
    """
    Read/Write connection metadata. Stores
    metadata about the current connection
    for displaying connection status and also
    stores for metadata for future reconnections.
    """
    connection_metadata = "default"
    METADATA_DICT = {
        MetadataEnum.CONNECTION: CONNECTION_STATE_FILEPATH,
        MetadataEnum.LAST_CONNECTION: LAST_CONNECTION_METADATA_FILEPATH,
        MetadataEnum.SERVER_CACHE: CACHE_METADATA_FILEPATH
    }

    def __init__(self):
        pass

    def save_servername(self, servername):
        """Save connected servername metadata.

        Args:
            servername (string): servername [PT#1]
        """
        last_metadata = self.get_connection_metadata(
            MetadataEnum.LAST_CONNECTION
        )
        real_metadata = self.get_connection_metadata(
            MetadataEnum.CONNECTION
        )

        real_metadata[ConnectionMetadataEnum.SERVER.value] = servername
        last_metadata[ConnectionMetadataEnum.SERVER.value] = servername

        logger.info("Saving servername \"{}\" on \"{}\"".format(
            servername, MetadataEnum.CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.CONNECTION, real_metadata
        )

        logger.info("Saving servername \"{}\" on \"{}\"".format(
            servername, MetadataEnum.LAST_CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.LAST_CONNECTION, last_metadata
        )

    def save_connect_time(self):
        """Save connected time metadata."""
        metadata = self.get_connection_metadata(MetadataEnum.CONNECTION)
        metadata[ConnectionMetadataEnum.CONNECTED_TIME.value] = str(
            int(time.time())
        )
        self.__write_connection_metadata(MetadataEnum.CONNECTION, metadata)
        logger.info("Saved connected time to file")

    def save_protocol(self, protocol):
        """Save connected protocol.

        Args:
            protocol (ProtocolEnum): TCP|UDP etc
        """
        real_metadata = self.get_connection_metadata(MetadataEnum.CONNECTION)
        last_metadata = self.get_connection_metadata(
            MetadataEnum.LAST_CONNECTION
        )
        real_metadata[ConnectionMetadataEnum.PROTOCOL.value] = protocol.value
        last_metadata[LastConnectionMetadataEnum.PROTOCOL.value] = protocol.value # noqa

        logger.info("Saving protocol \"{}\" on \"{}\"".format(
            protocol, MetadataEnum.CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.CONNECTION, real_metadata
        )

        logger.info("Saving protocol \"{}\" on \"{}\"".format(
            protocol, MetadataEnum.LAST_CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.LAST_CONNECTION, last_metadata
        )
        logger.info("Saved protocol to file")

    def save_display_server_ip(self, ip):
        real_metadata = self.get_connection_metadata(MetadataEnum.CONNECTION)
        real_metadata[ConnectionMetadataEnum.DISPLAY_SERVER_IP.value] = ip

        logger.info("Saving exit server IP \"{}\" on \"{}\"".format(
            ip, MetadataEnum.CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.CONNECTION, real_metadata
        )

        logger.info("Saved exit ip to file")

    def save_server_ip(self, ip):
        """Save connected server IP.

        Args:
            IP (string): server IP
        """
        last_metadata = self.get_connection_metadata(
            MetadataEnum.LAST_CONNECTION
        )
        last_metadata[LastConnectionMetadataEnum.SERVER_IP.value] = ip
        logger.info("Saving server ip \"{}\" on \"{}\"".format(
            ip, MetadataEnum.LAST_CONNECTION
        ))
        self.__write_connection_metadata(
            MetadataEnum.LAST_CONNECTION, last_metadata
        )
        logger.info("Saved server IP to file")

    def get_server_ip(self):
        """Get server IP.

        Returns:
            list: contains server IPs
        """
        logger.info("Getting server IP")
        return self.get_connection_metadata(
            MetadataEnum.LAST_CONNECTION
        )[LastConnectionMetadataEnum.SERVER_IP.value]

    def get_connection_metadata(self, metadata_type):
        """Get connection state metadata.

        Args:
            metadata_type (MetadataEnum): type of metadata to save

        Returns:
            dict: connection metadata
        """
        try:
            return self.manage_metadata(
                MetadataActionEnum.GET, metadata_type
            )
        except FileNotFoundError:
            return {}

    def __write_connection_metadata(self, metadata_type, metadata):
        """Save metadata to file.

        Args:
            metadata_type (MetadataEnum): type of metadata to save
            metadata (dict): metadata content
        """
        self.manage_metadata(
            MetadataActionEnum.WRITE,
            metadata_type,
            metadata
        )

    def remove_all_metadata(self):
        """Remove all metadata connection files."""
        self.manage_metadata(
            MetadataActionEnum.REMOVE,
            MetadataEnum.CONNECTION
        )
        self.manage_metadata(
            MetadataActionEnum.REMOVE,
            MetadataEnum.LAST_CONNECTION
        )

    def remove_connection_metadata(self, metadata_type):
        """Remove metadata file.

        Args:
            metadata_type (MetadataEnum): type of metadata to save
        """
        self.manage_metadata(
            MetadataActionEnum.REMOVE,
            metadata_type
        )

    def manage_metadata(self, action, metadata_type, metadata=None):
        """Metadata manager."""
        logger.debug(
            "Metadata manager \"action: {} - Metadata type: {}\"".format(
                action,
                metadata_type
            )
        )
        metadata_action_dict = {
            MetadataActionEnum.GET: self.get_metadata_from_file,
            MetadataActionEnum.WRITE: self.write_metadata_to_file,
            MetadataActionEnum.REMOVE: self.remove_metadata_file
        }

        if action not in metadata_action_dict:
            raise exceptions.IllegalMetadataActionError(
                "Illegal {} metadata action".format(action)
            )

        self.ensure_metadata_type_is_valid(metadata_type)

        metadata_from_file = metadata_action_dict[action](
            metadata_type, metadata
        )
        return metadata_from_file

    def get_metadata_from_file(self, metadata_type, _):
        """Get state metadata.

        Returns:
            json/dict
        """
        logger.debug("Getting metadata from \"{}\"".format(metadata_type))
        with open(self.METADATA_DICT[metadata_type]) as f:
            metadata = json.load(f)
            logger.debug("Successfully fetched metadata from file")
            return metadata

    def write_metadata_to_file(self, metadata_type, metadata):
        """Save metadata to file."""
        with open(self.METADATA_DICT[metadata_type], "w") as f:
            json.dump(metadata, f)
            logger.debug(
                "Successfully saved metadata to \"{}\"".format(metadata_type)
            )

    def remove_metadata_file(self, metadata_type, _):
        """Remove metadata file."""
        filepath = self.METADATA_DICT[metadata_type]

        if os.path.isfile(filepath):
            os.remove(filepath)

    def ensure_metadata_type_is_valid(self, metadata_type):
        """Check metedata type."""
        logger.debug("Checking if {} is valid".format(metadata_type))
        if metadata_type not in self.METADATA_DICT:
            raise exceptions.IllegalMetadataTypeError(
                "Metadata type not found"
            )
        logger.debug("\"{}\" is valid metadata type".format(metadata_type))

    def check_metadata_exists(self, metadata_type):
        """Check if metadata file exists."""
        logger.debug("Checking if \"{}\" exists".format(metadata_type))
        self.ensure_metadata_type_is_valid(metadata_type)

        metadata_exists = False
        if os.path.isfile(self.METADATA_DICT[metadata_type]):
            metadata_exists = True

        logger.debug(
            "Metadata \"{}\" \"{}\"".format(
                metadata_type,
                ("exists" if metadata_exists else "does not exist")
            )
        )
        return metadata_exists
