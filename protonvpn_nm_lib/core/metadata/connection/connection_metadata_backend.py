from abc import ABCMeta, abstractmethod
from ...utils import SubclassesMixin
from ....logger import logger


class ConnectionMetadataBackend(SubclassesMixin, metaclass=ABCMeta):

    @classmethod
    def get_backend(cls, connection_metadata_backend="default"):
        subclasses_dict = cls._get_subclasses_dict("connection_metadata")
        if connection_metadata_backend not in subclasses_dict:
            raise NotImplementedError(
                "Connection Metadata Backend not implemented"
            )
        logger.info("Connection metadata backend: {}".format(
            subclasses_dict[connection_metadata_backend]
        ))

        return subclasses_dict[connection_metadata_backend]()

    @abstractmethod
    def save_servername():
        """Save servername metadata."""

    @abstractmethod
    def save_connect_time():
        """Save connected time metadata."""

    @abstractmethod
    def save_protocol():
        """Save connected protocol."""
        pass

    @abstractmethod
    def save_display_server_ip():
        """Save IP that that is to be displayed."""
        pass

    @abstractmethod
    def save_server_ip():
        """Save server IP to which connection is made."""
        pass

    @abstractmethod
    def get_server_ip():
        """Get server IP to which connection is made."""
        pass

    @abstractmethod
    def get_connection_metadata():
        """Get state metadata."""

    @abstractmethod
    def remove_all_metadata():
        """Remove all metadata."""
