from .utils import Singleton


class ExecutionEnvironment(metaclass=Singleton):
    """This class hold all the system environment based elements.

    The goal is to abstract all differences between system and
    isolate them in one point.

    This is a singleton.
    """

    def __init__(self):
        self.__keyring = None
        self.__api_session = None

        self.__connection_backend = None
        self.__killswitch = None
        self.__ipv6leak = None

        self.__settings = None
        self.__connection_metadata = None
        self.__api_metadata = None
        self.__accounting = None
        self.__netzone = None

    @property
    def keyring(self):
        """Return the keyring to use"""
        if self.__keyring is None:
            from .keyring import KeyringBackend
            self.__keyring = KeyringBackend.get_default()
        return self.__keyring

    @keyring.setter
    def keyring(self, newvalue):
        self.__keyring = newvalue

    @property
    def connection_backend(self):
        """Return the connection backend to use (nm, etc.)"""
        if self.__connection_backend is None:
            from .connection_backend import ConnectionBackend
            self.__connection_backend = ConnectionBackend.get_backend()
        return self.__connection_backend

    @connection_backend.setter
    def connection_backend(self, newvalue):
        self.__connection_backend = newvalue

    @property
    def api_session(self):
        """Return the session to the API"""
        if self.__api_session is None:
            from .session import APISession
            self.__api_session = APISession()
        return self.__api_session

    @api_session.setter
    def api_session(self, newvalue):
        self.__api_session = newvalue

    @property
    def killswitch(self):
        """Return the session to the API"""
        if self.__killswitch is None:
            from .killswitch import KillSwitch
            self.__killswitch = KillSwitch()
        return self.__killswitch

    @killswitch.setter
    def killswitch(self, newvalue):
        self.__killswitch = newvalue

    @property
    def ipv6leak(self):
        """Return the session to the API"""
        if self.__ipv6leak is None:
            from .killswitch import IPv6LeakProtection
            self.__ipv6leak = IPv6LeakProtection()
        return self.__ipv6leak

    @ipv6leak.setter
    def ipv6leak(self, newvalue):
        self.__ipv6leak = newvalue

    @property
    def settings(self):
        """Return the session to the API"""
        if self.__settings is None:
            from .user_settings import SettingsBackend
            self.__settings = SettingsBackend.get_backend()
        return self.__settings

    @settings.setter
    def settings(self, newvalue):
        self.__settings = newvalue

    @property
    def connection_metadata(self):
        """Return the session to the API"""
        if self.__connection_metadata is None:
            from .metadata import ConnectionMetadataBackend
            self.__connection_metadata = ConnectionMetadataBackend.get_backend() # noqa
        return self.__connection_metadata

    @connection_metadata.setter
    def connection_metadata(self, newvalue):
        self.__connection_metadata = newvalue

    @property
    def netzone(self):
        """Return the session to the API"""
        if self.__netzone is None:
            from .metadata import NetzoneMetadataBackend
            self.__netzone = NetzoneMetadataBackend.get_backend() # noqa
        return self.__netzone

    @netzone.setter
    def netzone(self, newvalue):
        self.__netzone = newvalue

    @property
    def accounting(self):
        """Return the session to the API"""
        if self.__accounting is None:
            from .accounting import Accounting
            self.__accounting = Accounting.get_backend() # noqa
        return self.__accounting

    @accounting.setter
    def accounting(self, newvalue):
        self.__accounting = newvalue


    @property
    def user_agent(self):
        from ..constants import APP_VERSION
        """Get user agent to use when communicating with API

        Returns:
            string: User-Agent
        """
        try:
            import distro
            distribution, version, _ = distro.linux_distribution()
        except ImportError:
            distribution, version, _ = "Linux", "unknown version", "unknown codename"

        return "ProtonVPN/{} (Linux; {}/{})".format(APP_VERSION, distribution, version)
