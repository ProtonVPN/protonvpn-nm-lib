class ProtonVPNException(BaseException):
    def __init__(self, message, additional_info=None):
        self.message = message
        self.additional_context = additional_info
        super(ProtonVPNException, self).__init__(self.message)


class AccountingError(ProtonVPNException):
    """Base accounting exception/error."""


class AccountIsDelinquentError(AccountingError):
    """Account is delinquent (user has unpaid invoices)."""


class AccountWasDowngradedError(AccountingError):
    """Account was downgraded."""


class VPNUsernameOrPasswordHasBeenChangedError(AccountingError):
    """Account username or password has been changed."""


class AccountPasswordHasBeenCompromisedError(AccountingError):
    """Account password has been compromised."""


class ExceededAmountOfConcurrentSessionsError(AccountingError):
    """Account has exceeded the maximum amount of concurrent sessions."""


class APISessionIsNotValidError(ProtonVPNException):
    """
    This exception is raised when a call requires a valid Proton API session,
    but we currently don't have one. This can be solved by doing a new login.
    """


class JSONError(ProtonVPNException): # noqa
    """JSON generated errors"""


class JSONDataEmptyError(JSONError):
    """JSON SessionData empty error"""


class JSONDataNoneError(JSONError):
    """JSON SessionData none error"""


class JSONDataError(JSONError):
    """JSON SessionData error"""




class CacheError(ProtonVPNException): # noqa
    """Cache error base exception"""


class ServerCacheNotFound(CacheError):
    """Server cache was not found."""


class DefaultOVPNPortsNotFoundError(CacheError):
    """Default OpenVPN ports not found.
    Either cache is missing or unable to fetch from API.
    """




class KeyringError(ProtonVPNException):  # noqa
    """Keyring error"""


class AccessKeyringError(KeyringError):
    """Access keyring error."""


class KeyringDataNotFound(KeyringError): # noqa
    """Keyring data not found"""


class UserSessionNotFound(KeyringError):
    """User session not found."""




class IPv6LeakProtectionError(ProtonVPNException): # noqa
    """IPv6 leak protection error."""


class IPv6LeakProtectionOptionError(IPv6LeakProtectionError):
    """IPv6 leak protection option error."""


class EnableIPv6LeakProtectionError(IPv6LeakProtectionError):
    """IPv6 leak protection subprocess add error."""


class DisableIPv6LeakProtectionError(IPv6LeakProtectionError):
    """IPv6 leak protection subprocess delete error."""




class ProtonSessionWrapperError(ProtonVPNException): # noqa
    """Proton session wrapper error."""


class API400Error(ProtonSessionWrapperError):
    """Error 400.

    Upon refreshing tokens, wwhen a request is badly formatted this exception
    is raised. Usually requires a user to re-login.
    """


class API401Error(ProtonSessionWrapperError):
    """Error 401.

    Access token is invalid and should be refreshed.
    """


class API403Error(ProtonSessionWrapperError):
    """Error 403.

    Missing scopes. Client needs to re-authenticate.
    """


class API422Error(ProtonSessionWrapperError):
    """Error 422.

    Upon refreshing tokens, this exception is raised
    session has experied and re-login is required.
    """


class API429Error(ProtonSessionWrapperError):
    """Error 429.

    Too many requests, try after time specified
    in header.
    """


class API503Error(ProtonSessionWrapperError):
    """Error 503.

    API unreacheable/unavailable, retry connecting to API.
    """


class API2011Error(ProtonSessionWrapperError):
    """Error 2011.

    Generic API error.
    """


class API5002Error(ProtonSessionWrapperError):
    """Error 5002.

    Version is invalid.
    """


class API5003Error(ProtonSessionWrapperError):
    """Error 5003.

    Version is bad.
    """


class API8002Error(ProtonSessionWrapperError):
    """Error 8002.

    Incorrect login credentials.
    """


class API12087Error(ProtonSessionWrapperError):
    """Error12087.

    Invalid verification token.
    """


class API85031Error(ProtonSessionWrapperError):
    """Error 85031.

    Too many recent login attempts.
    """


class API9001Error(ProtonSessionWrapperError):
    """Error 9001.

    Human verification required.
    (Usually done via captcha)
    """


class API10013Error(ProtonSessionWrapperError):
    """Error 10013.

    Refresh token is invalid, re-authentication is required.
    """


class APITimeoutError(ProtonSessionWrapperError):
    """API timeout error."""


class APIError(ProtonSessionWrapperError):
    """API error."""


class UnknownAPIError(ProtonSessionWrapperError):
    """Unknown API error."""


class UnreacheableAPIError(ProtonSessionWrapperError):
    """APIBlockError"""


class NetworkConnectionError(ProtonSessionWrapperError):
    """Network connection error"""


class InsecureConnection(ProtonSessionWrapperError):
    """Insecure connection. Triggered when pinned fingerprint does not match."""




class KillswitchError(ProtonVPNException): # noqa
    """Killswitch error."""


class CreateKillswitchError(KillswitchError):
    """Create killswitch error"""


class CreateRoutedKillswitchError(CreateKillswitchError):
    """Create routed killswitch error"""


class CreateBlockingKillswitchError(CreateKillswitchError):
    """Create routed killswitch error"""


class DeleteKillswitchError(KillswitchError):
    """Delete killswitch error."""


class ActivateKillswitchError(KillswitchError):
    """Activate killswitch error."""


class DectivateKillswitchError(KillswitchError):
    """Deactivate killswitch error."""


class AvailableConnectivityCheckError(KillswitchError):
    """Available connectivity check error."""


class DisableConnectivityCheckError(KillswitchError):
    """Disable connectivity check error."""




class MetadataError(ProtonVPNException): # noqa
    """Metadata error."""


class IllegalMetadataActionError(MetadataError):
    """Illegal/unexpected metadata action error."""


class IllegalMetadataTypeError(MetadataError):
    """Illegal/unexpected metadata type error."""




class AddConnectionCredentialsError(ProtonVPNException): # noqa
    """Add credentials to connection error."""


class AddServerCertificateCheckError(ProtonVPNException):
    """Add server certificate check error"""


class VirtualDeviceNotFound(ProtonVPNException):
    """Virtual device could not be found."""


class IllegalVirtualDevice(ProtonVPNException):
    """Unexpeced virtual device."""


class IllegalVPNProtocol(ProtonVPNException):
    """Unexpected plugin for specified protocol."""


class ProtocolPluginNotFound(ProtonVPNException):
    """Plugin for specified protocol was not found."""


class ConnectionNotFound(ProtonVPNException):
    """Proton VPN connection not found."""


class UnexpectedServername(ProtonVPNException):
    """Unexpected servername."""




class ServerListError(ProtonVPNException): # noqa
    """Server list error."""


class EmptyServerListError(ServerListError):
    """Empty server list error."""


class FastestServerNotFound(EmptyServerListError):
    """Fastest server not found."""


class FastestServerInCountryNotFound(EmptyServerListError):
    """Fastest server in specified country not found."""


class FeatureServerNotFound(EmptyServerListError):
    """Server with specified feature was not found."""


class ServernameServerNotFound(EmptyServerListError):
    """Server with specified servername not found."""


class RandomServerNotFound(EmptyServerListError):
    """Random server not found."""
