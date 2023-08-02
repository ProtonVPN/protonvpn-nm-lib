import os
import random
import time

from ...constants import (API_URL, APP_VERSION, NETZONE_METADATA_FILEPATH,
                          CACHED_SERVERLIST, CLIENT_CONFIG,
                          CONNECTION_STATE_FILEPATH,
                          LAST_CONNECTION_METADATA_FILEPATH,
                          NOTIFICATIONS_FILE_PATH, PROTON_XDG_CACHE_HOME,
                          PROTON_XDG_CACHE_HOME_LOGS,
                          PROTON_XDG_CACHE_HOME_NOTIFICATION_ICONS,
                          PROTON_XDG_CACHE_HOME_STREAMING_ICONS,
                          STREAMING_ICONS_CACHE_TIME_PATH, STREAMING_SERVICES)
from ...enums import (APIEndpointEnum, KeyringEnum, KillswitchStatusEnum,
                      NotificationEnum, NotificationStatusEnum,
                      UserSettingStatusEnum)
from ...exceptions import (API403Error, API5002Error, API5003Error,
                           API8002Error, API9001Error, API10013Error,
                           API12087Error, API85031Error, API2011Error,
                           APISessionIsNotValidError, APITimeoutError,
                           DefaultOVPNPortsNotFoundError, InsecureConnection,
                           JSONDataError, NetworkConnectionError,
                           UnknownAPIError, UnreacheableAPIError)
from ...logger import logger
from ..environment import ExecutionEnvironment


class ErrorStrategy:
    def __init__(self, func):
        self._func = func

    def __call__(self, session, *args, **kwargs):
        from proton.exceptions import (ConnectionTimeOutError,
                                       NewConnectionError, ProtonAPIError,
                                       TLSPinningError, UnknownConnectionError)
        result = None

        try:
            result = self._func(session, *args, **kwargs)
        except ProtonAPIError as e:
            logger.exception(e)
            self.__handle_api_error(e, session, *args, **kwargs)
        except ConnectionTimeOutError as e:
            logger.exception(e)
            raise APITimeoutError("Connection to API timed out")
        except NewConnectionError as e:
            logger.exception(e)
            raise UnreacheableAPIError("Unable to reach API")
        except TLSPinningError as e:
            logger.exception(e)
            raise InsecureConnection("TLS pinning failed, connection could be insecure")
        except UnknownConnectionError as e:
            logger.exception(e)
            raise UnknownAPIError("Unknown API error occurred")

        if not result:
            raise NetworkConnectionError("Unable to reach internet connectivity")

        return result

    def __get__(self, obj, objtype):
        """Support instance methods."""
        import functools
        return functools.partial(self.__call__, obj)

    def __handle_api_error(self, e, session, *args, **kwargs):
        logger.info("Handle API error")
        if hasattr(self, f'_handle_{e.code}'):
            return getattr(
                self,
                f'_handle_{e.code}')(e, session, *args, **kwargs)
        else:
            raise self._remap_protonerror(e)

    def _call_without_error_handling(self, session, *args, **kwargs):
        """Call the function, without any advanced handlers, but still remap error codes"""
        from proton.exceptions import ProtonAPIError
        try:
            return self._func(session, *args, **kwargs)
        except ProtonAPIError as e:
            raise self._remap_protonerror(e)

    def _remap_protonerror(self, e):
        raise

    def _call_with_error_remapping(self, session, *args, **kwargs):
        return self._func(session, *args, **kwargs)

    def _call_original_function(self, session, *args, **kwargs):
        return getattr(session, self.__func__.__name__)(*args, **kwargs)

    # Common handlers retries
    def _handle_429(self, error, session, *args, **kwargs):
        logger.info("Caught 429 error, retrying new request if retry header present")

        hold_request_time = error.headers.get("Retry-After")
        try:
            hold_request_time = int(hold_request_time)
        except ValueError:
            raise UnreacheableAPIError(error)

        logger.info("Retrying after {} seconds".format(hold_request_time))
        time.sleep(hold_request_time)

        # Retry
        return self._call_original_function(session, *args, **kwargs)

    def _handle_500(self, error, session, *args, **kwargs):
        logger.info("Caught 500 error, raising exception")

        raise UnreacheableAPIError(error)

    def _handle_503(self, error, session, *args, **kwargs):
        logger.info("Caught 503 error, retrying new request if retry header present")

        hold_request_time = error.headers.get("Retry-After")
        try:
            hold_request_time = int(hold_request_time)
        except ValueError:
            raise UnreacheableAPIError(error)

        logger.info("Retrying after {} seconds".format(hold_request_time))
        time.sleep(hold_request_time)

        # Retry
        return self._call_original_function(session, *args, **kwargs)

    def _handle_2011(self, error, session, *args, **kwargs):
        logger.info("Caught 9001 error, generic error message: {}".format(error))
        raise API2011Error(error)

    def _handle_9001(self, error, session, *args, **kwargs):
        logger.info("Caught 9001 error, human verification required")
        raise API9001Error(error)

    def _handle_85031(self, error, session, *args, **kwargs):
        logger.info("Caught 85031 error, too many recent login attempts")
        raise API85031Error(error)

    def _handle_12087(self, error, session, *args, **kwargs):
        logger.info("Caught 12087 error, Invalid verification token")
        raise API12087Error(error)


class ErrorStrategyLogout(ErrorStrategy):
    def _handle_401(self, error, session, *args, **kwargs):
        logger.info("Ignored a 401 at logout")
        pass


class ErrorStrategyNormalCall(ErrorStrategy):
    def _handle_401(self, error, session, *args, **kwargs):
        logger.info("Caught 401 error, will refresh session and retry")
        session.refresh()
        # Retry (without error handling this time)
        return self._call_without_error_handling(session, *args, **kwargs)

    def _handle_403(self, error, session, *args, **kwargs):
        logger.info("Caught 403 error, missing scopes. Re-authentication needed.")
        raise API403Error(error)

    def _handle_5002(self, error, session, *args, **kwargs):
        logger.info("Caught 5002 error, invalid version.")
        raise API5002Error(error)

    def _handle_5003(self, error, session, *args, **kwargs):
        logger.info("Caught 5003 error, bad version.")
        raise API5003Error(error)

    def _handle_10013(self, error, session, *args, **kwargs):
        logger.info("Caught 10013 error, session invalid.")
        raise API10013Error(error)

    def _handle_400(self, error, session, *args, **kwargs):
        logger.info("Caught 400 error, session invalid.")
        raise APISessionIsNotValidError(error)

    def _handle_422(self, error, session, *args, **kwargs):
        logger.info("Caught 422 error, session invalid.")
        raise APISessionIsNotValidError(error)


class ErrorStrategyAuthenticate(ErrorStrategy):
    def _handle_401(self, error, session, *args, **kwargs):
        logger.info("Ignored a 401 at authenticate")
        pass

    def _handle_403(self, error, session, *args, **kwargs):
        logger.info("Ignored a 403 at authenticate")
        pass

    def _handle_8002(self, error, session, *args, **kwargs):
        logger.info("Caught 8002, incorrect credentials.")
        raise API8002Error(error)


class ErrorStrategyRefresh(ErrorStrategy):
    def _handle_409(self, error, session, *args, **kwargs):
        logger.info(
            "Caught 409 error, possible race condition,"
            "retry with error handling."
        )
        return self._call_without_error_handling(session, *args, **kwargs)

    def _handle_10013(self, error, session, *args, **kwargs):
        logger.info("Caught 10013 error, session invalid.")
        raise APISessionIsNotValidError(error)

    def _handle_400(self, error, session, *args, **kwargs):
        logger.info("Caught 400 error, session invalid.")
        raise APISessionIsNotValidError(error)

    def _handle_422(self, error, session, *args, **kwargs):
        logger.info("Caught 422 error, session invalid.")
        raise APISessionIsNotValidError(error)


class APISession:
    """
    Class that represents a session in the API.

    We use three keyring entries:
    1) DEFAULT_KEYRING_PROTON_USER (username)
    2) DEFAULT_KEYRING_SESSIONDATA (session data)
    3) DEFAULT_KEYRING_USERDATA (vpn data)

    These are checked using the following logic:
    - 1) or 2) missing => destroy all entries 1) and 2) and restart.
    - There's no valid reason why 1) would be missing but not 2),
        so we don't bother with logout in that case
    - 3) missing, but 1) and 2) are valid => fetch it from API.
    - 3) present, but 1) and 2) are missing => use it, but beware that
        API calls will fail (we could connect to VPN using cached data though)

    """

    FULL_CACHE_TIME_EXPIRE = 10800  # 3h in seconds
    STREAMING_SERVICES_TIME_EXPIRE = 10800
    CLIENT_CONFIG_TIME_EXPIRE = 10800
    STREAMING_ICON_TIME_EXPIRE = 28800  # 8h in seconds
    NOTIFICATIONS_TIME_EXPIRE = 43200   # 12h in seconds
    LOADS_CACHE_TIME_EXPIRE = 900  # 15min in seconds
    RANDOM_FRACTION = 0.22  # Generate a value of the timeout, +/- up to 22%, at random
    TIMEOUT = (3.05, 3.05)

    def __init__(self, api_url=None, enforce_pinning=True):
        if api_url is None:
            self._api_url = API_URL

        self._enforce_pinning = enforce_pinning

        self.__session_create()

        self.__proton_user = None
        self.__vpn_data = None
        self.__vpn_logicals = None
        self.__clientconfig = None
        self.__streaming_services = None
        self.__streaming_icons = None
        self.__notification_data = None

        # Load session
        try:
            self.__keyring_load_session()
        # FIXME: be more precise here to show correct message to the user
        except Exception as e:
            # What is thrown here are errors for accessing/parsing the keyring.
            # print("Couldn't load session, you'll have to login again")
            logger.exception(e)

    def __session_create(self):
        from proton.api import Session
        self.__proton_api = Session(
            self._api_url,
            log_dir_path=PROTON_XDG_CACHE_HOME_LOGS,
            cache_dir_path=PROTON_XDG_CACHE_HOME,
            appversion="LinuxVPN_" + APP_VERSION,
            user_agent=ExecutionEnvironment().user_agent,
            tls_pinning=self._enforce_pinning,
            timeout=self.TIMEOUT
        )
        self.__proton_api.enable_alternative_routing = ExecutionEnvironment()\
            .settings.alternative_routing.value

    def __keyring_load_session(self):
        """
        Try to load username and session data from keyring:
        - If any of these are missing, delete the remainder from the keyring
        - if api_url doesn't match, just don't load the session
            (as it's for a different API)
        """
        try:
            keyring_data_user = ExecutionEnvironment().keyring[
                KeyringEnum.DEFAULT_KEYRING_PROTON_USER.value
            ]
        except KeyError:
            # We don't have user data, just give up
            self.__keyring_clear_session()
            return

        try:
            keyring_data = ExecutionEnvironment().keyring[
                KeyringEnum.DEFAULT_KEYRING_SESSIONDATA.value
            ]
        except KeyError:
            # No entry from keyring, just abort here
            self.__keyring_clear_session()
            return

        # also check if the API url matches the one stored on file/and or if 24h have passed
        if keyring_data.get('api_url') != self.__proton_api.dump()['api_url']:
            # Don't reuse a session with different api url
            # FIXME
            # print("Wrong session url")
            return

        # We need a username there
        if 'proton_username' not in keyring_data_user:
            raise JSONDataError("Invalid format in KEYRING_PROTON_USER")

        # Only now that we know everything is working, we will set info
        # in the class
        from proton.api import Session

        # Update the stored version with the new one and the user agent upon loading
        # from keyring
        keyring_data["appversion"] = "LinuxVPN_" + APP_VERSION
        keyring_data["User-Agent"] = ExecutionEnvironment().user_agent

        # This is a "dangerous" call, as we assume that everything
        # in keyring_data is correctly formatted
        self.__proton_api = Session.load(
            keyring_data,
            log_dir_path=PROTON_XDG_CACHE_HOME_LOGS,
            cache_dir_path=PROTON_XDG_CACHE_HOME,
            tls_pinning=self._enforce_pinning,
            timeout=self.TIMEOUT
        )
        self.__proton_api.enable_alternative_routing = ExecutionEnvironment()\
            .settings.alternative_routing.value
        self.__proton_user = keyring_data_user['proton_username']

    def __keyring_clear_session(self):
        for k in [
            KeyringEnum.DEFAULT_KEYRING_SESSIONDATA,
            KeyringEnum.DEFAULT_KEYRING_PROTON_USER
        ]:
            try:
                del ExecutionEnvironment().keyring[k.value]
            except KeyError:
                pass

    def __keyring_clear_vpn_data(self):
        try:
            del ExecutionEnvironment().keyring[
                KeyringEnum.DEFAULT_KEYRING_USERDATA.value
            ]
        except KeyError:
            pass

    def update_alternative_routing(self, newvalue):
        self.__proton_api.enable_alternative_routing = newvalue

    @ErrorStrategyLogout
    def logout(self):
        self.__keyring_clear_vpn_data()
        self.__keyring_clear_session()
        logger.info("Cleared keyring session")

        self.__proton_user = None
        self.__vpn_data = None
        self.__clientconfig = None
        self.__streaming_services = None
        self.__streaming_icons = None
        self.__notification_data = None
        logger.info("Cleared user data")

        self.__vpn_logicals = None
        logger.info("Cleared local cache variables")

        # A best effort is to logout the user via
        # the API, but if that is not possible then
        # at the least logout the user locally.
        logger.info("Attempting to logout via API")
        try:
            self.__proton_api.logout()
        except: # noqa
            logger.info("Unable to logout via API")
            pass

        logger.info("Remove cache files")
        filepaths_to_remove = [
            CACHED_SERVERLIST, CLIENT_CONFIG, NETZONE_METADATA_FILEPATH,
            LAST_CONNECTION_METADATA_FILEPATH, CONNECTION_STATE_FILEPATH,
            STREAMING_ICONS_CACHE_TIME_PATH, STREAMING_SERVICES,
            PROTON_XDG_CACHE_HOME_STREAMING_ICONS, NOTIFICATIONS_FILE_PATH,
            PROTON_XDG_CACHE_HOME_NOTIFICATION_ICONS
        ]
        for fp in filepaths_to_remove:
            self.remove_cache(fp)

        # Re-create a new
        self.__session_create()

        return True

    @ErrorStrategyRefresh
    def refresh(self):
        self.ensure_valid()

        self.__proton_api.refresh()
        # We need to store again the session data
        ExecutionEnvironment().keyring[
            KeyringEnum.DEFAULT_KEYRING_SESSIONDATA.value
        ] = self.__proton_api.dump()

        return True

    @ErrorStrategyAuthenticate
    def authenticate(self, username, password, human_verification=None):
        """Authenticate using username/password.

        This destroys the current session, if any.
        """
        # Ensure the session is clean
        try:
            self.logout()
        except: # noqa
            pass

        # (try) to log in
        if human_verification:
            self.__proton_api.human_verification_token = human_verification

        self.__proton_api.authenticate(username, password)

        # Order is important here: we first want to set keyrings,
        # then set the class status to avoid inconstistencies
        ExecutionEnvironment().keyring[
            KeyringEnum.DEFAULT_KEYRING_SESSIONDATA.value
        ] = self.__proton_api.dump()

        ExecutionEnvironment().keyring[
            KeyringEnum.DEFAULT_KEYRING_PROTON_USER.value
        ] = {"proton_username": username}

        self.__proton_user = username

        # just by calling the properties, it automatically triggers to cache the data
        _ = [
            self.servers, self.clientconfig,
            self.streaming, self.streaming_icons,
            self._vpn_data
        ]
        self.get_all_notifications()

        return True

    @property
    def is_valid(self):
        """
        Return True if the we believe a valid proton session.

        It doesn't check however if the session is working on the API though,
        so an API call might still fail.
        """
        # We use __proton_user as a proxy, since it's defined if and only if
        # we have a logged-in session in __proton_api
        return self.__proton_user is not None

    def ensure_valid(self):
        if not self.is_valid:
            raise APISessionIsNotValidError("No session")

    def remove_cache(self, cache_path):
        try:
            os.remove(cache_path)
        except IsADirectoryError:
            import shutil
            shutil.rmtree(cache_path)
        except FileNotFoundError:
            pass

    @property
    def username(self):
        # Return the proton username
        self.ensure_valid()
        return self.__proton_user

    @property
    def max_connections(self):
        try:
            return int(self._vpn_data["max_connections"])
        except KeyError:
            return 20

    @property
    def delinquent(self):
        try:
            return True if self._vpn_data["delinquent"] > 2 else False
        except KeyError:
            return False

    @ErrorStrategyNormalCall
    def get_sessions(self):
        response = self.__proton_api.api_request(APIEndpointEnum.SESSIONS.value)

        try:
            return response.get("Sessions", [])
        except AttributeError:
            return []

    def refresh_vpn_data(self):
        self.__vpn_data_fetch_from_api()

    @ErrorStrategyNormalCall
    def __vpn_data_fetch_from_api(self):
        self.ensure_valid()

        api_vpn_data = self.__proton_api.api_request('/vpn')
        self.__vpn_data = {
            'username': api_vpn_data['VPN']['Name'],
            'password': api_vpn_data['VPN']['Password'],
            'tier': api_vpn_data['VPN']['MaxTier'],
            'max_connections': api_vpn_data['VPN']['MaxConnect'],
            'delinquent': api_vpn_data['Delinquent'],
            'warnings': api_vpn_data['Warnings']
        }

        # We now have valid VPN data, store it in the keyring
        ExecutionEnvironment().keyring[
            KeyringEnum.DEFAULT_KEYRING_USERDATA.value
        ] = self.__vpn_data

        return True

    @property
    def _vpn_data(self):
        """Get the vpn information.

        This is protected: we don't want anybody trying to mess
        with the JSON directly
        """
        # We have a local cache
        if self.__vpn_data is None:
            try:
                self.__vpn_data = ExecutionEnvironment().keyring[
                    KeyringEnum.DEFAULT_KEYRING_USERDATA.value
                ]
            except KeyError:
                # We couldn't load it from the keyring,
                # but that's really not something exceptional.
                self.__vpn_data_fetch_from_api()

        return self.__vpn_data

    @property
    def vpn_username(self):
        return self._vpn_data['username']

    @property
    def vpn_password(self):
        return self._vpn_data['password']

    @property
    def vpn_tier(self):
        return self._vpn_data['tier']

    def __generate_random_component(self):
        # 1 +/- 0.22*random
        return (1 + self.RANDOM_FRACTION * (2 * random.random() - 1))

    def _update_next_fetch_logicals(self):
        self.__next_fetch_logicals = self \
            .__vpn_logicals.logicals_update_timestamp + \
            self.FULL_CACHE_TIME_EXPIRE * self.__generate_random_component()

    def _update_next_fetch_loads(self):
        self.__next_fetch_load = self \
            .__vpn_logicals.loads_update_timestamp + \
            self.LOADS_CACHE_TIME_EXPIRE * self.__generate_random_component()

    def _update_next_fetch_client_config(self):
        self.__next_fetch_client_config = self \
            .__clientconfig.client_config_timestamp + \
            self.CLIENT_CONFIG_TIME_EXPIRE * self.__generate_random_component()

    def _update_next_fetch_streaming_services(self):
        self.__next_fetch_streaming_service = self \
            .__streaming_services.streaming_services_timestamp + \
            self.STREAMING_SERVICES_TIME_EXPIRE * self.__generate_random_component()

    def _update_next_fetch_streaming_icons(self):
        self.__next_fetch_streaming_icons = self \
            .__streaming_icons.streaming_icons_timestamp + \
            self.STREAMING_ICON_TIME_EXPIRE * self.__generate_random_component()

    def _update_next_fetch_notifications(self):
        self.__next_fetch_notifications = self \
            .__notification_data.notifications_timestamp + \
            self.NOTIFICATIONS_TIME_EXPIRE * self.__generate_random_component()

    @ErrorStrategyNormalCall
    def update_servers_if_needed(self, force=False):
        changed = False

        if not self.__ensure_that_api_can_be_reached():
            return

        additional_headers = None
        netzone_address = ExecutionEnvironment().netzone.address
        if netzone_address:
            additional_headers = {"X-PM-netzone": netzone_address}

        if self.__next_fetch_logicals < time.time() or force:
            # Update logicals
            logger.info("Fetching logicals")
            self.__ensure_that_alt_routing_can_be_skipped()
            self.__vpn_logicals.update_logical_data(
                self.__proton_api.api_request(
                    APIEndpointEnum.LOGICALS.value,
                    additional_headers=additional_headers
                )
            )
            changed = True
        elif self.__next_fetch_load < time.time():
            # Update loads
            logger.info("Fetching loads")
            self.__ensure_that_alt_routing_can_be_skipped()
            self.__vpn_logicals.update_load_data(
                self.__proton_api.api_request(
                    APIEndpointEnum.LOADS.value,
                    additional_headers=additional_headers
                )
            )
            changed = True

        if changed:
            self._update_next_fetch_logicals()
            self._update_next_fetch_loads()

            try:
                with open(CACHED_SERVERLIST, "w") as f:
                    f.write(self.__vpn_logicals.json_dumps())
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info(
                    "Could not save server cache {}".format(e)
                )

        return True

    @property
    def servers(self):
        if self.__vpn_logicals is None:
            from ..servers import ServerList

            # Create a new server list
            self.__vpn_logicals = ServerList()

            # Try to load from file
            try:
                with open(CACHED_SERVERLIST, "r") as f:
                    self.__vpn_logicals.json_loads(f.read())
            except FileNotFoundError:
                # This is not fatal,
                # we only were not capable of loading the cache.
                logger.info("Could not load server cache")

            self._update_next_fetch_logicals()
            self._update_next_fetch_loads()

        try:
            self.update_servers_if_needed()
        except APISessionIsNotValidError:
            raise
        except: # noqa
            pass

        # self.streaming
        return self.__vpn_logicals

    @ErrorStrategyNormalCall
    def update_client_config_if_needed(self, force=False):
        changed = False

        if not self.__ensure_that_api_can_be_reached():
            return

        if self.__next_fetch_client_config < time.time() or force:
            # Update client config
            logger.info("Fetching client config")
            self.__ensure_that_alt_routing_can_be_skipped()
            self.__clientconfig.update_client_config_data(
                self.__proton_api.api_request(APIEndpointEnum.CLIENT_CONFIG.value)
            )
            changed = True

        if changed:
            self._update_next_fetch_client_config()
            try:
                with open(CLIENT_CONFIG, "w") as f:
                    f.write(self.__clientconfig.json_dumps())
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info("Could not save client config cache {}".format(
                    e
                ))

            # Should try to fetch every +-3h, with an interval of +-12h
            # This ensure that if the previous fetch failed,
            # the client won't have to wait again 12h for retry but rather try again later
            try:
                self._notifications
            except: # noqa
                pass

        return True

    @property
    def clientconfig(self):
        if self.__clientconfig is None:
            from ..client_config import ClientConfig

            # Create a new client config
            self.__clientconfig = ClientConfig()

            # Try to load from file
            try:
                with open(CLIENT_CONFIG, "r") as f:
                    self.__clientconfig.json_loads(f.read())
            except FileNotFoundError:
                # This is not fatal,
                # we only were not capable of loading the cache.
                logger.info("Could not load client config cache")

            self._update_next_fetch_client_config()

        try:
            self.update_client_config_if_needed()
        except: # noqa
            pass

        return self.__clientconfig

    @ErrorStrategyNormalCall
    def update_streaming_data_if_needed(self, force=False):
        changed = False

        if not self.__ensure_that_api_can_be_reached():
            return

        if self.__next_fetch_streaming_service < time.time() or force:
            # Update streaming services
            logger.info("Fetching streaming data")
            self.__ensure_that_alt_routing_can_be_skipped()
            self.__streaming_services.update_streaming_services_data(
                self.__proton_api.api_request(APIEndpointEnum.STREAMING_SERVICES.value)
            )
            changed = True

        if changed:
            self._update_next_fetch_streaming_services()
            try:
                with open(STREAMING_SERVICES, "w") as f:
                    f.write(self.__streaming_services.json_dumps())
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info("Could not save streaming services cache {}".format(
                    e
                ))

        return True

    @property
    def streaming(self):
        if self.__streaming_services is None:
            from ..streaming import Streaming

            # create new Streaming object
            self.__streaming_services = Streaming()

            # Try to load from file
            try:
                with open(STREAMING_SERVICES, "r") as f:
                    self.__streaming_services.json_loads(f.read())
            except FileNotFoundError:
                # This is not fatal,
                # we only were not capable of loading the cache.
                logger.info("Could not load streaming cache")

            self._update_next_fetch_streaming_services()

        try:
            self.update_streaming_data_if_needed()
        except: # noqa
            pass

        self.streaming_icons

        return self.__streaming_services

    def update_streaming_icons_if_needed(self, force=False):
        if not self.__ensure_that_api_can_be_reached():
            return

        if self.__next_fetch_streaming_icons < time.time() or force:
            logger.info("Fetching streaming icons")
            self.__ensure_that_alt_routing_can_be_skipped()
            self.__streaming_icons.update_streaming_icons_data(self.__streaming_services)

            self._update_next_fetch_streaming_icons()
            try:
                with open(STREAMING_ICONS_CACHE_TIME_PATH, "w") as f:
                    f.write(self.__streaming_icons.json_dumps())
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info("Could not save streaming services cache {}".format(
                    e
                ))

    @property
    def _notifications(self):
        if self.__notification_data is None:
            from ..notification import NotificationData

            self.__notification_data = NotificationData()

            try:
                with open(NOTIFICATIONS_FILE_PATH, "r") as f:
                    self.__notification_data.json_loads(f.read())
            except FileNotFoundError:
                logger.info("Could not load notifications cache")

            self._update_next_fetch_notifications()

        try:
            self._update_notifications_if_needed()
        except APISessionIsNotValidError:
            raise
        except: # noqa
            pass

        return self.__notification_data

    @ErrorStrategyNormalCall
    def _update_notifications_if_needed(self, force=False):
        changed = False

        if not self.__ensure_that_api_can_be_reached() and not self.clientconfig.poll_notification_api: # noqa
            return

        if self.__next_fetch_notifications < time.time() or force:
            logger.info("Fetching new notifications")
            self.__notification_data.update_notifications_data(
                self.__proton_api.api_request(APIEndpointEnum.NOTIFICATIONS.value)
            )
            changed = True

        if changed:
            self._update_next_fetch_notifications()
            try:
                with open(NOTIFICATIONS_FILE_PATH, "w") as f:
                    f.write(self.__notification_data.json_dumps())
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info("Could not save streaming services cache {}".format(
                    e
                ))

            # Cache icons for notifications
            self.get_all_notifications()

            return True

    def get_all_notifications(self):
        return self._update_notification_status(
            self._notifications.get_all_notifications()
        )

    def get_notifications_by_type(self, notification_type):
        """Get specific notification object

        Args:
            notification_type (NotificationEnum)

        Returns:
            BaseNotification instance
        """
        if not isinstance(notification_type, str):
            notification_type = notification_type.value

        return self._update_notification_status(
            self._notifications.get_notification(notification_type)
        )

    def _update_notification_status(self, notification):
        event_notification = ExecutionEnvironment().settings.event_notification

        # If only one is available then it means that it's the empty one
        if not isinstance(notification, list) and notification.notification_type == NotificationEnum.EMPTY.value: # noqa
            if  event_notification != NotificationStatusEnum.UNKNOWN: # noqa
                ExecutionEnvironment().settings.event_notification = NotificationStatusEnum.UNKNOWN # noqa

            return notification

        # If the notification status is unknown, then it means that it is the first time
        # that this notifications is being loaded, and thus the status
        # should be changed to not opened so that clients have a notification element
        if event_notification == NotificationStatusEnum.UNKNOWN:
            ExecutionEnvironment().settings.event_notification = NotificationStatusEnum.NOT_OPENED # noqa

        return notification

    @ErrorStrategyNormalCall
    def get_location_data(self):
        self.__ensure_that_alt_routing_can_be_skipped()
        try:
            response = self.__proton_api.api_request(APIEndpointEnum.LOCATION.value)
        except (APITimeoutError, UnreacheableAPIError, UnknownAPIError) as e:
            logger.info("Unable to fetch new ip: {}".format(e))
            response = {}
        except: # noqa
            logger.info("Unknown error occurred. Either there is no connection or API is blocked.")
            response = {}

        from ..location import CurrentLocation
        return CurrentLocation(response)

    def __ensure_that_api_can_be_reached(self):
        if (
            (
                ExecutionEnvironment().settings.killswitch == KillswitchStatusEnum.HARD
                and ExecutionEnvironment().connection_backend.get_active_protonvpn_connection()
            ) or ExecutionEnvironment().settings.killswitch != KillswitchStatusEnum.HARD
        ):
            return True

        return False

    def __ensure_that_alt_routing_can_be_skipped(self):
        """Check if alternative routing can be skipped.

        This method should be called before making API calls.
        This is mainly for the purpose of alternative routing, since if a VPN
        connection is active, there is no reason to use alt routes and not directly
        the original API.
        """
        logger.info("Ensure that alternative routing can be skipped")
        if ExecutionEnvironment().settings.alternative_routing != UserSettingStatusEnum.ENABLED:
            logger.info("Alternative routing is disabled.")
            self.__proton_api.force_skip_alternative_routing = False
            return

        try:
            active_connection = ExecutionEnvironment()\
                .connection_backend.get_active_protonvpn_connection()
        except: # noqa
            active_connection = None
            logger.info(
                "Error occurred while trying to fetch VPN connection."
            )

        if not active_connection:
            logger.info(
                "Active Proton VPN connection could not be found. "
                "Switiching to alternative routing."
            )

            self.__proton_api.force_skip_alternative_routing = False
            return

        logger.info(
            "Active Proton VPN connection found. "
            "Force skipping alternative routing."
        )
        self.__proton_api.force_skip_alternative_routing = True

    @property
    def captcha_url(self):
        return self.__proton_api.captcha_url

    @property
    def streaming_icons(self):
        if self.__streaming_icons is None:
            from ..streaming import StreamingIcons

            # create new StreamingIcon object
            self.__streaming_icons = StreamingIcons()
            try:
                with open(STREAMING_ICONS_CACHE_TIME_PATH, "r") as f:
                    self.__streaming_icons.json_loads(f.read())
            except FileNotFoundError:
                # This is not fatal,
                # we only were not capable of loading the cache.
                logger.info("Could not load streaming time cache")

            self._update_next_fetch_streaming_icons()

        try:
            self.update_streaming_icons_if_needed()
        except: # noqa
            pass

        return self.__streaming_icons

    @property
    def vpn_ports_openvpn_udp(self):
        try:
            return self.clientconfig.default_udp_ports
        except (TypeError, KeyError) as e:
            logger.exception(e)
            raise DefaultOVPNPortsNotFoundError(
                "Default OVPN (UDP) ports could not be found"
            )

    @property
    def vpn_ports_openvpn_tcp(self):
        try:
            return self.clientconfig.default_tcp_ports
        except (TypeError, KeyError) as e:
            logger.exception(e)
            raise DefaultOVPNPortsNotFoundError(
                "Default OVPN (TCP) ports could not be found"
            )
