import json
from ...logger import logger
from ...enums import KeyringEnum
from ... import exceptions
from ._base import KeyringBackend
import os


class KeyringBackendLinux(KeyringBackend):
    def __init__(self, keyring_backend):
        self.__keyring_backend = keyring_backend
        self.__keyring_service = KeyringEnum.DEFAULT_KEYRING_SERVICE.value

    def __getitem__(self, key):
        logger.info("Get key {}".format(key))
        import keyring

        self._ensure_key_is_valid(key)

        try:
            stored_data = self.__keyring_backend.get_password(
                self.__keyring_service,
                key
            )
        except (keyring.errors.InitError) as e:
            logger.exception("AccessKeyringError: {}".format(e))
            raise exceptions.AccessKeyringError(
                "Could not fetch from keychain: {}".format(e)
            )
        except (Exception, keyring.errors.KeyringError) as e:
            logger.exception("KeyringError: {}".format(e))
            raise exceptions.KeyringError(e)

        # Since we're borrowing the dict interface,
        # be consistent and throw a KeyError if it doesn't exist
        if stored_data is None:
            raise KeyError(key)

        try:
            return json.loads(stored_data)
        except json.decoder.JSONDecodeError as e:
            logger.exception(e)
            raise exceptions.JSONDataEmptyError(e)
        except TypeError as e:
            logger.exception(e)
            raise exceptions.JSONDataNoneError(e)
        except Exception as e:
            logger.exception(e)
            raise exceptions.JSONDataError(e)

    def __delitem__(self, key):
        logger.info("Delete key {}".format(key))
        import keyring

        self._ensure_key_is_valid(key)

        try:
            self.__keyring_backend.delete_password(self.__keyring_service, key)
        except (
                keyring.errors.InitError
        ) as e:
            logger.exception("AccessKeyringError: {}".format(e))
            raise exceptions.AccessKeyringError(
                "Could not access keychain: {}".format(e)
            )
        except keyring.errors.PasswordDeleteError as e:
            logger.exception("KeyringDataNotFound: {}".format(e))
            raise KeyError(key)
        except (Exception, keyring.errors.KeyringError) as e:
            logger.exception("Unknown exception: {}".format(e))
            # We shouldn't ignore exceptions!
            raise exceptions.KeyringError(e)
            # capture_exception(e)

    def __setitem__(self, key, value):
        logger.info("Set key {}".format(key))
        """Add data entry to keyring.

        Args:
            data (dict(json)): data to be stored
            keyring_username (string): the keyring username
            keyring_service (string): the keyring servicename
        """

        import keyring

        self._ensure_key_is_valid(key)
        self._ensure_value_is_valid(value)

        json_data = json.dumps(value)
        try:
            self.__keyring_backend.set_password(
                self.__keyring_service,
                key,
                json_data
            )
        except (
            keyring.errors.InitError,
            keyring.errors.PasswordSetError
        ) as e:
            logger.exception("AccessKeyringError: {}".format(e))
            raise exceptions.AccessKeyringError(
                "Could not access keychain: {}".format(e)
            )
        except (Exception, keyring.errors.KeyringError) as e:
            logger.error("Exception: {}".format(e))
            raise exceptions.KeyringError(e)

    def _ensure_backend_is_working(self):
        """Ensure that a backend is working properly.

        It can happen so that a backend is installed but it might be
        missonfigured. But adding this test, we can asses if the backend
        is working correctly or not. If not then another backend should be tried instead.

        keyring.errors.InitError will be thrown if the backend system can not be initialized,
        indicating that possibly it might be misconfigured.
        """
        import keyring
        try:
            self.__keyring_backend.get_password(
                self.__keyring_service,
                "TestingThatBackendIsWorking"
            )
        except (keyring.errors.InitError) as e:
            logger.debug(e)
            logger.exception("Unable to select {} backend".format(self.__keyring_backend))
            raise exceptions.AccessKeyringError(
                "Unable to select {} backend".format(self.__keyring_backend)
            )
        except: # noqa
            pass


class KeyringBackendLinuxKwallet(KeyringBackendLinux):
    priority = (
        5.1
        if "KDE" in os.getenv(
            "XDG_CURRENT_DESKTOP", ""
        ).split(":")
        else 4.9
    )

    def __init__(self):
        from keyring.backends import kwallet
        backend = kwallet.DBusKeyring()
        super().__init__(backend)
        self._ensure_backend_is_working()


class KeyringBackendLinuxSecretService(KeyringBackendLinux):
    priority = 5

    def __init__(self):
        from keyring.backends import SecretService
        backend = SecretService.Keyring()
        super().__init__(backend)
        self._ensure_backend_is_working()
