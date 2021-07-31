import json
import os

from ...logger import logger
from ...constants import PROTON_XDG_CONFIG_HOME
from ._base import KeyringBackend


class KeyringBackendJsonFiles(KeyringBackend):
    # Low priority
    priority = -1000

    def __init__(self):
        super().__init__()

        self.__path_base = PROTON_XDG_CONFIG_HOME

    def __get_filename_for_key(self, key):
        self._ensure_key_is_valid(key)

        return os.path.join(self.__path_base, f'keyring-{key}.json')

    def __getitem__(self, key):
        logger.info("Get key {}".format(key))
        f = self.__get_filename_for_key(key)
        if not os.path.exists(f):
            raise KeyError(key)

        with open(f) as f:
            stored_data = f.read()
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
        f = self.__get_filename_for_key(key)
        if not os.path.exists(f):
            raise KeyError(key)
        os.unlink(f)

    def __setitem__(self, key, value):
        self._ensure_key_is_valid(key)
        self._ensure_value_is_valid(value)

        with open(self.__get_filename_for_key(key), 'w') as f:
            json.dump(value, f)

    def _ensure_backend_is_working(self):
        pass
