import datetime
import os
import re
from datetime import tzinfo
from ...constants import (NETWORK_MANAGER_LOGFILE, PROTON_XDG_CACHE_HOME_LOGS,
                          PROTONVPN_RECONNECT_LOGFILE)
from ..subprocess_wrapper import subprocess
from ..utils import Singleton

ZERO = datetime.timedelta(0)
HOUR = datetime.timedelta(hours=1)


class BugReport(metaclass=Singleton):
    DELTA_TIME_IN_DAYS = 3
    COMPILED_LOG_EPOCH_RE = re.compile(r"(\[\d+\.\d+\])")
    IS_USER_UNIT = False

    def generate_logs(self):
        """Generate all logs."""
        self.generate_network_manager_log()
        self.generate_protonvpn_reconnector_log()

    def generate_network_manager_log(self):
        """Generate NetworkManager log file for bug report.

        The log file is created with the help of python-systemd
        package which can easily read journalctl content.
        """
        self._remove_network_manager_log_if_exists()
        self.IS_USER_UNIT = False
        self.__generate_log("NetworkManager.service", NETWORK_MANAGER_LOGFILE)

    def generate_protonvpn_reconnector_log(self):
        """Generate Proton VPN Reconnect log file for bug report.

        The log file is created with the help of python-systemd
        package which can easily read journalctl content.
        """
        self._remove_protonvpn_reconnect_log_if_exists()
        self.IS_USER_UNIT = True
        self.__generate_log("protonvpn_reconnect.service", PROTONVPN_RECONNECT_LOGFILE)

    def _remove_network_manager_log_if_exists(self):
        self.__remove_log_if_exists(NETWORK_MANAGER_LOGFILE)

    def _remove_protonvpn_reconnect_log_if_exists(self):
        self.__remove_log_if_exists(PROTONVPN_RECONNECT_LOGFILE)

    def __generate_log(self, systemd_unit, filepath):
        """Generate log file.

        Args:
            systemd_unit (string): systemd .service name
            filepath (string): filepath to log file
        """
        from systemd import journal

        _journal = journal.Reader()

        if self.IS_USER_UNIT:
            _journal.add_match(_SYSTEMD_USER_UNIT=systemd_unit)
        else:
            _journal.add_match(_SYSTEMD_UNIT=systemd_unit)

        _journal.log_level(journal.LOG_DEBUG)

        self.__add_log_to_file(_journal, filepath)

        _journal.close()

    def __remove_log_if_exists(self, filepath):
        """Remove log file if it exists.

        Args:
            filepath (string): filepath to log file
        """
        if os.path.isfile(filepath):
            os.remove(filepath)

    def __add_log_to_file(self, journal, filepath):
        """Add log entry to file, line by line.

        The log fil will contain information from the last 3 days.

        Args:
            journal (systemd.journal.Reader): journal reader object
            filepath (string): filepath to log file
        """
        start_date = datetime.datetime.today() - datetime.timedelta(
            days=self.DELTA_TIME_IN_DAYS
        )
        start_date_timestamp = start_date.timestamp()
        with open(filepath, "a") as f:
            for entry in journal:

                # Skip entry if it's older then start date
                try:
                    if entry["_SOURCE_REALTIME_TIMESTAMP"].timestamp() < start_date_timestamp:
                        continue

                    edited_entry = self.__convert_time_to_utc(entry, "_SOURCE_REALTIME_TIMESTAMP")
                except KeyError:
                    if entry["__REALTIME_TIMESTAMP"].timestamp() < start_date_timestamp:
                        continue

                    edited_entry = self.__convert_time_to_utc(entry, "__REALTIME_TIMESTAMP")

                f.write(self.__format_entry(edited_entry))

    def __convert_time_to_utc(self, entry, key):
        dt = entry[key]
        entry[key] = dt.astimezone(UTC())

        return entry

    def __format_entry(self, entry):
        """Format log entry.

        It will also remove the time in epoch and replace it by human redeable time.

        Args:
            entry (dict): entry containing journalctl data
        """
        try:
            _date = str(entry["_SOURCE_REALTIME_TIMESTAMP"])
            _msg = self.COMPILED_LOG_EPOCH_RE.sub("", entry["MESSAGE"])
        except KeyError:
            _date = str(entry["__REALTIME_TIMESTAMP"])
            _msg = entry["MESSAGE"]

        _entry = _date + " " + _msg + "\n"

        return _entry

    def open_folder_with_logs(self):
        subprocess.run(["xdg-open", PROTON_XDG_CACHE_HOME_LOGS])


# Code snippets below were fetched from https://github.com/newvem/pytz
# Since the project is not available on all distro repos (that we support),
# only relevant parts of the code were imported.
# Some modifications had to be made to accomodate interoperability.


class BaseTzInfo(tzinfo):
    _utcoffset = None
    _tzname = None
    zone = None

    def __str__(self):
        return self.zone


class UTC(BaseTzInfo):
    """UTC

    Optimized UTC implementation. It unpickles using the single module global
    instance defined beneath this class declaration.
    """
    zone = "UTC"

    _utcoffset = ZERO
    _dst = ZERO
    _tzname = zone

    def fromutc(self, dt):
        if dt.tzinfo is None:
            return self.localize(dt)
        return super(UTC, self).fromutc(dt)

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

    def __reduce__(self):
        return _UTC, ()

    def localize(self, dt, is_dst=False):
        '''Convert naive time to local time'''
        if dt.tzinfo is not None:
            raise ValueError('Not naive datetime (tzinfo is already set)')
        return dt.replace(tzinfo=self)

    def normalize(self, dt, is_dst=False):
        '''Correct the timezone information on the given datetime'''
        if dt.tzinfo is self:
            return dt
        if dt.tzinfo is None:
            raise ValueError('Naive time - no tzinfo set')
        return dt.astimezone(self)

    def __repr__(self):
        return "<UTC>"

    def __str__(self):
        return "UTC"


def _UTC():
    """Factory function for utc unpickling.

    Makes sure that unpickling a utc instance always returns the same
    module global.

    These examples belong in the UTC class above, but it is obscured; or in
    the README.rst, but we are not depending on Python 2.4 so integrating
    the README.rst examples with the unit tests is not trivial.

    >>> import datetime, pickle
    >>> dt = datetime.datetime(2005, 3, 1, 14, 13, 21, tzinfo=utc)
    >>> naive = dt.replace(tzinfo=None)
    >>> p = pickle.dumps(dt, 1)
    >>> naive_p = pickle.dumps(naive, 1)
    >>> len(p) - len(naive_p)
    17
    >>> new = pickle.loads(p)
    >>> new == dt
    True
    >>> new is dt
    False
    >>> new.tzinfo is dt.tzinfo
    True
    >>> utc is UTC is timezone('UTC')
    True
    >>> utc is timezone('GMT')
    False
    """
    return UTC


_UTC.__safe_for_unpickling__ = True
