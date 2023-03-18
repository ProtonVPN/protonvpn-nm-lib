import os
import platform
import subprocess as _subprocess


class SubprocessWrapper:
    """Subprocess wrapper.
    This should be used instead of directly reling on subprocess,
    as it assures that the specified executables are safe to use.

    Exposes method:
        run()

    Description:

    run()
        Takes the exact same arguments as subprocess.run(), as this
        is effectivtly a layer on top of subprocess.
    """

    _acceptable_binaries = {"nmcli", "clear", "xdg-open"}
    PIPE = _subprocess.PIPE
    STDOUT = _subprocess.STDOUT
    DEVNULL = _subprocess.DEVNULL

    @staticmethod
    def is_root_owned(path):
        stat_info = os.stat(path)
        return stat_info.st_uid == 0 and stat_info.st_gid == 0

    def __init__(self):
        self._path_to_binaries = {}
        self.__search_for_matching_executables()
        self.__ensure_executables_exist()

    def __search_for_matching_executables(self):
        """Searches for matching executables.

        While searching, it will attempt to match the
        executables provided in _acceptable_binaries and ensure that
        those executables are root owned.

        It builds self._path_to_binaries, where
        binary_short_name => full secure path.
        """
        # Look for root-owned directories in the system path in order
        for path in os.environ.get('PATH', '').split(os.path.pathsep):
            if not os.path.isdir(path):
                continue
            if not self.is_root_owned(path):
                continue

            # Check for all the binaries that we haven't matched yet
            for binary in self._acceptable_binaries.difference(
                self._path_to_binaries.keys()
            ):
                binary_path_candidate = os.path.join(path, binary)
                if not os.path.isfile(binary_path_candidate):
                    continue

                if not self.is_root_owned(binary_path_candidate):
                    continue

                # We're happy with that one, store it
                self._path_to_binaries[binary] = binary_path_candidate

            # Shortcut: if we don't have any executable left to find,
            # we can exit the loop
            if len(self._path_to_binaries) == len(self._acceptable_binaries):
                break

    def __ensure_executables_exist(self):
        """Ensure that executables exist, by comparing the length of
        self._path_to_binaries to self._acceptable_binaries.
        """
        # Were we unable to find executables? This is bad
        if len(self._path_to_binaries) != len(self._acceptable_binaries):
            missing_executables = self._acceptable_binaries.difference(
                self._path_to_binaries.keys()
            )
            raise RuntimeError(
                "Couldn't find acceptable "
                "executables for {}".format(missing_executables)
            )

    def run(
        self, args, input=None, stdout=None, stderr=None,
        capture_output=False, timeout=None, check=False
    ):
        """Wraps subprocess run.

        For security reason we limit the acceptable arguments here.
        """
        if (
            type(args) != list
            or len(args) < 1
            or not all(type(a) == str for a in args)
        ):
            raise ValueError("args should be a non-empty list of string")

        if args[0] not in self._path_to_binaries:
            raise ValueError(
                "{!r} is not an acceptable binary".format(args[0])
            )

        # Replace the path with the one we wanted
        args[0] = self._path_to_binaries[args[0]]

        # Python below 3.7.0 does not support capture_output
        if platform.python_version() < "3.7.0":
            return _subprocess.run(
                args, input=input, stdout=stdout,
                stderr=stderr,
                timeout=timeout, check=check
            )
        else:
            return _subprocess.run(
                args, input=input, stdout=stdout,
                stderr=stderr, capture_output=capture_output,
                timeout=timeout, check=check
            )

subprocess = SubprocessWrapper() # noqa
