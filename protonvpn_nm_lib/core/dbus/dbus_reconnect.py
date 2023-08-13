import hashlib
import os
import sys
import dbus

import protonvpn_nm_lib

from ...constants import (LOCAL_SERVICE_FILEPATH,
                          SERVICE_TEMPLATE, XDG_CONFIG_SYSTEMD_USER)
from ...enums import DaemonReconnectorEnum
from ...logger import logger
from ..subprocess_wrapper import subprocess


class DbusReconnect:
    DAEMON_COMMANDS = [
        DaemonReconnectorEnum.START,
        DaemonReconnectorEnum.STOP,
        DaemonReconnectorEnum.DAEMON_RELOAD
    ]
    service_unit_name = "protonvpn_reconnect.service"

    def __init__(self):
        self.bus = dbus.SessionBus()

        if not os.path.isdir(XDG_CONFIG_SYSTEMD_USER):
            os.makedirs(XDG_CONFIG_SYSTEMD_USER)

        if (
            not os.path.isfile(LOCAL_SERVICE_FILEPATH)
            or (
                os.path.isfile(LOCAL_SERVICE_FILEPATH)
                and self.get_hash_from_template() != self.get_service_file_hash(LOCAL_SERVICE_FILEPATH)  # noqa
            )
        ):
            self.setup_service()

    def setup_service(self):
        """Setup .service file."""
        logger.info("Setting up .service file")
        filled_template = self.__get_filled_service_template()
        with open(LOCAL_SERVICE_FILEPATH, "w") as f:
            f.write(filled_template)

        self.call_daemon_reconnector(DaemonReconnectorEnum.DAEMON_RELOAD)

    def __get_filled_service_template(self):
        root_dir = os.path.dirname(protonvpn_nm_lib.__file__)
        daemon_folder = os.path.join(root_dir, "daemon")
        python_service_path = os.path.join(
            daemon_folder, "dbus_daemon_reconnector.py"
        )
        python_interpreter_path = sys.executable
        exec_start = python_interpreter_path + " " + python_service_path
        filled_template = SERVICE_TEMPLATE.replace("EXEC_START", exec_start)

        return filled_template

    def start_daemon_reconnector(self):
        """Start daemon reconnector."""
        logger.info("Starting daemon reconnector")
        daemon_status = False
        try:
            daemon_status = self.check_daemon_reconnector_status()
        except Exception as e:
            logger.exception("[!] Exception: {}".format(e))

        logger.info("Daemon status: {}".format(daemon_status))

        if daemon_status:
            return

        self.daemon_reconnector_manager(DaemonReconnectorEnum.START, daemon_status)

    def stop_daemon_reconnector(self):
        """Stop daemon reconnector."""
        logger.info("Stopping daemon reconnector")
        daemon_status = False
        try:
            daemon_status = self.check_daemon_reconnector_status()
        except Exception as e:
            logger.exception("[!] Exception: {}".format(e))

        if not daemon_status:
            return

        logger.info("Daemon status: {}".format(daemon_status))
        self.daemon_reconnector_manager(DaemonReconnectorEnum.STOP, daemon_status)

    def daemon_reconnector_manager(self, callback_type, daemon_status):
        """Start/stop daemon reconnector.

        Args:
            callback_type (DaemonReconnectorEnum): enum
            daemon_status (int): 1 or 0
        """
        logger.info(
            "Managing daemon: cb_type-> \"{}\"; ".format(callback_type)
            + "daemon_status -> \"{}\"".format(daemon_status)
        )
        if callback_type == DaemonReconnectorEnum.START and not daemon_status:
            logger.info("Calling daemon reconnector for start")
            self.call_daemon_reconnector(callback_type)
        elif callback_type == DaemonReconnectorEnum.STOP and daemon_status:
            logger.info("Calling daemon reconnector for stop")
            self.call_daemon_reconnector(callback_type)
            try:
                daemon_status = self.check_daemon_reconnector_status()
            except Exception as e:
                logger.exception("[!] Exception: {}".format(e))
            else:
                logger.info(
                    "Daemon status after stopping: {}".format(daemon_status)
                )
        else:
            logger.info("Something went wrong with the daemon reconnector")

    def check_daemon_reconnector_status(self):
        """Checks the status of the daemon reconnector and starts the process
        only if it's not already running.

        Returns:
            int: indicates the status of the daemon process
        """
        logger.info("Checking daemon reconnector status")

        systemd_object = self.bus.get_object(
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1"
        )
        systemd = dbus.Interface(systemd_object, "org.freedesktop.systemd1.Manager")
        try:
            service_path = systemd.GetUnit(self.service_unit_name)
            service_object = self.bus.get_object("org.freedesktop.systemd1", service_path)
            service_props = dbus.Interface(
                service_object, "org.freedesktop.DBus.Properties"
            )
            unit = service_props.GetAll("org.freedesktop.systemd1.Unit")
            active_state = str(unit.get("ActiveState", "inactive"))

            if active_state == "inactive":
                # Not running
                return 0
            elif (
                active_state == "active"
            ):
                # Already running
                return 1
            else:
                # Service threw an exception
                raise Exception(
                    "[!] An error occurred while checking for Proton VPN "
                    + "reconnector service: "
                    + "(Active state: {})".format(
                        active_state
                    )
                )
        except dbus.DBusException as exception:
            # Service threw an exception
            raise Exception(
                "[!] An error occurred while checking for Proton VPN "
                + "reconnector service: "
                + "(Exception: {} {})".format(
                    exception
                )
            )

    def call_daemon_reconnector(
        self, command
    ):
        """Makes calls to daemon reconnector to either
        start or stop the process.

        Args:
            command (string): to either start or stop the process
        """
        logger.info("Calling daemon reconnector")
        if command not in self.DAEMON_COMMANDS:
            raise Exception("Invalid daemon command \"{}\"".format(command))

        systemd_object = self.bus.get_object(
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1"
        )
        systemd = dbus.Interface(systemd_object, "org.freedesktop.systemd1.Manager")
        try:
            match command:
                case DaemonReconnectorEnum.START:
                    systemd.StartUnit(self.service_unit_name, "replace")
                case DaemonReconnectorEnum.STOP:
                    systemd.StopUnit(self.service_unit_name, "replace")
                case DaemonReconnectorEnum.DAEMON_RELOAD:
                    systemd.Reload()
        except dbus.DBusException as exception:
            msg = "[!] An error occurred while {}ing Proton VPN "\
                "reconnector service: {} {}".format(
                    command,
                    exception
                )
            logger.error(msg)

    def get_hash_from_template(self):
        filled_template = self.__get_filled_service_template()
        template_hash = hashlib.sha256(
            filled_template.encode('ascii')
        ).hexdigest()
        logger.info("Template hash \"{}\"".format(template_hash))
        return template_hash

    def get_service_file_hash(self, file):
        # A arbitrary (but fixed) buffer
        # size (change accordingly)
        # 65536 = 65536 bytes = 64 kilobytes
        BUF_SIZE = 65536
        sha256 = hashlib.sha256()
        with open(file, "rb") as f:
            while True:
                # reading data = BUF_SIZE from
                # the file and saving it in a
                # variable
                data = f.read(BUF_SIZE)
                # True if eof = 1
                if not data:
                    break
                # Passing that data to that sh256 hash
                # function (updating the function with
                # that data)
                sha256.update(data)

        # sha256.hexdigest() hashes all the input
        # data passed to the sha256() via sha256.update()
        # Acts as a finalize method, after which
        # all the input data gets hashed hexdigest()
        # hashes the data, and returns the output
        # in hexadecimal format
        generated_hash = sha256.hexdigest()
        logger.info("Generated hash at runtime \"{}\"".format(generated_hash))
        return generated_hash
