
import gi

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib

from ....logger import logger


class NMClientMixin:
    nm_client = NM.Client.new(None)
    main_loop = GLib.MainLoop()

    def _add_connection_async(self, connection):
        self.nm_client.add_connection_async(
            connection,
            True,
            None,
            self.__dynamic_callback,
            dict(
                callback_type="add",
                conn_name=connection.get_id(),
            )
        )
        self.main_loop.run()

    def _start_connection_async(self, connection):
        """Start ProtonVPN connection."""
        logger.info("Starting VPN connection")

        self.nm_client.activate_connection_async(
            connection,
            None,
            None,
            None,
            self.__dynamic_callback,
            dict(
                callback_type="start",
                conn_name=connection.get_id()
            )
        )
        self.main_loop.run()

    def _remove_connection_async(self, connection):
        logger.info("Removing VPN connection")

        try:
            self.stop_connection_async(connection)
        except: # noqa
            pass

        connection.delete_async(
            None,
            self.__dynamic_callback,
            dict(
                callback_type="remove",
                conn_name=connection.get_id()
            )
        )
        self.main_loop.run()

    def _stop_connection_async(self, connection):
        """Stop ProtonVPN connection.

        Args(optional):
            client (NM.nm_client): new NetworkManager Client object
        """
        logger.info("Stopping VPN connection")

        self.nm_client.deactivate_connection_async(
            connection,
            None,
            self.__dynamic_callback,
            dict(
                callback_type="stop",
                conn_name=connection.get_id()
            )
        )
        self.main_loop.run()

    def __dynamic_callback(self, client, result, data):
        """Dynamic callback method.

        Args:
            client (NM.nm_client): nm client object
            result (Gio.AsyncResult): function
            data (dict): optional extra data
        """
        callback_type = data.get("callback_type")
        logger.info("Callback type: \"{}\"".format(callback_type))
        conn_name = data.get("conn_name")

        try:
            callback_type_dict = dict(
                remove=dict(
                    finish_function=NM.Client.delete_finish,
                    msg="removed"
                )
            )
        except AttributeError:
            callback_type_dict = dict(
                add=dict(
                    finish_function=NM.Client.add_connection_finish,
                    msg="added"
                ),
                start=dict(
                    finish_function=NM.Client.activate_connection_finish,
                    msg="started"
                ),
                stop=dict(
                    finish_function=NM.Client.deactivate_connection_finish,
                    msg="stopped"
                )
            )

        try:
            (callback_type_dict[callback_type]["finish_function"])(client, result)
            msg = "The connection profile \"{}\" has been {}.".format(
                conn_name,
                callback_type_dict[callback_type]["msg"]
            )
            logger.info(msg)
        except Exception as e:
            logger.exception("Exception: {}".format(e))

        self.main_loop.quit()
