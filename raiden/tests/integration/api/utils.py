import os

import gevent
import psutil

from raiden.api.rest import APIServer
from raiden.app import App
from raiden.utils.typing import Port


def wait_for_listening_port(
    port_number: Port, tries: int = 10, sleep: float = 0.1, pid: int = None
) -> None:
    if pid is None:
        pid = os.getpid()
    for _ in range(tries):
        gevent.sleep(sleep)
        # macoOS requires root access for the connections api to work
        # so get connections of the current process only
        connections = psutil.Process(pid).connections()
        for conn in connections:
            if conn.status == "LISTEN" and conn.laddr[1] == port_number:
                return

    raise RuntimeError(f"{port_number} is not bound")


def prepare_api_server(raiden_app: App) -> APIServer:
    api_server = raiden_app.raiden.api_server
    if api_server is None:
        raise RuntimeError("REST API not enabled, enable it using the `enable_rest_api` fixture")

    assert api_server is not None
    config = raiden_app.raiden.config
    port = config.rest_api.port
    assert port is not None, "REST API port is `None`"

    # required for `url_for`
    api_server.flask_app.config["SERVER_NAME"] = f"localhost:{port}"

    # Fixes flaky test, where requests are done prior to the server initializing
    # the listening socket.
    # https://github.com/raiden-network/raiden/issues/389#issuecomment-305551563
    wait_for_listening_port(port)

    return api_server
