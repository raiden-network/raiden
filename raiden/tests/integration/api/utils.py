import os

import gevent
import psutil

from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.app import App


def wait_for_listening_port(
        port_number: int,
        tries: int = 10,
        sleep: float = 0.1,
        pid: int = None,
) -> None:
    if pid is None:
        pid = os.getpid()
    for _ in range(tries):
        gevent.sleep(sleep)
        # macoOS requires root access for the connections api to work
        # so get connections of the current process only
        connections = psutil.Process(pid).connections()
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr[1] == port_number:
                return

    raise RuntimeError('{port} is not bound'.format(port=port_number))


def create_api_server(raiden_app: App, port_number: int) -> APIServer:
    raiden_api = RaidenAPI(raiden_app.raiden)
    rest_api = RestAPI(raiden_api)
    api_server = APIServer(rest_api)
    api_server.flask_app.config['SERVER_NAME'] = 'localhost:{}'.format(port_number)
    api_server.start(port=port_number)

    # Fixes flaky test, were requests are done prior to the server initializing
    # the listening socket.
    # https://github.com/raiden-network/raiden/issues/389#issuecomment-305551563
    wait_for_listening_port(port_number)

    return api_server
