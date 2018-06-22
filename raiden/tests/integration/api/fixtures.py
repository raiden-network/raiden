# pylint: disable=too-many-arguments,redefined-outer-name
import os
import pytest
import psutil
import gevent
from gevent import Greenlet

from raiden.api.python import RaidenAPI
from raiden.api.rest import RestAPI, APIServer


def wait_for_listening_port(port_number, tries=10, sleep=0.1, pid=None):
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


# TODO: Figure out why this fixture can't work as session scoped
#       What happens is that after one test is done, in the next one
#       the server is no longer running even though the teardown has not
#       been invoked.
@pytest.fixture
def api_backend(raiden_network, rest_api_port_number):
    raiden_api = RaidenAPI(raiden_network[0].raiden)
    rest_api = RestAPI(raiden_api)
    api_server = APIServer(rest_api)
    api_server.flask_app.config['SERVER_NAME'] = 'localhost:{}'.format(rest_api_port_number)

    # TODO: Find out why tests fail with debug=True
    server = Greenlet.spawn(
        api_server.run,
        port=rest_api_port_number,
        debug=False,
        use_evalex=False,
    )

    # Fixes flaky test, were requests are done prior to the server initializing
    # the listening socket.
    # https://github.com/raiden-network/raiden/issues/389#issuecomment-305551563
    wait_for_listening_port(rest_api_port_number)

    yield api_server, rest_api

    server.kill(block=True, timeout=10)
