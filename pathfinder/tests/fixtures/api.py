from itertools import count
from typing import Iterator

import psutil
import pytest

from pathfinder.api.rest import ServiceApi
from pathfinder.config import API_DEFAULT_PORT, API_PATH
from pathfinder.pathfinding_service import PathfindingService


def get_free_port(address: str, initial_port: int):
    """Find an unused TCP port in a specified range. This should not
      be used in misson-critical applications - a race condition may
      occur if someone grabs the port before caller of this function
      has chance to use it.
      Parameters:
          address : an ip address of interface to use
          initial_port : port to start iteration with
      Return:
          Iterator that will return next unused port on a specified
          interface
    """

    try:
        # On OSX this function requires root privileges
        psutil.net_connections()
    except psutil.AccessDenied:
        return count(initial_port)

    def _unused_ports():
        for port in count(initial_port):
            # check if the port is being used
            connect_using_port = (
                conn
                for conn in psutil.net_connections()
                if hasattr(conn, 'laddr') and
                conn.laddr[0] == address and
                conn.laddr[1] == port
            )

            # only generate unused ports
            if not any(connect_using_port):
                yield port

    return _unused_ports()


@pytest.fixture(scope='session')
def api_schema() -> str:
    return 'http'


@pytest.fixture(scope='session')
def api_port() -> int:
    return API_DEFAULT_PORT


@pytest.fixture(scope='session')
def port_generator(request):
    """ count generator used to get a unique port number. """
    return get_free_port('localhost', API_DEFAULT_PORT)


@pytest.fixture
def free_port(port_generator: Iterator[int]) -> int:
    return next(port_generator)


@pytest.fixture
def api_url(api_schema: str, free_port: int) -> str:
    return '{}://localhost:{}{}'.format(api_schema, free_port, API_PATH)


@pytest.fixture
def api_sut(pathfinding_service: PathfindingService, free_port: int) -> ServiceApi:
    api = ServiceApi(pathfinding_service)
    api.run(port=free_port)
    return api
