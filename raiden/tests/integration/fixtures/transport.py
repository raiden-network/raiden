import pytest

from enum import Enum
from collections import namedtuple
from urllib.parse import urljoin

from mirakuru import HTTPExecutor


TransportConfig = namedtuple('TransportConfig', 'protocol parameters')
MatrixTransportConfig = namedtuple('MatrixTransportConfig', 'command server')


class TransportProtocol(Enum):
    UDP = 'udp'
    MATRIX = 'matrix'


@pytest.fixture
def transport_config():
    return TransportConfig(protocol=TransportProtocol.UDP, parameters=None)
    # can be changed with command line options, see tests/conftest.py


@pytest.fixture
def skip_if_not_udp(request):
    """Skip the test if not run with UDP transport"""
    if request.config.option.transport == 'udp':
        return
    pytest.skip('This test works only with UDP transport')


@pytest.fixture
def local_matrix_server(transport_config):

    if not transport_config.protocol == TransportProtocol.MATRIX:
        yield None
        return

    server = transport_config.parameters.server

    # if command is none, assume server is already running
    if transport_config.parameters.command in (None, 'none'):
        yield server
        return

    # otherwise, run our own local server
    matrix = HTTPExecutor(
        transport_config.parameters.command,
        status=r'^[24]\d\d$',
        url=urljoin(server, '/_matrix'),
        timeout=120,
        sleep=0.1,
        shell=True,
    )

    matrix.start()
    yield server
    matrix.stop()
