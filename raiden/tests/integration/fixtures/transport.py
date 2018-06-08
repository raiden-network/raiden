import pytest

from enum import Enum
from collections import namedtuple

from mirakuru import TCPExecutor


TransportProtocol = Enum('TransportType', 'UDP MATRIX')
TransportConfig = namedtuple('TransportConfig', 'protocol parameters')
MatrixTransportConfig = namedtuple('MatrixTransportConfig', 'command host port')


@pytest.fixture
def transport_config():
    return TransportConfig(protocol=TransportProtocol.UDP, parameters=None)
    # can be changed with command line options, see tests/conftest.py


@pytest.fixture
def local_matrix_server(transport_config):

    if not transport_config.protocol == TransportProtocol.MATRIX:
        yield None
        return

    assert transport_config.parameters.command is not None, \
        'Missing --local-matrix setting. Cannot run Matrix version of integration test.'

    server = TCPExecutor(
        transport_config.parameters.command,
        host=transport_config.parameters.host,
        port=transport_config.parameters.port,
        timeout=120,
        sleep=0.1,
        shell=True
    )

    server.start()
    yield f'http://{transport_config.parameters.host}:{transport_config.parameters.port}'
    server.stop()
