from collections import namedtuple
from enum import Enum
from urllib.parse import urljoin

import pytest

from raiden.utils.http import HTTPExecutor

TransportConfig = namedtuple('TransportConfig', 'protocol parameters')
MatrixTransportConfig = namedtuple('MatrixTransportConfig', 'command server')


class TransportProtocol(Enum):
    UDP = 'udp'
    MATRIX = 'matrix'


@pytest.fixture
def transport(request):
    """ 'all' replaced by parametrize in conftest.pytest_generate_tests """
    return request.config.getoption('transport')


@pytest.fixture
def transport_config(request, transport):
    if transport == 'udp':
        return TransportConfig(protocol=TransportProtocol.UDP, parameters=None)
    elif transport == 'matrix':
        command = request.config.getoption('local_matrix')
        return TransportConfig(
            protocol=TransportProtocol.MATRIX,
            parameters=MatrixTransportConfig(
                command=command,
                server=request.config.getoption('matrix_server'),
            ),
        )
    else:
        return None
    # can be changed with command line options, see tests/conftest.py


@pytest.fixture
def skip_if_not_udp(request):
    """Skip the test if not run with UDP transport"""
    if request.config.option.transport in ('udp', 'all'):
        return
    pytest.skip('This test works only with UDP transport')


@pytest.fixture
def skip_if_not_matrix(request):
    """Skip the test if not run with Matrix transport"""
    if request.config.option.transport in ('matrix', 'all'):
        return
    pytest.skip('This test works only with Matrix transport')


@pytest.fixture
def public_and_private_rooms():
    """If present in a test, conftest.pytest_generate_tests will parametrize private_rooms fixture
    """
    return True


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
    with HTTPExecutor(
        transport_config.parameters.command,
        url=urljoin(server, '/_matrix/client/versions'),
        method='GET',
        timeout=30,
        shell=True,
    ):
        yield server
