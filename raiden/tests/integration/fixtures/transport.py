from enum import Enum

import pytest

from raiden.network.transport import MatrixTransport
from raiden.tests.utils.transport import generate_synapse_config, matrix_server_starter


class TransportProtocol(Enum):
    UDP = 'udp'
    MATRIX = 'matrix'


@pytest.fixture
def transport(request):
    """ 'all' replaced by parametrize in conftest.pytest_generate_tests """
    return request.config.getoption('transport')


@pytest.fixture
def transport_protocol(transport):
    return TransportProtocol(transport)


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


@pytest.fixture(scope='session')
def synapse_config_generator():
    with generate_synapse_config() as generator:
        yield generator


@pytest.fixture
def matrix_server_count():
    return 1


@pytest.fixture
def local_matrix_servers(transport_protocol, matrix_server_count, synapse_config_generator):
    if transport_protocol is not TransportProtocol.MATRIX:
        yield [None]
        return

    starter = matrix_server_starter(
        count=matrix_server_count,
        config_generator=synapse_config_generator,
    )
    with starter as server_urls:
        yield server_urls


@pytest.fixture
def matrix_transports(local_matrix_servers, retries_before_backoff, retry_interval, private_rooms):
    transports = []
    for server in local_matrix_servers:
        transports.append(
            MatrixTransport({
                'discovery_room': 'discovery',
                'retries_before_backoff': retries_before_backoff,
                'retry_interval': retry_interval,
                'server': server,
                'server_name': server.netloc,
                'available_servers': local_matrix_servers,
                'private_rooms': private_rooms,
            }),
        )

    yield transports

    for transport in transports:
        transport.stop()
