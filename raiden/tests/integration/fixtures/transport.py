import pytest

from raiden.network.transport import MatrixTransport
from raiden.tests.fixtures.variables import TransportProtocol
from raiden.tests.utils.transport import generate_synapse_config, matrix_server_starter


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
def local_matrix_servers(
        request,
        transport_protocol,
        matrix_server_count,
        synapse_config_generator,
):
    if transport_protocol is not TransportProtocol.MATRIX:
        yield [None]
        return

    starter = matrix_server_starter(
        count=matrix_server_count,
        config_generator=synapse_config_generator,
        log_context=request.node.name,
    )
    with starter as server_urls:
        yield server_urls


# Beware: the arguments to `global_rooms` should be lists
@pytest.fixture
def global_rooms():
    return ['discovery']


@pytest.fixture
def matrix_transports(
        local_matrix_servers,
        retries_before_backoff,
        retry_interval,
        private_rooms,
        number_of_transports,
        global_rooms,
):
    transports = []
    for transport_index in range(number_of_transports):
        server = local_matrix_servers[transport_index % len(local_matrix_servers)]
        transports.append(
            MatrixTransport({
                'global_rooms': global_rooms,
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

    for transport in transports:
        transport.get()
