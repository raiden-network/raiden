from typing import List

import pytest

from raiden.constants import Environment
from raiden.network.transport import MatrixTransport
from raiden.settings import (
    DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
    CapabilitiesConfig,
    MatrixTransportConfig,
)
from raiden.tests.fixtures.variables import TransportProtocol
from raiden.tests.utils.transport import ParsedURL, generate_synapse_config, matrix_server_starter
from raiden.utils.http import HTTPExecutor
from raiden.utils.typing import Iterable, Optional, Tuple


@pytest.fixture(scope="session")
def synapse_config_generator():
    with generate_synapse_config() as generator:
        yield generator


@pytest.fixture
def matrix_server_count() -> int:
    return 1


@pytest.fixture
def matrix_sync_timeout() -> int:
    return DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT


@pytest.fixture
def local_matrix_servers_with_executor(
    request,
    transport_protocol,
    matrix_server_count,
    synapse_config_generator,
    port_generator,
) -> Iterable[List[Tuple[ParsedURL, HTTPExecutor]]]:
    if transport_protocol is not TransportProtocol.MATRIX:
        yield []
        return

    starter = matrix_server_starter(
        free_port_generator=port_generator,
        count=matrix_server_count,
        config_generator=synapse_config_generator,
        log_context=request.node.name,
    )
    with starter as servers:
        yield servers


@pytest.fixture
def local_matrix_servers(
    local_matrix_servers_with_executor: List[Tuple[ParsedURL, HTTPExecutor]]
) -> Iterable[List[ParsedURL]]:
    yield [url for url, _ in local_matrix_servers_with_executor]


@pytest.fixture
def matrix_transports(
    local_matrix_servers: List[ParsedURL],
    retries_before_backoff: int,
    retry_interval_initial: float,
    retry_interval_max: float,
    number_of_transports: int,
    matrix_sync_timeout: int,
    capabilities: CapabilitiesConfig,
    environment_type: Environment,
) -> Iterable[List[MatrixTransport]]:
    transports = []
    local_matrix_servers_str = [str(server) for server in local_matrix_servers]

    for transport_index in range(number_of_transports):
        server = local_matrix_servers[transport_index % len(local_matrix_servers)]
        transports.append(
            MatrixTransport(
                config=MatrixTransportConfig(
                    retries_before_backoff=retries_before_backoff,
                    retry_interval_initial=retry_interval_initial,
                    retry_interval_max=retry_interval_max,
                    server=server,
                    available_servers=local_matrix_servers_str,
                    sync_timeout=matrix_sync_timeout,
                    capabilities_config=capabilities,
                ),
                environment=environment_type,
            )
        )

    yield transports

    for transport in transports:
        transport.stop()

    for transport in transports:
        # Calling `get()` on a never started Greenlet will block forever
        if transport._started:
            transport.greenlet.get()


@pytest.fixture
def resolver_ports(number_of_nodes) -> List[Optional[int]]:
    """Default resolver ports for all nodes.

    By default, Raiden nodes start without hash resolvers.
    This is achieved by setting the ports to None. This cause the command line not to
    include --resolver-endpoint  and resolver processes will not start.
    """
    return [None] * number_of_nodes
