from typing import List

import pytest

from raiden.constants import DISCOVERY_DEFAULT_ROOM
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.tests.fixtures.variables import TransportProtocol
from raiden.tests.utils.transport import generate_synapse_config, matrix_server_starter
from raiden.utils.typing import Optional


@pytest.fixture(scope="session")
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
    port_generator,
    broadcast_rooms,
    chain_id,
):
    if transport_protocol is not TransportProtocol.MATRIX:
        yield [None]
        return

    broadcast_rooms_aliases = [
        make_room_alias(chain_id, room_name) for room_name in broadcast_rooms
    ]

    starter = matrix_server_starter(
        free_port_generator=port_generator,
        broadcast_rooms_aliases=broadcast_rooms_aliases,
        count=matrix_server_count,
        config_generator=synapse_config_generator,
        log_context=request.node.name,
    )
    with starter as server_urls:
        yield server_urls


@pytest.fixture
def broadcast_rooms() -> List[str]:
    return [DISCOVERY_DEFAULT_ROOM]


@pytest.fixture
def matrix_transports(
    local_matrix_servers,
    retries_before_backoff,
    retry_interval,
    number_of_transports,
    broadcast_rooms,
):
    transports = []
    for transport_index in range(number_of_transports):
        server = local_matrix_servers[transport_index % len(local_matrix_servers)]
        transports.append(
            MatrixTransport(
                {
                    "broadcast_rooms": broadcast_rooms,
                    "retries_before_backoff": retries_before_backoff,
                    "retry_interval": retry_interval,
                    "server": server,
                    "server_name": server.netloc,
                    "available_servers": local_matrix_servers,
                }
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
