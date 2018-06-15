# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
import os
import random

import pytest
from eth_utils import to_normalized_address
from raiden.network.utils import get_free_port

from raiden.utils import privatekey_to_address
from raiden.settings import (
    DEFAULT_EVENTS_POLL_TIMEOUT,
    DEFAULT_POLL_TIMEOUT,
    DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
    DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
)
from raiden.tests.integration.fixtures.transport import TransportProtocol
from raiden.transfer.mediated_transfer.mediator import TRANSIT_BLOCKS
from raiden.utils import sha3

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)


@pytest.fixture
def settle_timeout(number_of_nodes, reveal_timeout):
    """
    NettingChannel default settle timeout for tests.
    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    return number_of_nodes * (reveal_timeout + TRANSIT_BLOCKS)


@pytest.fixture
def reveal_timeout():
    """
    NettingChannel default reveal timeout for tests.
    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    return 8


@pytest.fixture
def events_poll_timeout():
    return DEFAULT_EVENTS_POLL_TIMEOUT


@pytest.fixture
def random_marker():
    """ A random marker used to identify a pytest run.

    Some tests will spawn a private chain, the private chain will be one or
    more ethereum nodes on a new subprocesss. These nodes may fail to start on
    concurrent test runs, mostly because of port number conflicts, but even
    though the test fails to start its private chain it may run interacting
    with the geth process from a different test run! This leads to
    unreasonable test errors.

    This fixture creates a random marker used to distinguish pytest runs and
    avoid test failures. Note this could fail for other reasons and fail to
    detect unwanted interations if the user sets the PYTHONHASHSEED to the same
    value.
    """
    random_hex = hex(random.getrandbits(100))

    # strip the leading 0x and trailing L
    return random_hex[2:-1]


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    # Arbitrary initial balance for each channel, using a small number for
    # easier calculations during testing
    return 200


@pytest.fixture
def both_participants_deposit():
    """ Boolean flag indicating if both participants of a channel put a deposit. """
    return True


@pytest.fixture
def number_of_tokens():
    """ Number of tokens pre-registered in the test Registry. """
    return 1


@pytest.fixture
def number_of_nodes():
    """ Number of raiden nodes in the test network. """
    return 3


@pytest.fixture
def channels_per_node():
    """ Number of pre-created channels per test raiden node. """
    return 1


@pytest.fixture
def poll_timeout():
    """ Timeout in seconds for polling a cluster. Used for geth. """
    return DEFAULT_POLL_TIMEOUT


@pytest.fixture
def retry_interval():
    return 0.5


@pytest.fixture
def retries_before_backoff():
    return 2


@pytest.fixture
def throttle_capacity():
    return DEFAULT_TRANSPORT_THROTTLE_CAPACITY


@pytest.fixture
def throttle_fill_rate():
    return DEFAULT_TRANSPORT_THROTTLE_FILL_RATE


@pytest.fixture
def nat_invitation_timeout():
    return 5


@pytest.fixture
def nat_keepalive_retries():
    return 2


@pytest.fixture
def nat_keepalive_timeout():
    return 1


@pytest.fixture
def privatekey_seed(request):
    """ Private key template, allow different keys to be used for each test to
    avoid collisions.
    """
    return request.node.name + ':{}'


@pytest.fixture
def token_amount(number_of_nodes, deposit):
    total_per_node = 3 * (deposit + 1)
    total_token = total_per_node * number_of_nodes
    return total_token


@pytest.fixture
def network_wait(transport_config, blockchain_type):
    """Time in seconds used to wait for network events."""
    # Has to be set higher for Travis builds and for the Matrix versions of the
    # tests, due to Travis and the local Synapse server being slow sometimes
    network_wait = 0.3
    if blockchain_type == 'tester':
        network_wait += 0.3
    if 'TRAVIS' in os.environ:
        network_wait += 0.5
    if transport_config.protocol == TransportProtocol.MATRIX:
        network_wait += 2.7
    return network_wait


@pytest.fixture
def private_keys(number_of_nodes, privatekey_seed):
    """ Private keys for each raiden node. """

    # Note: The fixtures depend on the order of the private keys
    result = [
        sha3(privatekey_seed.format(position).encode())
        for position in range(number_of_nodes)
    ]

    # this must not happen, otherwise the keys and addresses will be equal!
    assert len(set(result)) == number_of_nodes, '`privatekey_seed` generate repeated keys'

    return result


@pytest.fixture
def deploy_key(privatekey_seed):
    return sha3(privatekey_seed.format('deploykey').encode())


@pytest.fixture
def blockchain_type(request):
    return request.config.option.blockchain_type


@pytest.fixture
def blockchain_number_of_nodes():
    """ Number of nodes in the cluster, not the same as the number of raiden
    nodes. Used for all geth clusters.
    """
    return 1


@pytest.fixture
def blockchain_key_seed():
    """ Private key template for the nodes in the private blockchain, allows
    different keys to be used for each test to avoid collisions.
    """
    return 'cluster:{}'


@pytest.fixture
def blockchain_private_keys(blockchain_number_of_nodes, blockchain_key_seed):
    """ The private keys for the each private chain node, not the same as the
    raiden's private key.
    """
    return [
        sha3(blockchain_key_seed.format(position).encode())
        for position in range(blockchain_number_of_nodes)
    ]


@pytest.fixture(scope='session')
def port_generator(request):
    """ count generator used to get a unique port number. """
    return get_free_port('127.0.0.1', request.config.option.initial_port)


@pytest.fixture
def blockchain_rpc_ports(blockchain_number_of_nodes, port_generator):
    """ A list of unique port numbers to be used by the blockchain nodes for
    the json-rpc interface.
    """
    return [
        next(port_generator)
        for _ in range(blockchain_number_of_nodes)
    ]


@pytest.fixture
def blockchain_p2p_ports(blockchain_number_of_nodes, port_generator):
    """ A list of unique port numbers to be used by the blockchain nodes for
    the p2p protocol.
    """
    return [
        next(port_generator)
        for _ in range(blockchain_number_of_nodes)
    ]


@pytest.fixture
def raiden_udp_ports(number_of_nodes, port_generator):
    """ A list of unique port numbers to be used by the raiden apps for the udp
    transport.
    """
    return [
        next(port_generator)
        for _ in range(number_of_nodes)
    ]


@pytest.fixture
def rest_api_port_number(port_generator):
    """ Unique port for the REST API server. """
    return next(port_generator)


@pytest.fixture
def in_memory_database():
    """A boolean value indicating whether the sqlite3 databases will be in memory
    or in normal files. Defaults to True (in memory)."""
    return True


@pytest.fixture
def database_paths(tmpdir, private_keys, in_memory_database):
    """ Sqlite database paths for each app.
    """
    # According to http://www.sqlite.org/inmemorydb.html each memory connection will
    # create a unique in-memory DB, which is exactly what we need in this case for
    # each different Raiden app
    if in_memory_database:
        return [
            ':memory:'
            for position in range(len(private_keys))
        ]

    database_paths = list()
    for idx, pkey in enumerate(private_keys):
        app_dir = os.path.join(
            tmpdir.strpath,
            to_normalized_address(privatekey_to_address(pkey))[2:8],
        )
        if not os.path.exists(app_dir):
            os.makedirs(app_dir)
        database_paths.append(os.path.join(app_dir, 'log.db'))

    return database_paths
