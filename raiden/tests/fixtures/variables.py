# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
from itertools import count

import pytest
import psutil
import os
from ethereum.utils import sha3

from raiden.settings import (
    DEFAULT_EVENTS_POLL_TIMEOUT,
    DEFAULT_POLL_TIMEOUT,
)
from raiden.network.transport import UDPTransport

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)


@pytest.fixture
def settle_timeout(blockchain_type):
    """
    NettingChannel default settle timeout for tests.
    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    if blockchain_type == 'geth':
        return 16
    else:
        return 400


@pytest.fixture
def reveal_timeout(blockchain_type):
    """
    NettingChannel default reveal timeout for tests.
    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    if blockchain_type == 'geth':
        return 4
    else:
        return 20


@pytest.fixture
def events_poll_timeout():
    return DEFAULT_EVENTS_POLL_TIMEOUT


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
def transport_class():
    return UDPTransport


@pytest.fixture
def send_ping_time():
    """
    Time in seconds after which if we have received no message from a node we
    have a connection with, we are going to send a PING message
    """
    return 0


@pytest.fixture
def max_unresponsive_time():
    """
    Max time in seconds for which an address can send no packets and still
    be considered healthy. Give 0 in order to disable healthcheck.
    """
    return 0  # Default is no healthcheck for tests


@pytest.fixture
def privatekey_seed():
    """ Private key template, allow different keys to be used for each test to
    avoid collisions.
    """
    return 'key:{}'


@pytest.fixture
def token_amount(number_of_nodes, deposit):
    total_per_node = 3 * (deposit + 1)
    total_token = total_per_node * number_of_nodes
    return total_token


@pytest.fixture
def private_keys(number_of_nodes, privatekey_seed):
    """ Private keys for each raiden node. """
    result = [
        sha3(privatekey_seed.format(position))
        for position in range(number_of_nodes)
    ]

    # this must not happen, otherwise the keys and addresses will be equal!
    assert len(set(result)) == number_of_nodes, '`privatekey_seed` generate repeated keys'

    return result


@pytest.fixture
def deploy_key(privatekey_seed):
    return sha3(privatekey_seed.format('deploykey'))


@pytest.fixture
def blockchain_type(request):
    return request.config.option.blockchain_type


@pytest.fixture
def blockchain_number_of_nodes():
    """ Number of nodes in the cluster, not the same as the number of raiden
    nodes. Used for all geth clusters and ignored for tester and
    mock.
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
        sha3(blockchain_key_seed.format(position))
        for position in range(blockchain_number_of_nodes)
    ]


@pytest.fixture(scope='session')
def port_generator(request):
    """ count generator used to get a unique port number. """

    try:
        # On OSX this function requires root privileges
        psutil.net_connections()
    except psutil.AccessDenied:
        return count(request.config.option.initial_port)

    def _unused_ports():
        for port in count(request.config.option.initial_port):
            # check if the port is being used
            connect_using_port = (
                conn
                for conn in psutil.net_connections()
                if hasattr(conn, 'laddr') and conn.laddr[1] == port
            )

            # only generate unused ports
            if not any(connect_using_port):
                yield port

    return _unused_ports()


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
    protocol.
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
    else:
        return [
            os.path.join(tmpdir.strpath, 'transaction_log_{}.db'.format(position))
            for position in range(len(private_keys))
        ]
