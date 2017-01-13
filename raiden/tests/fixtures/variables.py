# -*- coding: utf-8 -*-
import os
from itertools import count

import pytest
from ethereum.utils import sha3

from raiden.raiden_service import DEFAULT_REVEAL_TIMEOUT, DEFAULT_SETTLE_TIMEOUT
from raiden.tasks import DEFAULT_EVENTS_POLL_TIMEOUT
from raiden.network.rpc.client import DEFAULT_POLL_TIMEOUT
from raiden.network.transport import UDPTransport

# Arbitrary initial balance for each channel, using a small number to tractable
# numbers during testing
DEFAULT_DEPOSIT = 200

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)


@pytest.fixture
def settle_timeout():
    """ NettingChannel default settle timeout. """
    return 100


@pytest.fixture
def reveal_timeout():
    """ NettingChannel default settle timeout. """
    return 5


@pytest.fixture
def events_poll_timeout():
    return DEFAULT_EVENTS_POLL_TIMEOUT


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    return DEFAULT_DEPOSIT


@pytest.fixture
def both_participants_deposit():
    """ Boolean flag indicating if both participants of a channel put a deposit. """
    return True


@pytest.fixture
def number_of_assets():
    """ Number of assets pre-registered in the test Registry. """
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
    # docker travis timeouts too often with the a timeout of 60
    if 'TRAVIS' in os.environ:
        return 180

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
def asset_amount(number_of_nodes, deposit):
    total_per_node = 3 * (deposit + 1)
    total_asset = total_per_node * number_of_nodes
    return total_asset


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
    """ Number of nodes in a the cluster, not the same as the number of raiden
    nodes. Used for all geth clusters and ignored for tester and
    mock.
    """
    return 3


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
    return count(request.config.option.initial_port)


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
