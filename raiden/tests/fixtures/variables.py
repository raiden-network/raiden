# -*- coding: utf-8 -*-
import os

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
    return DEFAULT_SETTLE_TIMEOUT


@pytest.fixture
def reveal_timeout():
    """ NettingChannel default settle timeout. """
    return DEFAULT_REVEAL_TIMEOUT


@pytest.fixture
def events_poll_timeout():
    return DEFAULT_EVENTS_POLL_TIMEOUT


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    return DEFAULT_DEPOSIT


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


# TODO: return a base port that is not random and guaranteed to be used
# only once (avoid that a badly cleaned test interfere with the next).
@pytest.fixture
def blockchain_p2p_base_port():
    """ Default P2P base port. """
    return 29870
