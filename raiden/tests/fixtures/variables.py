# pylint: disable=redefined-outer-name
import os
import random

import pytest
from eth_utils import denoms, remove_0x_prefix, to_normalized_address

from raiden.constants import Environment
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_RETRY_TIMEOUT,
    DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
    DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
)
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.utils import privatekey_to_address, sha3
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MAX, TEST_SETTLE_TIMEOUT_MIN

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)

DEFAULT_BALANCE = denoms.ether * 10  # pylint: disable=no-member
DEFAULT_BALANCE_BIN = str(DEFAULT_BALANCE)
DEFAULT_PASSPHRASE = 'notsosecret'  # Geth's account passphrase

RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = int(0.075 * 10 ** 18)


@pytest.fixture
def settle_timeout(reveal_timeout):
    """
    NettingChannel default settle timeout for tests.
    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    return reveal_timeout * 3


@pytest.fixture
def chain_id():
    # This value must be used in the `--networkid` option for the geth client
    return UNIT_CHAIN_ID


@pytest.fixture
def settle_timeout_min():
    return TEST_SETTLE_TIMEOUT_MIN


@pytest.fixture
def settle_timeout_max():
    return TEST_SETTLE_TIMEOUT_MAX


@pytest.fixture
def reveal_timeout(number_of_nodes):
    """ NettingChannel default reveal timeout for tests.

    If using geth we set it considerably lower since waiting for
    too many blocks to be mined is very costly time-wise.
    """
    # The tests use a private chain with proof-of-authority, this kind of chain
    # will mine a new block every second.
    #
    # When a node `A` needs to send a message to a node `B` for the first time,
    # `A` has to create a matrix room and invite `B` into it. The room creation
    # will take 2 seconds, and the invite 1 second to complete, this adds 3
    # seconds/blocks of latency to the first message.
    #
    # Because the lock expiration is fixed, and it's computed based on the
    # reveal timeout value, we need to make it large enough to accomodate for
    # the room creation and invite, the formula below is used for that:
    return number_of_nodes * 4


@pytest.fixture
def retry_timeout():
    return DEFAULT_RETRY_TIMEOUT


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
    return remove_0x_prefix(random_hex)


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    # Arbitrary initial balance for each channel, using a small number for
    # easier calculations during testing
    return 200


@pytest.fixture
def number_of_tokens():
    """ Number of tokens pre-registered in the test Registry. """
    return 1


@pytest.fixture
def register_tokens():
    """ Should fixture generated tokens be registered with raiden. """
    return True


@pytest.fixture
def number_of_nodes():
    """ Number of raiden nodes in the test network. """
    return 3


@pytest.fixture
def channels_per_node():
    """ Number of pre-created channels per test raiden node. """
    return 1


@pytest.fixture
def retry_interval(request):
    if request.config.option.transport == 'matrix':
        return 5
    else:
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
    total_per_node = RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT * 4
    total_token = total_per_node * number_of_nodes
    return total_token


@pytest.fixture
def network_wait():
    """Time in seconds used to wait for network events."""
    return 10.0


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
def database_paths(tmpdir, private_keys):
    """ Sqlite database paths for each app. """
    database_paths = list()
    for pkey in private_keys:
        app_dir = os.path.join(
            tmpdir.strpath,
            to_normalized_address(privatekey_to_address(pkey))[2:8],
        )
        if not os.path.exists(app_dir):
            os.makedirs(app_dir)
        database_paths.append(os.path.join(app_dir, 'log.db'))

    return database_paths


@pytest.fixture
def private_rooms():
    return True


@pytest.fixture
def environment_type():
    """Specifies the environment type"""
    return Environment.PRODUCTION
