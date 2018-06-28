import pytest
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.blockchain import geth_create_blockchain
from web3 import Web3, HTTPProvider


@pytest.fixture
def web3(blockchain_rpc_ports):
    host = '0.0.0.0'
    rpc_port = blockchain_rpc_ports[0]
    endpoint = 'http://%s:%s' % (host, rpc_port)
    return Web3(HTTPProvider(endpoint))


@pytest.fixture
def blockchain_backend(
        request,
        deploy_key,
        web3,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
        tmpdir,
        random_marker,
):

    """ Helper to do proper cleanup. """
    geth_processes = geth_create_blockchain(
        deploy_key,
        web3,
        private_keys,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_p2p_ports,
        str(tmpdir),
        request.config.option.verbose,
        random_marker,
        None,
    )
    yield geth_processes

    [x.terminate() for x in geth_processes]
    cleanup_tasks()


@pytest.fixture
def init_blockchain(blockchain_backend):
    pass
