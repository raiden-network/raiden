import pytest
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3, HTTPProvider
from web3.providers.eth_tester import EthereumTesterProvider

from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.geth import (
    geth_run_private_blockchain,
    GethNodeDescription,
)
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.tester import (
    fund_accounts,
    Miner,
)
from raiden.utils import (
    privatekey_to_address,
)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


@pytest.fixture
def endpoint_discovery_services(blockchain_services, endpoint_registry_address):
    return [
        ContractDiscovery(chain.node_address, chain.discovery(endpoint_registry_address))
        for chain in blockchain_services.blockchain_services
    ]


@pytest.fixture(scope='session')
def ethereum_tester(
    patch_genesis_gas_limit,
):
    """Returns an instance of an Ethereum tester"""
    tester = EthereumTester(PyEVMBackend())
    tester.set_fork_block('FORK_BYZANTIUM', 0)
    return tester


@pytest.fixture
def web3(
        blockchain_p2p_ports,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_type,
        deploy_key,
        private_keys,
        random_marker,
        request,
        tmpdir,
        ethereum_tester,
        chain_id,
):
    """ Starts a private chain with accounts funded. """
    # include the deploy key in the list of funded accounts
    keys_to_fund = set(private_keys)
    keys_to_fund.add(deploy_key)
    keys_to_fund = sorted(keys_to_fund)

    if blockchain_type == 'geth':
        host = '0.0.0.0'
        rpc_port = blockchain_rpc_ports[0]
        endpoint = f'http://{host}:{rpc_port}'
        web3 = Web3(HTTPProvider(endpoint))

        assert len(blockchain_private_keys) == len(blockchain_rpc_ports)
        assert len(blockchain_private_keys) == len(blockchain_p2p_ports)

        geth_nodes = [
            GethNodeDescription(
                key,
                rpc,
                p2p,
                miner=(pos == 0),
            )
            for pos, (key, rpc, p2p) in enumerate(zip(
                blockchain_private_keys,
                blockchain_rpc_ports,
                blockchain_p2p_ports,
            ))
        ]

        accounts_to_fund = [
            privatekey_to_address(key)
            for key in keys_to_fund
        ]

        geth_processes = geth_run_private_blockchain(
            web3,
            accounts_to_fund,
            geth_nodes,
            str(tmpdir),
            chain_id,
            request.config.option.verbose,
            random_marker,
        )

        yield web3

        for process in geth_processes:
            process.terminate()

        cleanup_tasks()

    elif blockchain_type == 'tester':
        web3 = Web3(EthereumTesterProvider(ethereum_tester))
        snapshot = ethereum_tester.take_snapshot()

        fund_accounts(web3, keys_to_fund, ethereum_tester)

        miner = Miner(web3)
        miner.start()

        yield web3

        miner.stop.set()
        miner.join()
        ethereum_tester.revert_to_snapshot(snapshot)

    else:
        raise ValueError(f'unknwon blockchain_type {blockchain_type}')


@pytest.fixture
def deploy_client(blockchain_rpc_ports, deploy_key, web3):
    host = '0.0.0.0'
    rpc_port = blockchain_rpc_ports[0]

    return JSONRPCClient(
        host,
        rpc_port,
        deploy_key,
        web3=web3,
    )


@pytest.fixture
def deploy_service(deploy_key, deploy_client):
    return BlockChainService(deploy_key, deploy_client)


@pytest.fixture
def blockchain_services(
        deploy_service,
        private_keys,
        secret_registry_address,
        token_network_registry_address,
        web3,
):
    return jsonrpc_services(
        deploy_service,
        private_keys,
        secret_registry_address,
        token_network_registry_address,
        web3=web3,
    )
