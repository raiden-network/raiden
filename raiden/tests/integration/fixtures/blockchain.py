import os

import pytest
from web3 import HTTPProvider, Web3

from raiden.constants import GENESIS_BLOCK_NUMBER, EthClient
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.eth_node import (
    AccountDescription,
    EthNodeDescription,
    GenesisDescription,
    run_private_blockchain,
)
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.utils import privatekey_to_address
from raiden.utils.smart_contracts import deploy_contract_web3
from raiden.utils.typing import TokenAddress
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


@pytest.fixture
def web3(
    blockchain_p2p_ports,
    blockchain_private_keys,
    blockchain_rpc_ports,
    blockchain_type,
    blockchain_extra_config,
    deploy_key,
    private_keys,
    account_genesis_eth_balance,
    random_marker,
    request,
    tmpdir,
    chain_id,
    logs_storage,
):
    """ Starts a private chain with accounts funded. """
    # include the deploy key in the list of funded accounts
    keys_to_fund = sorted(set(private_keys + [deploy_key]))

    if blockchain_type not in {client.value for client in EthClient}:
        raise ValueError(f"unknown blockchain_type {blockchain_type}")

    host = "127.0.0.1"
    rpc_port = blockchain_rpc_ports[0]
    endpoint = f"http://{host}:{rpc_port}"
    web3 = Web3(HTTPProvider(endpoint))

    assert len(blockchain_private_keys) == len(blockchain_rpc_ports)
    assert len(blockchain_private_keys) == len(blockchain_p2p_ports)

    eth_nodes = [
        EthNodeDescription(
            private_key=key,
            rpc_port=rpc,
            p2p_port=p2p,
            miner=(pos == 0),
            extra_config=blockchain_extra_config,
            blockchain_type=blockchain_type,
        )
        for pos, (key, rpc, p2p) in enumerate(
            zip(blockchain_private_keys, blockchain_rpc_ports, blockchain_p2p_ports)
        )
    ]

    accounts_to_fund = [
        AccountDescription(privatekey_to_address(key), account_genesis_eth_balance)
        for key in keys_to_fund
    ]

    # The private chain data is always discarded on the CI
    base_datadir = str(tmpdir)

    # Save the Ethereum node's log for debugging
    base_logdir = os.path.join(logs_storage, blockchain_type)

    genesis_description = GenesisDescription(
        prefunded_accounts=accounts_to_fund, chain_id=chain_id, random_marker=random_marker
    )
    eth_node_runner = run_private_blockchain(
        web3=web3,
        eth_nodes=eth_nodes,
        base_datadir=base_datadir,
        log_dir=base_logdir,
        verbosity="info",
        genesis_description=genesis_description,
    )
    with eth_node_runner:
        yield web3

    cleanup_tasks()


@pytest.fixture
def deploy_client(blockchain_rpc_ports, deploy_key, web3, blockchain_type):
    if blockchain_type == "parity":
        return JSONRPCClient(web3, deploy_key, gas_estimate_correction=lambda gas: 2 * gas)
    return JSONRPCClient(web3, deploy_key)


@pytest.fixture
def proxy_manager(deploy_key, deploy_client, contract_manager):
    return ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )


@pytest.fixture
def blockchain_services(
    proxy_manager,
    private_keys,
    secret_registry_address,
    service_registry_address,
    token_network_registry_address,
    web3,
    contract_manager,
):
    return jsonrpc_services(
        proxy_manager=proxy_manager,
        private_keys=private_keys,
        secret_registry_address=secret_registry_address,
        service_registry_address=service_registry_address,
        token_network_registry_address=token_network_registry_address,
        web3=web3,
        contract_manager=contract_manager,
    )


@pytest.fixture
def unregistered_token(token_amount, deploy_client, contract_manager) -> TokenAddress:
    return TokenAddress(
        deploy_contract_web3(
            CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_client,
            contract_manager=contract_manager,
            constructor_arguments=(token_amount, 2, "raiden", "Rd"),
        )
    )
