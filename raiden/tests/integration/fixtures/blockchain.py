import os

import pytest
from eth_typing import URI
from eth_utils import to_canonical_address
from web3 import HTTPProvider, Web3

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.eth_node import (
    AccountDescription,
    GenesisDescription,
    run_private_blockchain,
)
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import TokenAddress
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


@pytest.fixture
def web3(
    deploy_key,
    eth_nodes_configuration,
    private_keys,
    account_genesis_eth_balance,
    random_marker,
    tmpdir,
    chain_id,
    logs_storage,
    blockchain_type,
):
    """ Starts a private chain with accounts funded. """
    # include the deploy key in the list of funded accounts
    keys_to_fund = sorted(set(private_keys + [deploy_key]))

    host = "127.0.0.1"
    rpc_port = eth_nodes_configuration[0].rpc_port
    endpoint = f"http://{host}:{rpc_port}"
    web3 = Web3(HTTPProvider(URI(endpoint)))

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
        eth_nodes=eth_nodes_configuration,
        base_datadir=base_datadir,
        log_dir=base_logdir,
        verbosity="info",
        genesis_description=genesis_description,
    )
    with eth_node_runner:
        yield web3

    cleanup_tasks()


@pytest.fixture
def deploy_client(deploy_key, web3, blockchain_type) -> JSONRPCClient:
    return JSONRPCClient(web3=web3, privkey=deploy_key)


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
    contract_proxy, _ = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_amount, 2, "raiden", "Rd"),
    )
    return TokenAddress(to_canonical_address(contract_proxy.address))
