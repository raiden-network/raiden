import pytest
from eth_utils import to_canonical_address, to_checksum_address

from raiden.network.proxies import Token, TokenNetwork, TokenNetworkRegistry
from raiden.tests.utils import factories
from raiden.tests.utils.smartcontracts import deploy_token
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)


@pytest.fixture
def token_network_registry_proxy(deploy_client, token_network_registry_address, contract_manager):
    return TokenNetworkRegistry(
        jsonrpc_client=deploy_client,
        registry_address=to_canonical_address(token_network_registry_address),
        contract_manager=contract_manager,
    )


@pytest.fixture
def token_network_proxy(
        chain_id,
        contract_manager,
        deploy_client,
        secret_registry_address,
        token_contract,
        token_network_contract,
):
    compiled = {
        CONTRACT_TOKEN_NETWORK: contract_manager.get_contract(
            CONTRACT_TOKEN_NETWORK,
        ),
    }
    token_network_contract = deploy_client.deploy_solidity_contract(
        CONTRACT_TOKEN_NETWORK,
        compiled,
        constructor_parameters=[
            token_contract.contract.address,
            secret_registry_address,
            chain_id,
            TEST_SETTLE_TIMEOUT_MIN,
            TEST_SETTLE_TIMEOUT_MAX,
            to_checksum_address(factories.make_address()),
        ],
    )
    return TokenNetwork(
        jsonrpc_client=deploy_client,
        token_network_address=to_canonical_address(token_network_contract.contract.address),
        contract_manager=contract_manager,
    )


@pytest.fixture(name='token_contract')
def deploy_token_and_return_jsonrpc_proxy(deploy_client, contract_manager):
    return deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=10000,
        decimals=0,
        token_name='TKN',
        token_symbol='TKN',
    )


@pytest.fixture
def token_proxy(deploy_client, token_contract, contract_manager):
    return Token(
        jsonrpc_client=deploy_client,
        token_address=to_canonical_address(token_contract.contract.address),
        contract_manager=contract_manager,
    )
