import pytest
from eth_utils import to_canonical_address

from raiden.network.proxies import Token, TokenNetwork, TokenNetworkRegistry
from raiden.tests.utils.smartcontracts import deploy_token


@pytest.fixture(name='token_network_registry_proxy')
def create_token_network_registry_proxy(
        deploy_client,
        token_network_registry_address,
        contract_manager,
):
    return TokenNetworkRegistry(
        jsonrpc_client=deploy_client,
        registry_address=to_canonical_address(token_network_registry_address),
        contract_manager=contract_manager,
    )


@pytest.fixture(name='token_network_proxy')
def register_token_and_return_the_network_proxy(
        contract_manager,
        deploy_client,
        token_contract,
        token_network_registry_proxy,
):
    token_address = to_canonical_address(token_contract.contract.address)
    token_network_address = token_network_registry_proxy.add_token(
        token_address=token_address,
        given_block_identifier='latest',
    )

    return TokenNetwork(
        jsonrpc_client=deploy_client,
        token_network_address=token_network_address,
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
