import pytest
from eth_utils import to_canonical_address, to_checksum_address

from raiden.network.proxies import SecretRegistry, Token, TokenNetwork, TokenNetworkRegistry
from raiden.tests.utils import factories
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden_contracts.constants import (
    CONTRACT_HUMAN_STANDARD_TOKEN,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER


@pytest.fixture
def deploy_contract(deploy_client):
    """Deploy a contract using raiden-contracts contract manager"""
    def f(contract_name: str, args=None):
        if args is None:
            args = []
        compiled = {
            contract_name: CONTRACT_MANAGER.get_contract(contract_name),
        }
        return deploy_client.deploy_solidity_contract(
            contract_name,
            compiled,
            constructor_parameters=args,
        )
    return f


@pytest.fixture
def secret_registry_contract(deploy_contract):
    return deploy_contract(CONTRACT_SECRET_REGISTRY)


@pytest.fixture
def secret_registry_proxy(deploy_client, secret_registry_contract):
    return SecretRegistry(
        deploy_client,
        to_canonical_address(secret_registry_contract.contract.address),
    )


@pytest.fixture
def token_network_registry_contract(chain_id, deploy_contract, secret_registry_contract):
    return deploy_contract(
        CONTRACT_TOKEN_NETWORK_REGISTRY,
        [
            secret_registry_contract.contract.address,
            chain_id,
            TEST_SETTLE_TIMEOUT_MIN,
            TEST_SETTLE_TIMEOUT_MAX,
        ],
    )


@pytest.fixture
def token_network_registry_proxy(deploy_client, token_network_registry_contract):
    return TokenNetworkRegistry(
        deploy_client,
        to_canonical_address(token_network_registry_contract.contract.address),
    )


@pytest.fixture
def token_network_contract(
        chain_id,
        deploy_contract,
        secret_registry_contract,
        token_contract,
        network_type,
):
    return deploy_contract(
        CONTRACT_TOKEN_NETWORK,
        [
            token_contract.contract.address,
            secret_registry_contract.contract.address,
            chain_id,
            TEST_SETTLE_TIMEOUT_MIN,
            TEST_SETTLE_TIMEOUT_MAX,
            to_checksum_address(factories.make_address()),
        ],
    )


@pytest.fixture
def token_network_proxy(deploy_client, token_network_contract):
    return TokenNetwork(
        deploy_client,
        to_canonical_address(token_network_contract.contract.address),
    )


@pytest.fixture
def token_contract(deploy_token):
    return deploy_token(10000, 0, 'TKN', 'TKN')


@pytest.fixture
def token_proxy(deploy_client, token_contract):
    return Token(
        deploy_client,
        to_canonical_address(token_contract.contract.address),
    )


@pytest.fixture
def deploy_token(deploy_client):
    def f(initial_amount, decimals, token_name, token_symbol):
        token_address = deploy_contract_web3(
            CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_client,
            num_confirmations=None,
            constructor_arguments=(
                initial_amount,
                decimals,
                token_name,
                token_symbol,
            ),
        )

        contract_abi = CONTRACT_MANAGER.get_contract_abi(CONTRACT_HUMAN_STANDARD_TOKEN)
        return deploy_client.new_contract_proxy(
            contract_interface=contract_abi,
            contract_address=token_address,
        )

    return f
