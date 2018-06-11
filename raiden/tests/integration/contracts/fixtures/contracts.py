import pytest
from raiden.network.proxies import (
    SecretRegistry,
    TokenNetworkRegistry,
)

from raiden_contracts.contract_manager import CONTRACT_MANAGER
from eth_utils import to_canonical_address
from raiden.utils import get_contract_path
from raiden.utils.solc import compile_files_cwd

from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_HUMAN_STANDARD_TOKEN,
)


@pytest.fixture
def deploy_contract(blockchain_services, deploy_client):
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
        [secret_registry_contract.contract.address, chain_id],
    )


@pytest.fixture
def token_network_registry_proxy(deploy_client, token_network_registry_contract):
    return TokenNetworkRegistry(
        deploy_client,
        to_canonical_address(token_network_registry_contract.contract.address),
    )


@pytest.fixture
def deploy_token(deploy_client):
    def f(initial_amount, decimals, token_name, token_symbol):
        args = [initial_amount, token_name, decimals, token_symbol]
        contract_path = get_contract_path('HumanStandardToken.sol')
        compiled = compile_files_cwd([contract_path])
        return deploy_client.deploy_solidity_contract(
            CONTRACT_HUMAN_STANDARD_TOKEN,
            compiled,
            constructor_parameters=args,
            contract_path=contract_path,
        )
    return f
