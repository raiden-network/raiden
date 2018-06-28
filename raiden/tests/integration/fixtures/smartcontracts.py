import pytest
from eth_utils import decode_hex
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
)

from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.tests.utils.smartcontracts import deploy_tokens_and_fund_accounts
from raiden.utils import (
    get_contract_path,
    privatekey_to_address,
)
from raiden.utils.solc import compile_files_cwd


@pytest.fixture
def token_addresses(
        token_amount,
        number_of_tokens,
        private_keys,
        deploy_service,
        registry_address,
        register_tokens,
):
    """ Fixture that yields `number_of_tokens` ERC20 token addresses, where the
    `token_amount` (per token) is distributed among the addresses behind `deploy_client` and
    potentially pre-registered with the raiden Registry.
    The following arguments can control the behavior:

    Args:
        token_amount (int): the overall number of units minted per token
        number_of_tokens (int): the number of token instances
        register_tokens (bool): controls if tokens will be registered with raiden Registry
    """

    participants = [privatekey_to_address(key) for key in private_keys]
    token_addresses = deploy_tokens_and_fund_accounts(
        token_amount,
        number_of_tokens,
        deploy_service,
        participants,
    )

    if register_tokens:
        for token in token_addresses:
            deploy_service.registry(registry_address).add_token(token)

    return token_addresses


@pytest.fixture
def endpoint_registry_address(deploy_client):
    address = deploy_contract_web3(
        CONTRACT_ENDPOINT_REGISTRY,
        deploy_client,
    )
    return address


@pytest.fixture
def secret_registry_address(deploy_client):
    address = deploy_contract_web3(
        CONTRACT_SECRET_REGISTRY,
        deploy_client,
    )
    return address


@pytest.fixture
def registry_address(deploy_client):
    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_files_cwd([registry_path])
    registry_proxy = deploy_client.deploy_solidity_contract(
        'Registry',
        registry_contracts,
        dict(),
        tuple(),
        contract_path=registry_path,
    )
    return decode_hex(registry_proxy.contract.address)
