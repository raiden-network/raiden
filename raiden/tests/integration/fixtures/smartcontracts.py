import pytest
from eth_utils import to_checksum_address

from raiden.tests.utils.smartcontracts import deploy_contract_web3, deploy_tokens_and_fund_accounts
from raiden.utils import privatekey_to_address, typing
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)


@pytest.fixture
def token_addresses(
        token_amount,
        number_of_tokens,
        private_keys,
        deploy_service,
        token_network_registry_address,
        register_tokens,
) -> typing.List[typing.Address]:
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
            deploy_service.token_network_registry(token_network_registry_address).add_token(token)

    return token_addresses


@pytest.fixture
def endpoint_registry_address(deploy_client) -> typing.Address:
    address = deploy_contract_web3(
        CONTRACT_ENDPOINT_REGISTRY,
        deploy_client,
        num_confirmations=None,
    )
    return address


@pytest.fixture
def secret_registry_address(deploy_client) -> typing.Address:
    address = deploy_contract_web3(
        CONTRACT_SECRET_REGISTRY,
        deploy_client,
        num_confirmations=None,
    )
    return address


@pytest.fixture
def token_network_registry_address(
        deploy_client,
        secret_registry_address,
        chain_id,
        settle_timeout_min,
        settle_timeout_max,
) -> typing.Address:
    address = deploy_contract_web3(
        CONTRACT_TOKEN_NETWORK_REGISTRY,
        deploy_client,
        num_confirmations=None,
        constructor_arguments=(
            to_checksum_address(secret_registry_address),
            chain_id,
            settle_timeout_min,
            settle_timeout_max,
        ),
    )
    return address
