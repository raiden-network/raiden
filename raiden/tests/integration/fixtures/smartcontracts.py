import pytest
from eth_utils import to_canonical_address, to_checksum_address

from raiden.network.proxies import SecretRegistry, Token, TokenNetwork, TokenNetworkRegistry
from raiden.tests.utils.smartcontracts import (
    deploy_contract_web3,
    deploy_token,
    deploy_tokens_and_fund_accounts,
)
from raiden.utils import privatekey_to_address, typing
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)


@pytest.fixture(name='token_addresses')
def deploy_all_tokens_register_and_return_their_addresses(
        token_amount,
        number_of_tokens,
        private_keys,
        deploy_service,
        token_network_registry_address,
        register_tokens,
        contract_manager,
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
        token_amount=token_amount,
        number_of_tokens=number_of_tokens,
        deploy_service=deploy_service,
        participants=participants,
        contract_manager=contract_manager,
    )

    if register_tokens:
        for token in token_addresses:
            registry = deploy_service.token_network_registry(token_network_registry_address)
            registry.add_token(token_address=token, given_block_identifier='latest')

    return token_addresses


@pytest.fixture
def endpoint_registry_address(deploy_client, contract_manager) -> typing.Address:
    address = deploy_contract_web3(
        contract_name=CONTRACT_ENDPOINT_REGISTRY,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
    )
    return address


@pytest.fixture(name='secret_registry_address')
def deploy_secret_registry_and_return_address(deploy_client, contract_manager) -> typing.Address:
    address = deploy_contract_web3(
        contract_name=CONTRACT_SECRET_REGISTRY,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
    )
    return address


@pytest.fixture
def secret_registry_proxy(deploy_client, secret_registry_address, contract_manager):
    """This uses the available SecretRegistry JSONRPCClient proxy to
    instantiate a Raiden proxy.

    The JSONRPCClient proxy just exposes the functions from the smart contract
    as methods in a generate python object, the Raiden proxy uses it to
    provider alternative interfaces *and* most importantly to do additional
    error checking (reason for transaction failure, gas usage, etc.).
    """
    return SecretRegistry(
        jsonrpc_client=deploy_client,
        secret_registry_address=to_canonical_address(secret_registry_address),
        contract_manager=contract_manager,
    )


@pytest.fixture(name='token_network_registry_address')
def deploy_token_network_registry_and_return_address(
        deploy_client,
        secret_registry_address,
        chain_id,
        settle_timeout_min,
        settle_timeout_max,
        contract_manager,
) -> typing.Address:
    address = deploy_contract_web3(
        contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        constructor_arguments=(
            to_checksum_address(secret_registry_address),
            chain_id,
            settle_timeout_min,
            settle_timeout_max,
        ),
    )
    return address


@pytest.fixture(name='token_network_proxy')
def register_token_and_return_the_network_proxy(
        contract_manager,
        deploy_client,
        token_proxy,
        token_network_registry_address,
):
    registry_address = to_canonical_address(token_network_registry_address)

    token_network_registry_proxy = TokenNetworkRegistry(
        jsonrpc_client=deploy_client,
        registry_address=registry_address,
        contract_manager=contract_manager,
    )
    token_network_address = token_network_registry_proxy.add_token(
        token_address=token_proxy.address,
        given_block_identifier='latest',
    )

    return TokenNetwork(
        jsonrpc_client=deploy_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )


@pytest.fixture(name='token_proxy')
def deploy_token_and_return_proxy(deploy_client, contract_manager):
    token_contract = deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=10000,
        decimals=0,
        token_name='TKN',
        token_symbol='TKN',
    )

    return Token(
        jsonrpc_client=deploy_client,
        token_address=to_canonical_address(token_contract.contract.address),
        contract_manager=contract_manager,
    )
