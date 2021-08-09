from unittest.mock import patch

import pytest
from eth_utils import is_same_address, to_canonical_address, to_normalized_address

from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER, NULL_ADDRESS_BYTES, UINT256_MAX
from raiden.exceptions import (
    AddressWithoutCode,
    InvalidToken,
    InvalidTokenAddress,
    MaxTokenNetworkNumberReached,
    RaidenRecoverableError,
)
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.proxies.token import Token
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.factories import make_token_address
from raiden.tests.utils.smartcontracts import deploy_token
from raiden.utils.typing import TokenAddress, TokenAmount, TokenNetworkRegistryAddress
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MAX, TEST_SETTLE_TIMEOUT_MIN
from raiden_contracts.contract_manager import ContractManager


# Disable the default tokens
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("register_tokens", [False])
def test_token_network_registry(
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_contract_name: str,
) -> None:
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )

    confirmed_block_identifier = deploy_client.get_confirmed_blockhash()

    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address, block_identifier=confirmed_block_identifier
    )

    assert (
        token_network_registry_proxy.settlement_timeout_min(BLOCK_ID_LATEST)
        == TEST_SETTLE_TIMEOUT_MIN
    )
    assert (
        token_network_registry_proxy.settlement_timeout_max(BLOCK_ID_LATEST)
        == TEST_SETTLE_TIMEOUT_MAX
    )
    assert (
        token_network_registry_proxy.get_token_network_created(block_identifier=BLOCK_ID_LATEST)
        == 0
    )

    bad_token_address = make_token_address()

    # Registering a non-existing token network should fail
    with pytest.raises(AddressWithoutCode):
        token_network_registry_proxy.add_token(
            token_address=bad_token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            given_block_identifier=confirmed_block_identifier,
        )

    test_token = deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=TokenAmount(1000),
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
        token_contract_name=token_contract_name,
    )
    test_token_address = TokenAddress(to_canonical_address(test_token.address))

    # Check the proper exception is raised if the token does not comply to the
    # ERC20 interface. In this case the token does not have the totalSupply()
    # function implemented #3697 which is validated in the smart contract.
    with patch.object(Token, "total_supply", return_value=None):
        with pytest.raises(InvalidToken):
            token_network_registry_proxy.add_token(
                token_address=test_token_address,
                channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
                token_network_deposit_limit=TokenAmount(UINT256_MAX),
                given_block_identifier=deploy_client.get_confirmed_blockhash(),
            )

    # Register a valid token
    preblockhash = deploy_client.get_confirmed_blockhash()
    _, token_network_address = token_network_registry_proxy.add_token(
        token_address=test_token_address,
        channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
        given_block_identifier=preblockhash,
    )
    assert token_network_address is not None
    assert (
        token_network_registry_proxy.get_token_network_created(block_identifier=BLOCK_ID_LATEST)
        == 1
    )

    # Re-registering the same token should fail with a recoverable error
    # because it is a race condition.
    with pytest.raises(RaidenRecoverableError):
        token_network_registry_proxy.add_token(
            token_address=test_token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            given_block_identifier=preblockhash,
        )

    logs = token_network_registry_proxy.filter_token_added_events()
    assert is_same_address(logs[0]["args"]["token_address"], test_token.address)
    assert is_same_address(logs[0]["args"]["token_network_address"], token_network_address)
    assert (
        token_network_registry_proxy.get_token_network(bad_token_address, BLOCK_ID_LATEST) is None
    )

    result_address = token_network_registry_proxy.get_token_network(
        test_token_address, BLOCK_ID_LATEST
    )

    assert result_address
    assert to_normalized_address(result_address) == to_normalized_address(token_network_address)

    with pytest.raises(ValueError):
        assert token_network_registry_proxy.get_token_network(
            None, BLOCK_ID_LATEST  # type: ignore
        )

    # These are not registered token addresses
    assert (
        token_network_registry_proxy.get_token_network(bad_token_address, BLOCK_ID_LATEST) is None
    )
    assert (
        token_network_registry_proxy.get_token_network(test_token_address, BLOCK_ID_LATEST)
        is not None
    )
    address = token_network_registry_proxy.get_token_network(
        TokenAddress(token_network_address), BLOCK_ID_LATEST
    )
    assert address is None


def test_token_network_registry_max_token_networks(
    deploy_client, token_network_registry_address, contract_manager
):
    """get_max_token_networks() should return an integer"""
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    confirmed_block_identifier = deploy_client.get_confirmed_blockhash()
    token_network_registry_proxy = proxy_manager.token_network_registry(
        to_canonical_address(token_network_registry_address),
        block_identifier=confirmed_block_identifier,
    )
    assert (
        token_network_registry_proxy.get_max_token_networks(block_identifier=BLOCK_ID_LATEST)
        == UINT256_MAX - 1
    )


def test_token_network_registry_with_zero_token_address(
    deploy_client, token_network_registry_address, contract_manager
):
    """Try to register a token at 0x0000..00"""
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    confirmed_block_identifier = deploy_client.get_confirmed_blockhash()
    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address, block_identifier=confirmed_block_identifier
    )
    with pytest.raises(InvalidTokenAddress, match="0x00..00 will fail"):
        token_network_registry_proxy.add_token(
            token_address=NULL_ADDRESS_BYTES,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            given_block_identifier=deploy_client.get_confirmed_blockhash(),
        )


@pytest.mark.parametrize("max_token_networks", [1])
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("register_tokens", [False])
def test_token_network_registry_allows_the_last_slot_to_be_used(
    deploy_client, token_network_registry_address, contract_manager, token_contract_name
):
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    confirmed_block_identifier = deploy_client.get_confirmed_blockhash()

    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address, block_identifier=confirmed_block_identifier
    )

    assert (
        token_network_registry_proxy.get_token_network_created(block_identifier=BLOCK_ID_LATEST)
        == 0
    )

    test_token = deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=TokenAmount(1000),
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
        token_contract_name=token_contract_name,
    )
    first_token_address = TokenAddress(to_canonical_address(test_token.address))
    preblockhash = deploy_client.get_confirmed_blockhash()

    # Register a valid token, this is the last slot and should succeeded
    token_network_registry_proxy.add_token(
        token_address=first_token_address,
        channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
        given_block_identifier=preblockhash,
    )

    test_token = deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=TokenAmount(1000),
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
        token_contract_name=token_contract_name,
    )
    second_token_address = TokenAddress(to_canonical_address(test_token.address))
    preblockhash = deploy_client.get_confirmed_blockhash()

    # Tries to register a new valid token after all slots have been used. This
    # has to fail.
    with pytest.raises(MaxTokenNetworkNumberReached):
        token_network_registry_proxy.add_token(
            token_address=second_token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            given_block_identifier=preblockhash,
        )
