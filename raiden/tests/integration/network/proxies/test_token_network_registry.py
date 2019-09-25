from unittest.mock import patch

import pytest
from eth_utils import is_same_address, to_canonical_address, to_normalized_address

from raiden.constants import GENESIS_BLOCK_NUMBER, NULL_ADDRESS_BYTES, UINT256_MAX
from raiden.exceptions import (
    AddressWithoutCode,
    InvalidToken,
    InvalidTokenAddress,
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

    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address
    )

    assert token_network_registry_proxy.settlement_timeout_min("latest") == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_registry_proxy.settlement_timeout_max("latest") == TEST_SETTLE_TIMEOUT_MAX
    assert token_network_registry_proxy.get_token_network_created(block_identifier="latest") == 0

    bad_token_address = make_token_address()

    # Registering a non-existing token network should fail
    with pytest.raises(AddressWithoutCode):
        token_network_registry_proxy.add_token(
            token_address=bad_token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            block_identifier=deploy_client.get_confirmed_blockhash(),
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
    test_token_address = TokenAddress(to_canonical_address(test_token.contract.address))

    # Check the proper exception is raised if the token does not comply to the
    # ERC20 interface. In this case the token does not have the totalSupply()
    # function implemented #3697 which is validated in the smart contract.
    with patch.object(Token, "total_supply", return_value=""):
        with pytest.raises(InvalidToken):
            token_network_registry_proxy.add_token(
                token_address=test_token_address,
                channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
                token_network_deposit_limit=TokenAmount(UINT256_MAX),
                block_identifier=deploy_client.get_confirmed_blockhash(),
            )

    # Register a valid token
    event_filter = token_network_registry_proxy.tokenadded_filter()
    preblockhash = deploy_client.get_confirmed_blockhash()
    token_network_address = token_network_registry_proxy.add_token(
        token_address=test_token_address,
        channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
        block_identifier=preblockhash,
    )
    assert token_network_address
    assert token_network_registry_proxy.get_token_network_created(block_identifier="latest") == 1

    # Re-registering the same token should fail with a recoverable error
    # because it is a race condition.
    with pytest.raises(RaidenRecoverableError):
        token_network_registry_proxy.add_token(
            token_address=test_token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            block_identifier=preblockhash,
        )

    logs = event_filter.get_all_entries()
    assert len(logs) == 1
    decoded_event = token_network_registry_proxy.proxy.decode_event(logs[0])
    assert is_same_address(decoded_event["args"]["token_address"], test_token.contract.address)
    assert is_same_address(decoded_event["args"]["token_network_address"], token_network_address)
    assert token_network_registry_proxy.get_token_network(bad_token_address, "latest") is None

    result_address = token_network_registry_proxy.get_token_network(test_token_address, "latest")

    assert result_address
    assert to_normalized_address(result_address) == to_normalized_address(token_network_address)

    with pytest.raises(ValueError):
        assert token_network_registry_proxy.get_token_network(None, "latest")  # type: ignore

    # These are not registered token addresses
    assert token_network_registry_proxy.get_token_network(bad_token_address, "latest") is None
    assert token_network_registry_proxy.get_token_network(test_token_address, "latest") is not None
    address = token_network_registry_proxy.get_token_network(  # type: ignore
        token_network_address, "latest"
    )
    assert address is None


def test_token_network_registry_max_token_networks(
    deploy_client, token_network_registry_address, contract_manager
):
    """ get_max_token_networks() should return an integer """
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    token_network_registry_proxy = proxy_manager.token_network_registry(
        to_canonical_address(token_network_registry_address)
    )
    assert (
        token_network_registry_proxy.get_max_token_networks(block_identifier="latest")
        == UINT256_MAX
    )


def test_token_network_registry_with_zero_token_address(
    deploy_client, token_network_registry_address, contract_manager
):
    """ Try to register a token at 0x0000..00 """
    proxy_manager = ProxyManager(
        rpc_client=deploy_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address
    )
    with pytest.raises(InvalidTokenAddress, match="0x00..00 will fail"):
        token_network_registry_proxy.add_token(
            token_address=NULL_ADDRESS_BYTES,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            block_identifier=deploy_client.get_confirmed_blockhash(),
        )
