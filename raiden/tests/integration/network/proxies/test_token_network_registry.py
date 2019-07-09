from unittest.mock import patch

import pytest
from eth_utils import is_same_address, to_canonical_address

from raiden.constants import (
    RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
    RED_EYES_PER_TOKEN_NETWORK_LIMIT,
)
from raiden.exceptions import AddressWithoutCode, InvalidToken, RaidenRecoverableError
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.token import Token
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.smartcontracts import deploy_token
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MAX, TEST_SETTLE_TIMEOUT_MIN


def test_token_network_registry(
    deploy_client, contract_manager, token_network_registry_address, token_contract_name
):
    registry_address = to_canonical_address(token_network_registry_address)

    blockchain_service = BlockChainService(
        jsonrpc_client=deploy_client, contract_manager=contract_manager
    )

    token_network_registry_proxy = TokenNetworkRegistry(
        jsonrpc_client=deploy_client,
        registry_address=registry_address,
        contract_manager=contract_manager,
        blockchain_service=blockchain_service,
    )

    assert token_network_registry_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_registry_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

    bad_token_address = make_address()
    # try to register non-existing token network
    with pytest.raises(AddressWithoutCode):
        token_network_registry_proxy.add_token_with_limits(
            token_address=bad_token_address,
            channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
            token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
        )
    # create token network & register it
    test_token = deploy_token(
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        initial_amount=1000,
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
        token_contract_name=token_contract_name,
    )

    test_token_address = to_canonical_address(test_token.contract.address)
    # try to register a token network not following ERC20 protocol

    with patch.object(Token, "total_supply", return_value=""):
        with pytest.raises(InvalidToken):
            token_network_registry_proxy.add_token_with_limits(
                token_address=test_token_address,
                channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
                token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
            )

    event_filter = token_network_registry_proxy.tokenadded_filter()
    token_network_address = token_network_registry_proxy.add_token_with_limits(
        token_address=test_token_address,
        channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
        token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
    )

    with pytest.raises(RaidenRecoverableError) as exc:
        token_network_address = token_network_registry_proxy.add_token_with_limits(
            token_address=test_token_address,
            channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
            token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
        )

        assert "Token already registered" in str(exc)

    logs = event_filter.get_all_entries()
    assert len(logs) == 1
    decoded_event = token_network_registry_proxy.proxy.decode_event(logs[0])
    assert is_same_address(decoded_event["args"]["token_address"], test_token.contract.address)
    assert is_same_address(decoded_event["args"]["token_network_address"], token_network_address)
    # test other getters
    assert token_network_registry_proxy.get_token_network(bad_token_address) is None
    assert is_same_address(
        token_network_registry_proxy.get_token_network(test_token_address), token_network_address
    )

    with pytest.raises(ValueError):
        assert token_network_registry_proxy.get_token_network(None) is None

    assert token_network_registry_proxy.get_token_network(bad_token_address) is None
    assert token_network_registry_proxy.get_token_network(token_network_address) is None
    assert token_network_registry_proxy.get_token_network(test_token_address) is not None
