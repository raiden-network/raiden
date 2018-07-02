import pytest
from raiden.exceptions import (
    TransactionThrew,
    InvalidAddress,
    AddressWithoutCode,
    NoTokenManager,
)
from raiden.tests.utils.factories import make_address
from eth_utils import is_same_address, to_canonical_address


def test_network_registry(token_network_registry_proxy, deploy_token):
    bad_token_address = make_address()
    # try to register non-existing token network
    with pytest.raises(TransactionThrew):
        token_network_registry_proxy.add_token(bad_token_address)
    # create token network & register it
    test_token = deploy_token(1000, 0, 'TKN', 'TKN')
    test_token_address = to_canonical_address(test_token.contract.address)
    event_filter = token_network_registry_proxy.tokenadded_filter()
    token_network_address = token_network_registry_proxy.add_token(
        test_token_address,
    )
    logs = event_filter.get_all_entries()
    assert len(logs) == 1
    decoded_event = token_network_registry_proxy.proxy.decode_event(logs[0])
    assert is_same_address(decoded_event['args']['token_address'], test_token.contract.address)
    assert is_same_address(
        decoded_event['args']['token_network_address'],
        token_network_address,
    )
    # test other getters
    assert token_network_registry_proxy.get_token_network(bad_token_address) is None
    assert is_same_address(
        token_network_registry_proxy.get_token_network(test_token_address),
        token_network_address,
    )

    with pytest.raises(AddressWithoutCode):
        token_network_registry_proxy.token_network_by_token(bad_token_address)
    with pytest.raises(InvalidAddress):
        token_network_registry_proxy.token_network_by_token(None)
    with pytest.raises(NoTokenManager):
        token_network_registry_proxy.token_network_by_token(token_network_address)
    token_manager = token_network_registry_proxy.token_network_by_token(
        test_token_address,
    )
    assert token_manager is not None
