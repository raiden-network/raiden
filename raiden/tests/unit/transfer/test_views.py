import pytest

from raiden.tests.utils import factories
from raiden.transfer.views import (
    count_token_network_channels,
    filter_channels_by_partneraddress,
    filter_channels_by_status,
    get_participants_addresses,
    get_token_identifiers,
    get_token_network_identifiers,
    get_token_network_registry_by_token_network_identifier,
    role_from_transfer_task,
)


def test_filter_channels_by_partneraddress_empty(chain_state):
    payment_network_id = factories.make_address()
    token_address = factories.make_address()
    partner_addresses = [factories.make_address(), factories.make_address()]
    assert (
        filter_channels_by_partneraddress(
            chain_state=chain_state,
            payment_network_id=payment_network_id,
            token_address=token_address,
            partner_addresses=partner_addresses,
        )
        == []
    )


def test_filter_channels_by_status_empty_excludes():
    channel_states = factories.make_channel_set(number_of_channels=3).channels
    channel_states[1].close_transaction = channel_states[1].open_transaction
    channel_states[2].close_transaction = channel_states[2].open_transaction
    channel_states[2].settle_transaction = channel_states[2].open_transaction
    assert (
        filter_channels_by_status(channel_states=channel_states, exclude_states=None)
        == channel_states
    )


def test_count_token_network_channels_no_token_network(chain_state):
    assert (
        count_token_network_channels(
            chain_state=chain_state,
            payment_network_id=factories.make_address(),
            token_address=factories.make_address(),
        )
        == 0
    )


def test_get_participants_addresses_no_token_network(chain_state):
    assert (
        get_participants_addresses(
            chain_state=chain_state,
            payment_network_id=factories.make_address(),
            token_address=factories.make_address(),
        )
        == set()
    )


def test_get_token_network_registry_by_token_network_identifier_is_none(chain_state):
    assert (
        get_token_network_registry_by_token_network_identifier(
            chain_state=chain_state, token_network_identifier=factories.make_address()
        )
        is None
    )


def test_get_token_network_identifiers_empty_list_for_payment_network_none(chain_state):
    assert (
        get_token_network_identifiers(
            chain_state=chain_state, payment_network_id=factories.make_address()
        )
        == list()
    )


def test_token_identifiers_empty_list_for_payment_network_none(chain_state):
    assert (
        get_token_identifiers(chain_state=chain_state, payment_network_id=factories.make_address())
        == list()
    )


def test_role_from_transfer_task_raises_value_error():
    with pytest.raises(ValueError):
        role_from_transfer_task(object())
