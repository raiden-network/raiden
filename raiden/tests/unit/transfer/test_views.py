from raiden.tests.utils import factories
from raiden.transfer.views import (
    count_token_network_channels,
    filter_channels_by_partneraddress,
    filter_channels_by_status,
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
