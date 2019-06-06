import pytest

from raiden.blockchain.events import Event
from raiden.blockchain_events_handler import (
    create_channel_closed_state_change,
    create_update_transfer_state_change,
)
from raiden.tests.utils import factories
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveRouteClosed,
    ContractReceiveUpdateTransfer,
)
from raiden_contracts.constants import ChannelEvent


@pytest.fixture
def container():
    return factories.make_chain_state(number_of_channels=2)


@pytest.fixture
def event_data(container):
    return dict(
        args=dict(channel_identifier=container.channels[0].identifier),
        block_hash=factories.make_block_hash(),
        block_number=factories.make_block_number(),
        transaction_hash=factories.make_transaction_hash(),
    )


@pytest.fixture
def update_transfer(container, event_data):
    event_data["event"] = ChannelEvent.BALANCE_PROOF_UPDATED
    event_data["args"]["nonce"] = 1
    return Event(originating_contract=container.token_network_address, event_data=event_data)


def test_create_update_transfer_state_change(container, update_transfer):
    state_change = create_update_transfer_state_change(
        chain_state=container.chain_state, event=update_transfer
    )
    assert isinstance(state_change, ContractReceiveUpdateTransfer)


def test_create_update_transfer_state_change_unknown_token_network(container, update_transfer):
    update_transfer.originating_contract = factories.make_token_network_address()
    state_change = create_update_transfer_state_change(
        chain_state=container.chain_state, event=update_transfer
    )
    assert state_change is None


def test_create_update_transfer_state_change_unknown_channel(container, update_transfer):
    update_transfer.event_data["args"]["channel_identifier"] = factories.make_channel_identifier()
    state_change = create_update_transfer_state_change(
        chain_state=container.chain_state, event=update_transfer
    )
    assert state_change is None


@pytest.fixture
def channel_closed(container, event_data):
    event_data["event"] = ChannelEvent.CLOSED
    event_data["args"]["closing_participant"] = factories.make_address()
    return Event(originating_contract=container.token_network_address, event_data=event_data)


def test_create_channel_closed_state_change(container, channel_closed):
    state_change = create_channel_closed_state_change(
        chain_state=container.chain_state, event=channel_closed
    )
    assert isinstance(state_change, ContractReceiveChannelClosed)


def test_create_channel_closed_state_change_unknown_token_network(container, channel_closed):
    channel_closed.originating_contract = factories.make_token_network_address()
    state_change = create_channel_closed_state_change(
        chain_state=container.chain_state, event=channel_closed
    )
    assert isinstance(state_change, ContractReceiveRouteClosed)


def test_create_channel_closed_state_change_unknown_channel(container, channel_closed):
    channel_closed.event_data["args"]["channel_identifier"] = factories.make_channel_identifier()
    state_change = create_channel_closed_state_change(
        chain_state=container.chain_state, event=channel_closed
    )
    assert isinstance(state_change, ContractReceiveRouteClosed)
