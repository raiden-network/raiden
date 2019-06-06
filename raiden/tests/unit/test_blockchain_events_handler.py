from unittest.mock import patch

import pytest

from raiden.blockchain.events import Event
from raiden.blockchain_events_handler import (
    create_batch_unlock_state_change,
    create_channel_closed_state_change,
    create_update_transfer_state_change,
)
from raiden.storage.sqlite import EventRecord, StateChangeRecord
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.events import SendBalanceProof
from raiden.transfer.state_change import (
    BalanceProofStateChange,
    ContractReceiveChannelBatchUnlock,
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


@pytest.fixture
def unlock(container, event_data):
    event_data["event"] = ChannelEvent.UNLOCKED
    event_data["args"] = dict(
        locksroot=factories.EMPTY_MERKLE_ROOT,
        receiver=factories.make_address(),
        sender=factories.make_address(),
        unlocked_amount=factories.UNIT_TRANSFER_AMOUNT,
        returned_tokens=factories.UNIT_TRANSFER_AMOUNT,
    )
    return Event(originating_contract=container.token_network_address, event_data=event_data)


def test_create_channel_batch_unlock_state_change_discards_if_not_participant(container, unlock):
    address = factories.make_address()
    state_change = create_batch_unlock_state_change(
        chain_state=container.chain_state, event=unlock, our_address=address, storage=None
    )
    assert state_change is None


def test_create_channel_batch_unlock_state_change_as_receiver(container, unlock):
    sender = container.channels[1].partner_state.address
    unlock.event_data["args"]["sender"] = sender
    receiver = container.channels[1].our_state.address
    unlock.event_data["args"]["receiver"] = receiver

    last_balance_proof = factories.create(
        factories.BalanceProofSignedStateProperties(
            canonical_identifier=factories.UNIT_CANONICAL_ID
        )
    )
    state_change_record = StateChangeRecord(
        state_change_identifier=1,
        data=BalanceProofStateChange(sender=receiver, balance_proof=last_balance_proof),
    )

    with patch(
        "raiden.blockchain_events_handler.get_state_change_with_balance_proof_by_locksroot",
        return_value=state_change_record,
    ):
        state_change = create_batch_unlock_state_change(
            chain_state=container.chain_state, event=unlock, our_address=receiver, storage=None
        )
    assert isinstance(state_change, ContractReceiveChannelBatchUnlock)


def test_create_channel_batch_unlock_state_change_as_sender(container, unlock):
    sender = container.channels[0].our_state.address
    unlock.event_data["args"]["sender"] = sender
    receiver = container.channels[0].partner_state.address
    unlock.event_data["args"]["receiver"] = receiver

    last_balance_proof = factories.create(
        factories.BalanceProofProperties(canonical_identifier=factories.UNIT_CANONICAL_ID)
    )
    event_record = EventRecord(
        state_change_identifier=1,
        event_identifier=1,
        data=SendBalanceProof(
            message_identifier=1,
            payment_identifier=1,
            token_address=container.token_address,
            balance_proof=last_balance_proof,
            secret=factories.make_secret(),
            canonical_identifier=factories.UNIT_CANONICAL_ID,
            recipient=receiver,
        ),
    )

    with patch(
        "raiden.blockchain_events_handler.get_event_with_balance_proof_by_locksroot",
        return_value=event_record,
    ):
        state_change = create_batch_unlock_state_change(
            chain_state=container.chain_state, event=unlock, our_address=sender, storage=None
        )
    assert isinstance(state_change, ContractReceiveChannelBatchUnlock)
