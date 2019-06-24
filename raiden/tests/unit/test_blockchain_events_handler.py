from unittest.mock import Mock, patch

import pytest

from raiden.blockchain.events import Event
from raiden.blockchain_events_handler import (
    create_batch_unlock_state_change,
    create_channel_closed_state_change,
    create_channel_new_state_change,
    create_new_balance_state_change,
    create_new_tokennetwork_state_change,
    create_update_transfer_state_change,
)
from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.storage.sqlite import EventRecord, StateChangeRecord
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.events import SendBalanceProof
from raiden.transfer.state_change import (
    BalanceProofStateChange,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveUpdateTransfer,
)
from raiden_contracts.constants import ChannelEvent


@pytest.fixture
def chain_state_setup():
    return factories.make_chain_state(number_of_channels=2)


@pytest.fixture
def event_data(chain_state_setup):
    return dict(
        args=dict(channel_identifier=chain_state_setup.channels[0].identifier),
        block_hash=factories.make_block_hash(),
        block_number=factories.make_block_number(),
        transaction_hash=factories.make_transaction_hash(),
    )


@pytest.fixture
def update_transfer_event(chain_state_setup, event_data):
    event_data["event"] = ChannelEvent.BALANCE_PROOF_UPDATED
    event_data["args"]["nonce"] = 1
    return Event(
        originating_contract=chain_state_setup.token_network_address, event_data=event_data
    )


def test_create_update_transfer_state_change(chain_state_setup, update_transfer_event):
    state_change = create_update_transfer_state_change(
        chain_state=chain_state_setup.chain_state, event=update_transfer_event
    )
    assert isinstance(state_change, ContractReceiveUpdateTransfer)


def test_create_update_transfer_state_change_unknown_token_network(
    chain_state_setup, update_transfer_event
):
    update_transfer_event.originating_contract = factories.make_token_network_address()
    state_change = create_update_transfer_state_change(
        chain_state=chain_state_setup.chain_state, event=update_transfer_event
    )
    assert state_change is None


def test_create_update_transfer_state_change_unknown_channel(
    chain_state_setup, update_transfer_event
):
    update_transfer_event.event_data["args"][
        "channel_identifier"
    ] = factories.make_channel_identifier()
    state_change = create_update_transfer_state_change(
        chain_state=chain_state_setup.chain_state, event=update_transfer_event
    )
    assert state_change is None


@pytest.fixture
def channel_closed_event(chain_state_setup, event_data):
    event_data["event"] = ChannelEvent.CLOSED
    event_data["args"]["closing_participant"] = factories.make_address()
    return Event(
        originating_contract=chain_state_setup.token_network_address, event_data=event_data
    )


def test_create_channel_closed_state_change(chain_state_setup, channel_closed_event):
    state_change = create_channel_closed_state_change(
        chain_state=chain_state_setup.chain_state, event=channel_closed_event
    )
    assert isinstance(state_change, ContractReceiveChannelClosed)


def test_create_channel_closed_state_change_unknown_token_network(
    chain_state_setup, channel_closed_event
):
    channel_closed_event.originating_contract = factories.make_token_network_address()
    state_change = create_channel_closed_state_change(
        chain_state=chain_state_setup.chain_state, event=channel_closed_event
    )
    assert isinstance(state_change, ContractReceiveRouteClosed)


def test_create_channel_closed_state_change_unknown_channel(
    chain_state_setup, channel_closed_event
):
    channel_closed_event.event_data["args"][
        "channel_identifier"
    ] = factories.make_channel_identifier()
    state_change = create_channel_closed_state_change(
        chain_state=chain_state_setup.chain_state, event=channel_closed_event
    )
    assert isinstance(state_change, ContractReceiveRouteClosed)


@pytest.fixture
def unlock_event(chain_state_setup, event_data):
    event_data["event"] = ChannelEvent.UNLOCKED
    event_data["args"] = dict(
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        receiver=factories.make_address(),
        sender=factories.make_address(),
        unlocked_amount=factories.UNIT_TRANSFER_AMOUNT,
        returned_tokens=factories.UNIT_TRANSFER_AMOUNT,
    )
    return Event(
        originating_contract=chain_state_setup.token_network_address, event_data=event_data
    )


def test_create_channel_batch_unlock_state_change_discards_if_not_participant(
    chain_state_setup, unlock_event
):
    address = factories.make_address()
    state_change = create_batch_unlock_state_change(
        chain_state=chain_state_setup.chain_state,
        event=unlock_event,
        our_address=address,
        storage=None,
    )
    assert state_change is None


def test_create_channel_batch_unlock_state_change_as_receiver(chain_state_setup, unlock_event):
    sender = chain_state_setup.channels[1].partner_state.address
    unlock_event.event_data["args"]["sender"] = sender
    receiver = chain_state_setup.channels[1].our_state.address
    unlock_event.event_data["args"]["receiver"] = receiver

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
            chain_state=chain_state_setup.chain_state,
            event=unlock_event,
            our_address=receiver,
            storage=None,
        )
    assert isinstance(state_change, ContractReceiveChannelBatchUnlock)


def test_create_channel_batch_unlock_state_change_as_sender(chain_state_setup, unlock_event):
    sender = chain_state_setup.channels[0].our_state.address
    unlock_event.event_data["args"]["sender"] = sender
    receiver = chain_state_setup.channels[0].partner_state.address
    unlock_event.event_data["args"]["receiver"] = receiver

    last_balance_proof = factories.create(
        factories.BalanceProofProperties(canonical_identifier=factories.UNIT_CANONICAL_ID)
    )
    event_record = EventRecord(
        state_change_identifier=1,
        event_identifier=1,
        data=SendBalanceProof(
            message_identifier=1,
            payment_identifier=1,
            token_address=chain_state_setup.token_address,
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
            chain_state=chain_state_setup.chain_state,
            event=unlock_event,
            our_address=sender,
            storage=None,
        )
    assert isinstance(state_change, ContractReceiveChannelBatchUnlock)


def test_create_new_tokennetwork_state_change(event_data):
    token_address = factories.make_address()
    token_network_address = factories.make_address()
    event_data["args"]["token_address"] = token_address
    event_data["args"]["token_network_address"] = token_network_address

    event = Event(originating_contract=token_network_address, event_data=event_data)
    state_change = create_new_tokennetwork_state_change(event)

    assert state_change.transaction_hash == event_data["transaction_hash"]
    assert state_change.payment_network_address == event.originating_contract
    assert state_change.token_network.network_graph.token_network_address == token_network_address
    assert not state_change.token_network.network_graph.channel_identifier_to_participants


@pytest.fixture
def channel_new_event(event_data):
    event_data["args"]["channel_identifier"] = factories.make_channel_identifier()
    event_data["args"]["participant1"] = factories.make_address()
    event_data["args"]["participant2"] = factories.make_address()

    return Event(originating_contract=factories.make_address(), event_data=event_data)


def test_create_channel_new_state_change_as_participant(channel_new_event):
    chain = Mock(payment_channel=Mock(token_address=factories.make_address()))
    fee_schedule = factories.create(factories.FeeScheduleStateProperties(flat=33))
    channel_state = factories.create(
        factories.NettingChannelStateProperties(fee_schedule=fee_schedule)
    )
    our_address = channel_new_event.event_data["args"]["participant1"]

    with patch("raiden.blockchain_events_handler.get_channel_state", return_value=channel_state):
        state_change, to_health_check, fee_update = create_channel_new_state_change(
            chain=chain,
            chain_id=factories.UNIT_CHAIN_ID,
            our_address=our_address,
            payment_network_address=factories.UNIT_PAYMENT_NETWORK_IDENTIFIER,
            reveal_timeout=factories.UNIT_REVEAL_TIMEOUT,
            fee_schedule=fee_schedule,
            event=channel_new_event,
        )
        assert isinstance(state_change, ContractReceiveChannelNew)
        assert to_health_check == channel_state.partner_state.address
        assert fee_update.canonical_identifier == channel_state.canonical_identifier
        assert fee_update.fee_schedule.flat == 33


def test_create_channel_new_state_change_as_non_participant(channel_new_event):
    chain = Mock(payment_channel=Mock(token_address=factories.make_address()))
    fee_schedule = factories.create(factories.FeeScheduleStateProperties(flat=33))
    channel_state = factories.create(
        factories.NettingChannelStateProperties(fee_schedule=fee_schedule)
    )
    our_address = factories.make_address()

    with patch("raiden.blockchain_events_handler.get_channel_state", return_value=channel_state):
        state_change, to_health_check, fee_update = create_channel_new_state_change(
            chain=chain,
            chain_id=factories.UNIT_CHAIN_ID,
            our_address=our_address,
            payment_network_address=factories.UNIT_PAYMENT_NETWORK_IDENTIFIER,
            reveal_timeout=factories.UNIT_REVEAL_TIMEOUT,
            fee_schedule=fee_schedule,
            event=channel_new_event,
        )
        assert isinstance(state_change, ContractReceiveRouteNew)
        assert to_health_check is None
        assert fee_update is None


@pytest.fixture
def new_balance_event(chain_state_setup, event_data):
    event_data["args"]["participant"] = factories.make_address()
    event_data["args"]["total_deposit"] = 20000

    return Event(
        originating_contract=chain_state_setup.token_network_address, event_data=event_data
    )


def test_create_new_balance_state_change(chain_state_setup, new_balance_event):
    state_change, _ = create_new_balance_state_change(
        chain_state=chain_state_setup.chain_state, event=new_balance_event
    )
    assert isinstance(state_change, ContractReceiveChannelNewBalance)
    assert (
        state_change.canonical_identifier.token_network_address
        == chain_state_setup.token_network_address
    )
    assert (
        state_change.deposit_transaction.participant_address
        == new_balance_event.event_data["args"]["participant"]
    )


def test_create_new_balance_state_change_unknown_channel(chain_state_setup, new_balance_event):
    new_balance_event.event_data["args"][
        "channel_identifier"
    ] = factories.make_channel_identifier()
    state_change, _ = create_new_balance_state_change(
        chain_state=chain_state_setup.chain_state, event=new_balance_event
    )
    assert state_change is None
