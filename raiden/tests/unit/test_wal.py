import os
import random
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

import pytest
import ulid

from raiden.constants import RAIDEN_DB_VERSION
from raiden.exceptions import InvalidDBData
from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import (
    HIGH_STATECHANGE_ULID,
    LOW_STATECHANGE_ULID,
    RANGE_ALL_STATE_CHANGES,
    SerializedSQLiteStorage,
    StateChangeID,
)
from raiden.storage.utils import TimestampedEvent
from raiden.storage.wal import WriteAheadLog, restore_state
from raiden.tests.utils.factories import (
    make_address,
    make_block_hash,
    make_canonical_identifier,
    make_locksroot,
    make_token_network_registry_address,
    make_transaction_hash,
)
from raiden.transfer.architecture import State, StateChange, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.state_change import Block, ContractReceiveChannelBatchUnlock
from raiden.utils.typing import BlockGasLimit, BlockNumber, Callable, List, TokenAmount


class Empty(State):
    pass


def state_transition_noop(state, state_change):  # pylint: disable=unused-argument
    return TransitionResult(Empty(), [])


@dataclass
class AccState(State):
    state_changes: List[Block] = field(default_factory=list)


def state_transtion_acc(state, state_change):
    state = state
    state.state_changes.append(state_change)
    return TransitionResult(state, [])


def new_wal(state_transition: Callable, state: State = None) -> WriteAheadLog:
    serializer = JSONSerializer()
    state = state or Empty()

    storage = SerializedSQLiteStorage(":memory:", serializer)
    storage.write_first_state_snapshot(state)

    return WriteAheadLog(state, storage, state_transition)


def dispatch(wal: WriteAheadLog, state_changes: List[StateChange]):
    with wal.process_state_change_atomically() as dispatcher:
        for state_change in state_changes:
            dispatcher.dispatch(state_change)


def test_initial_state_snapshotting():
    serializer = JSONSerializer()
    state = Empty()

    storage = SerializedSQLiteStorage(":memory:", serializer)

    assert not storage.database.has_snapshot()
    assert not storage.get_snapshot_before_state_change(LOW_STATECHANGE_ULID)
    storage.write_first_state_snapshot(state)
    assert storage.database.has_snapshot()
    assert storage.get_snapshot_before_state_change(LOW_STATECHANGE_ULID)


def test_connect_to_corrupt_db(tmpdir):
    serializer = JSONSerializer
    dbpath = os.path.join(tmpdir, "log.db")
    with open(dbpath, "wb") as f:
        f.write(os.urandom(256))

    with pytest.raises(InvalidDBData):
        SerializedSQLiteStorage(dbpath, serializer)


def test_wal_has_version():
    wal = new_wal(state_transition_noop)
    assert wal.version == RAIDEN_DB_VERSION
    # Let's make sure that nobody makes a setter for this attribute
    with pytest.raises(AttributeError):
        wal.version = 5


def test_write_read_log() -> None:
    wal = new_wal(state_transition_noop)

    block_number = BlockNumber(1337)
    block_hash = make_block_hash()
    block = Block(block_number=block_number, gas_limit=BlockGasLimit(1), block_hash=block_hash)
    unlocked_amount = TokenAmount(10)
    returned_amount = TokenAmount(5)
    participant = make_address()
    partner = make_address()
    locksroot = make_locksroot()
    contract_receive_unlock = ContractReceiveChannelBatchUnlock(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=make_canonical_identifier(token_network_address=make_address()),
        receiver=participant,
        sender=partner,
        locksroot=locksroot,
        unlocked_amount=unlocked_amount,
        returned_tokens=returned_amount,
        block_number=block_number,
        block_hash=block_hash,
    )

    state_changes1 = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    count1 = len(state_changes1)

    dispatch(wal, [block])

    state_changes2 = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    count2 = len(state_changes2)
    assert count1 + 1 == count2

    dispatch(wal, [contract_receive_unlock])

    state_changes3 = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    count3 = len(state_changes3)
    assert count2 + 1 == count3

    result1, result2 = state_changes3[-2:]
    assert isinstance(result1, Block)
    assert result1.block_number == block_number

    assert isinstance(result2, ContractReceiveChannelBatchUnlock)
    assert result2.receiver == participant
    assert result2.sender == partner
    assert result2.locksroot == locksroot
    assert result2.unlocked_amount == unlocked_amount
    assert result2.returned_tokens == returned_amount

    # Make sure state snapshot can only go for corresponding state change ids
    with pytest.raises(sqlite3.IntegrityError):
        wal.storage.write_state_snapshot(State(), StateChangeID(ulid.new()), 1)


def test_timestamped_event():
    event = EventPaymentSentFailed(
        make_token_network_registry_address(), make_address(), 1, make_address(), "whatever"
    )
    log_time = datetime.fromisoformat("2018-09-07T20:02:35.000")

    timestamped = TimestampedEvent(event, log_time)
    assert timestamped.log_time == log_time
    assert isinstance(timestamped.event, EventPaymentSentFailed)
    assert (
        timestamped.reason == timestamped.event.reason == "whatever"  # pylint: disable=no-member
    )
    assert timestamped.identifier == timestamped.event.identifier == 1  # pylint: disable=no-member


def test_write_read_events():
    wal = new_wal(state_transition_noop)

    event = EventPaymentSentFailed(
        make_token_network_registry_address(), make_address(), 1, make_address(), "whatever"
    )

    with pytest.raises(sqlite3.IntegrityError):
        unexisting_state_change_id = random.getrandbits(16 * 8).to_bytes(16, "big")
        wal.storage.write_events([(unexisting_state_change_id, event)])

    previous_events = wal.storage.get_events_with_timestamps()

    state_change_ids = wal.storage.write_state_changes([StateChange()])
    wal.storage.write_events([(state_change_ids[0], event)])

    new_events = wal.storage.get_events_with_timestamps()
    assert len(previous_events) + 1 == len(new_events)

    latest_event = new_events[-1]
    assert isinstance(latest_event, TimestampedEvent)
    assert isinstance(latest_event.event, EventPaymentSentFailed)


def test_restore_without_snapshot():
    wal = new_wal(state_transition_noop, AccState())

    block1 = Block(block_number=5, gas_limit=1, block_hash=make_transaction_hash())
    dispatch(wal, [block1])

    block2 = Block(block_number=7, gas_limit=1, block_hash=make_transaction_hash())
    dispatch(wal, [block2])

    block3 = Block(block_number=8, gas_limit=1, block_hash=make_transaction_hash())
    dispatch(wal, [block3])

    aggregate = restore_state(
        transition_function=state_transtion_acc,
        storage=wal.storage,
        state_change_identifier=HIGH_STATECHANGE_ULID,
        node_address=make_address(),
    )

    assert aggregate.state_changes == [block1, block2, block3]


def test_restore_without_snapshot_in_batches():
    wal = new_wal(state_transition_noop, AccState())

    block1 = Block(block_number=5, gas_limit=1, block_hash=make_transaction_hash())
    block2 = Block(block_number=7, gas_limit=1, block_hash=make_transaction_hash())
    block3 = Block(block_number=8, gas_limit=1, block_hash=make_transaction_hash())
    dispatch(wal, [block1, block2, block3])

    aggregate = restore_state(
        transition_function=state_transtion_acc,
        storage=wal.storage,
        state_change_identifier=HIGH_STATECHANGE_ULID,
        node_address=make_address(),
    )

    assert aggregate.state_changes == [block1, block2, block3]


def test_get_snapshot_before_state_change() -> None:
    wal = new_wal(state_transtion_acc, AccState())

    block1 = Block(
        block_number=BlockNumber(5), gas_limit=BlockGasLimit(1), block_hash=make_block_hash()
    )
    dispatch(wal, [block1])
    wal.snapshot(1)

    block2 = Block(
        block_number=BlockNumber(7), gas_limit=BlockGasLimit(1), block_hash=make_block_hash()
    )
    dispatch(wal, [block2])
    wal.snapshot(2)

    block3 = Block(
        block_number=BlockNumber(8), gas_limit=BlockGasLimit(1), block_hash=make_block_hash()
    )
    dispatch(wal, [block3])
    wal.snapshot(3)

    snapshot = wal.storage.get_snapshot_before_state_change(HIGH_STATECHANGE_ULID)
    assert snapshot and snapshot.data == AccState([block1, block2, block3])
