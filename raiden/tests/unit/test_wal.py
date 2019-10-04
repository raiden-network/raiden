import os
import random
import sqlite3
from dataclasses import dataclass, field

import pytest

from raiden.constants import RAIDEN_DB_VERSION
from raiden.exceptions import InvalidDBData
from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import (
    HIGH_STATECHANGE_ULID,
    RANGE_ALL_STATE_CHANGES,
    SerializedSQLiteStorage,
)
from raiden.storage.utils import TimestampedEvent
from raiden.storage.wal import WriteAheadLog, restore_to_state_change
from raiden.tests.utils.factories import (
    make_address,
    make_canonical_identifier,
    make_token_network_registry_address,
    make_transaction_hash,
)
from raiden.transfer.architecture import State, StateChange, StateManager, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.state_change import Block, ContractReceiveChannelBatchUnlock
from raiden.utils import sha3
from raiden.utils.typing import Callable, List


class Empty(State):
    pass


def state_transition_noop(state, state_change):  # pylint: disable=unused-argument
    return TransitionResult(Empty(), list())


@dataclass
class AccState(State):
    state_changes: List[Block] = field(default_factory=list)


def state_transtion_acc(state, state_change):
    state = state or AccState()
    state.state_changes.append(state_change)
    return TransitionResult(state, list())


def new_wal(state_transition: Callable, state: State = None) -> WriteAheadLog:
    serializer = JSONSerializer()

    state_manager = StateManager(state_transition, state)
    storage = SerializedSQLiteStorage(":memory:", serializer)
    wal = WriteAheadLog(state_manager, storage)
    return wal


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


def test_write_read_log():
    wal = new_wal(state_transition_noop)

    block_number = 1337
    block_hash = make_transaction_hash()
    block = Block(block_number=block_number, gas_limit=1, block_hash=block_hash)
    unlocked_amount = 10
    returned_amount = 5
    participant = make_address()
    partner = make_address()
    locksroot = sha3(b"test_write_read_log")
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

    wal.log_and_dispatch([block])

    state_changes2 = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    count2 = len(state_changes2)
    assert count1 + 1 == count2

    wal.log_and_dispatch([contract_receive_unlock])

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
        wal.storage.write_state_snapshot(State(), "AAAA")


def test_timestamped_event():
    event = EventPaymentSentFailed(
        make_token_network_registry_address(), make_address(), 1, make_address(), "whatever"
    )
    log_time = "2018-09-07T20:02:35.000"

    timestamped = TimestampedEvent(event, log_time)
    assert timestamped.log_time == log_time
    assert timestamped.reason == timestamped.wrapped_event.reason == "whatever"
    assert timestamped.identifier == 1


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
    assert isinstance(latest_event.wrapped_event, EventPaymentSentFailed)


def test_restore_without_snapshot():
    wal = new_wal(state_transition_noop)

    block1 = Block(block_number=5, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block1])

    block2 = Block(block_number=7, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block2])

    block3 = Block(block_number=8, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block3])

    newwal = restore_to_state_change(
        transition_function=state_transtion_acc,
        storage=wal.storage,
        state_change_identifier=HIGH_STATECHANGE_ULID,
        node_address=make_address(),
    )

    aggregate = newwal.state_manager.current_state
    assert aggregate.state_changes == [block1, block2, block3]


def test_restore_without_snapshot_in_batches():
    wal = new_wal(state_transition_noop)

    block1 = Block(block_number=5, gas_limit=1, block_hash=make_transaction_hash())
    block2 = Block(block_number=7, gas_limit=1, block_hash=make_transaction_hash())
    block3 = Block(block_number=8, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block1, block2, block3])

    newwal = restore_to_state_change(
        transition_function=state_transtion_acc,
        storage=wal.storage,
        state_change_identifier=HIGH_STATECHANGE_ULID,
        node_address=make_address(),
    )

    aggregate = newwal.state_manager.current_state
    assert aggregate.state_changes == [block1, block2, block3]


def test_get_snapshot_before_state_change():
    wal = new_wal(state_transtion_acc)

    block1 = Block(block_number=5, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block1])
    wal.snapshot()

    block2 = Block(block_number=7, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block2])
    wal.snapshot()

    block3 = Block(block_number=8, gas_limit=1, block_hash=make_transaction_hash())
    wal.log_and_dispatch([block3])
    wal.snapshot()

    snapshot = wal.storage.get_snapshot_before_state_change(HIGH_STATECHANGE_ULID)
    assert snapshot.data == AccState([block1, block2, block3])
