import os
import sqlite3

import pytest

from raiden.exceptions import InvalidDBData
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.storage.utils import TimestampedEvent
from raiden.storage.wal import WriteAheadLog, restore_to_state_change
from raiden.tests.utils import factories
from raiden.transfer.architecture import State, StateManager, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.state_change import Block, ContractReceiveChannelBatchUnlock
from raiden.utils import sha3


def state_transition_noop(state, state_change):  # pylint: disable=unused-argument
    return TransitionResult(state, list())


class AccState(State):
    def __init__(self):
        self.state_changes = list()

    def to_dict(self):
        return {
            'state_changes': self.state_changes,
        }

    @classmethod
    def from_dict(cls, data):
        result = cls()
        result.state_changes = data['state_changes']
        return result


def state_transtion_acc(state, state_change):
    state = state or AccState()
    state.state_changes.append(state_change)
    return TransitionResult(state, list())


def new_wal(state_transition):
    state = None
    serializer = JSONSerializer

    state_manager = StateManager(state_transition, state)
    storage = SQLiteStorage(':memory:', serializer)
    wal = WriteAheadLog(state_manager, storage)
    return wal


def test_connect_to_corrupt_db(tmpdir):
    serializer = JSONSerializer
    dbpath = os.path.join(tmpdir, 'log.db')
    with open(dbpath, 'wb') as f:
        f.write(os.urandom(256))

    with pytest.raises(InvalidDBData):
        SQLiteStorage(dbpath, serializer)


def test_wal_has_version():
    wal = new_wal(state_transition_noop)
    assert wal.version == RAIDEN_DB_VERSION
    # Let's make sure that nobody makes a setter for this attribute
    with pytest.raises(AttributeError):
        wal.version = 5


def test_write_read_log():
    wal = new_wal(state_transition_noop)

    block_number = 1337
    block = Block(
        block_number=block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    unlocked_amount = 10
    returned_amount = 5
    participant = factories.make_address()
    partner = factories.make_address()
    locksroot = sha3(b'test_write_read_log')
    contract_receive_unlock = ContractReceiveChannelBatchUnlock(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=factories.make_address(),
        participant=participant,
        partner=partner,
        locksroot=locksroot,
        unlocked_amount=unlocked_amount,
        returned_tokens=returned_amount,
        block_number=block_number,
    )

    state_changes1 = wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    count1 = len(state_changes1)

    wal.log_and_dispatch(block)

    state_changes2 = wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    count2 = len(state_changes2)
    assert count1 + 1 == count2

    wal.log_and_dispatch(contract_receive_unlock)

    state_changes3 = wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    count3 = len(state_changes3)
    assert count2 + 1 == count3

    result1, result2 = state_changes3[-2:]
    assert isinstance(result1, Block)
    assert result1.block_number == block_number

    assert isinstance(result2, ContractReceiveChannelBatchUnlock)
    assert result2.participant == participant
    assert result2.partner == partner
    assert result2.locksroot == locksroot
    assert result2.unlocked_amount == unlocked_amount
    assert result2.returned_tokens == returned_amount

    # Make sure state snapshot can only go for corresponding state change ids
    with pytest.raises(sqlite3.IntegrityError):
        wal.storage.write_state_snapshot(34, 'AAAA')

    # Make sure we can only have a single state snapshot
    assert wal.storage.get_latest_state_snapshot() is None

    wal.storage.write_state_snapshot(1, 'AAAA')
    assert wal.storage.get_latest_state_snapshot() == (1, 'AAAA')

    wal.storage.write_state_snapshot(2, 'BBBB')
    assert wal.storage.get_latest_state_snapshot() == (2, 'BBBB')


def test_timestamped_event():
    event = EventPaymentSentFailed(
        factories.make_payment_network_identifier(),
        factories.make_address(),
        1,
        factories.make_address(),
        'whatever',
    )
    log_time = '2018-09-07T20:02:35.000'

    timestamped = TimestampedEvent(event, log_time)
    assert timestamped.log_time == log_time
    assert timestamped.reason == timestamped.wrapped_event.reason == 'whatever'
    assert timestamped.identifier == 1


def test_write_read_events():
    wal = new_wal(state_transition_noop)

    event = EventPaymentSentFailed(
        factories.make_payment_network_identifier(),
        factories.make_address(),
        1,
        factories.make_address(),
        'whatever',
    )
    event_list = [event]

    with pytest.raises(sqlite3.IntegrityError):
        unexisting_state_change_id = 1
        wal.storage.write_events(
            unexisting_state_change_id,
            event_list,
            '2018-08-31T17:38:00.000',
        )

    previous_events = wal.storage.get_events_with_timestamps()

    log_time = '2018-09-07T20:02:35.0000'
    state_change_id = wal.storage.write_state_change('statechangedata', log_time)
    wal.storage.write_events(
        state_change_id,
        event_list,
        log_time,
    )

    new_events = wal.storage.get_events_with_timestamps()
    assert len(previous_events) + 1 == len(new_events)

    latest_event = new_events[-1]
    assert isinstance(latest_event, TimestampedEvent)
    assert isinstance(latest_event.wrapped_event, EventPaymentSentFailed)
    assert latest_event.log_time == log_time


def test_restore_without_snapshot():
    wal = new_wal(state_transition_noop)

    block1 = Block(
        block_number=5,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block1)

    block2 = Block(
        block_number=7,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block2)

    block3 = Block(
        block_number=8,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block3)

    newwal = restore_to_state_change(
        transition_function=state_transtion_acc,
        storage=wal.storage,
        state_change_identifier='latest',
    )

    aggregate = newwal.state_manager.current_state
    assert aggregate.state_changes == [block1, block2, block3]


def test_get_snapshot_closest_to_state_change():
    wal = new_wal(state_transtion_acc)

    block1 = Block(
        block_number=5,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block1)
    wal.snapshot()

    block2 = Block(
        block_number=7,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block2)
    wal.snapshot()

    block3 = Block(
        block_number=8,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    wal.log_and_dispatch(block3)
    wal.snapshot()

    _, snapshot = wal.storage.get_snapshot_closest_to_state_change('latest')
    assert snapshot.state_changes == [block1, block2, block3]
