import os
import sqlite3

import pytest

from raiden.exceptions import InvalidDBData
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.storage.wal import WriteAheadLog, restore_from_latest_snapshot
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


def state_transtion_acc(state, state_change):
    state = state or AccState()
    state.state_changes.append(state_change)
    return TransitionResult(state, list())


def new_wal():
    state = None
    serializer = JSONSerializer

    state_manager = StateManager(state_transition_noop, state)
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
    wal = new_wal()
    assert wal.version == RAIDEN_DB_VERSION
    # Let's make sure that nobody makes a setter for this attribute
    with pytest.raises(AttributeError):
        wal.version = 5


def test_write_read_log():
    wal = new_wal()

    block_number = 1337
    block = Block(block_number)
    unlocked_amount = 10
    returned_amount = 5
    participant = factories.make_address()
    partner = factories.make_address()
    locksroot = sha3(b'test_write_read_log')
    contract_receive_unlock = ContractReceiveChannelBatchUnlock(
        factories.make_transaction_hash(),
        factories.make_address(),
        participant,
        partner,
        locksroot,
        unlocked_amount,
        returned_amount,
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


def test_write_read_events():
    wal = new_wal()

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
        )

    previous_events = wal.storage.get_events()

    state_change_id = wal.storage.write_state_change('statechangedata')
    wal.storage.write_events(
        state_change_id,
        event_list,
    )

    new_events = wal.storage.get_events()
    assert len(previous_events) + 1 == len(new_events)

    latest_event = new_events[-1]
    assert isinstance(latest_event, EventPaymentSentFailed)


def test_restore_without_snapshot():
    wal = new_wal()

    wal.log_and_dispatch(Block(5))
    wal.log_and_dispatch(Block(7))
    wal.log_and_dispatch(Block(8))

    newwal = restore_from_latest_snapshot(
        state_transtion_acc,
        wal.storage,
    )

    aggregate = newwal.state_manager.current_state
    assert aggregate.state_changes == [Block(5), Block(7), Block(8)]
