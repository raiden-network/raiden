import os
import sqlite3
import pytest

import transfer.mediated_transfer.factories as factories

from raiden.tests.utils.log import get_all_state_events
from raiden.transfer.log import StateChangeLog, StateChangeLogSQLiteBackend
from raiden.transfer.mediated_transfer.state_change import ContractReceiveWithdraw
from raiden.transfer.mediated_transfer.events import EventTransferFailed
from raiden.transfer.state_change import Block, ActionRouteChange
from raiden.transfer.state import RouteState


def init_database(tmpdir, in_memory_database):
    database_path = ":memory:"
    if not in_memory_database:
        database_path = os.path.join(tmpdir.strpath, 'database.db')
    return StateChangeLog(
        storage_instance=StateChangeLogSQLiteBackend(
            database_path=database_path
        )
    )


def test_write_read_log(tmpdir, in_memory_database):
    log = init_database(tmpdir, in_memory_database)

    block_number = 1337
    block = Block(block_number)
    identifier = 42
    balance = 79
    route = factories.make_route(factories.ADDR, balance)
    action_route_change = ActionRouteChange(identifier, route)
    contract_receive_withdraw = ContractReceiveWithdraw(
        factories.ADDR,
        factories.UNIT_SECRET,
        factories.HOP1
    )

    assert log.log(block) == 1
    assert log.log(action_route_change) == 2
    assert log.log(contract_receive_withdraw) == 3

    result1 = log.get_state_change_by_id(1)
    result2 = log.get_state_change_by_id(2)
    result3 = log.get_state_change_by_id(3)

    assert isinstance(result1, Block)
    assert result1.block_number == block_number
    assert isinstance(result2, ActionRouteChange)
    assert result2.identifier == identifier
    assert isinstance(result2.route, RouteState)
    assert result2.route == route
    assert isinstance(result3, ContractReceiveWithdraw)
    assert result3.channel_address == factories.ADDR
    assert result3.secret == factories.UNIT_SECRET
    assert result3.receiver == factories.HOP1

    # Make sure state snapshot can only go for corresponding state change ids
    with pytest.raises(sqlite3.IntegrityError):
        log.storage.write_state_snapshot(34, 'AAAA')
    # Make sure we can only have a single state snapshot
    assert log.storage.get_state_snapshot() is None
    log.storage.write_state_snapshot(1, 'AAAA')
    assert (1, 'AAAA') == log.storage.get_state_snapshot()
    log.storage.write_state_snapshot(2, 'BBBB')
    assert (2, 'BBBB') == log.storage.get_state_snapshot()


def test_write_read_events(tmpdir, in_memory_database):
    log = init_database(tmpdir, in_memory_database)
    event = EventTransferFailed(1, 'whatever')
    with pytest.raises(sqlite3.IntegrityError):
        log.storage.write_state_events(1, [(None, 1, log.serializer.serialize(event))])
    assert(len(get_all_state_events(log)) == 0)

    log.storage.write_state_change('statechangedata')
    log.storage.write_state_events(1, [(None, 1, log.serializer.serialize(event))])
    logged_events = get_all_state_events(log)
    assert(len(logged_events) == 1)
    assert(logged_events[0][0] == 1)
    assert(logged_events[0][1] == 1)
    assert(isinstance(logged_events[0][2], EventTransferFailed))
