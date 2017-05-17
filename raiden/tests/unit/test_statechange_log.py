import os

import transfer.mediated_transfer.factories as factories

from raiden.transfer.log import StateChangeLog, StateChangeLogSQLiteBackend
from raiden.transfer.mediated_transfer.state_change import ContractReceiveWithdraw
from raiden.transfer.state_change import Block, ActionRouteChange
from raiden.transfer.state import RouteState


def test_write_read_log(tmpdir, in_memory_database):
    database_path = ":memory:"
    if not in_memory_database:
        database_path = os.path.join(tmpdir.strpath, 'database.db')
    log = StateChangeLog(
        storage_instance=StateChangeLogSQLiteBackend(
            database_path=database_path
        )
    )

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

    log.log(block)
    assert log.last_identifier() == 1
    log.log(action_route_change)
    assert log.last_identifier() == 2
    log.log(contract_receive_withdraw)
    assert log.last_identifier() == 3

    result1 = log.get_transaction_by_id(1)
    result2 = log.get_transaction_by_id(2)
    result3 = log.get_transaction_by_id(3)

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

    # Make sure we can only have a single state snapshot
    assert log.storage.get_state_snapshot() is None
    log.storage.write_state_snapshot(34, 'AAAA')
    assert (34, 'AAAA') == log.storage.get_state_snapshot()
    log.storage.write_state_snapshot(56, 'BBBB')
    assert (56, 'BBBB') == log.storage.get_state_snapshot()
