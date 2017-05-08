import os

import transfer.mediated_transfer.factories as factories

from raiden.transfer.log import TransactionLog, TransactionLogSQLiteBackend
from raiden.transfer.mediated_transfer.state_change import ContractReceiveWithdraw
from raiden.transfer.state_change import Block, ActionRouteChange
from raiden.transfer.state import RouteState


def test_write_read_log(tmpdir):
    log = TransactionLog(
        storage_class=TransactionLogSQLiteBackend(
            database_path=os.path.join(tmpdir.strpath, 'database.db')
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
    log.log(action_route_change)
    log.log(contract_receive_withdraw)

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
