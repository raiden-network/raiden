import os

import transfer.mediated_transfer.factories as factories

from raiden.transfer.log import TransactionLog
from raiden.transfer.state_change import Block, ActionRouteChange


def test_write_to_log(tmpdir):
    log = TransactionLog(database_path=os.path.join(tmpdir.strpath, 'database_1.db'))

    block_number = 1337
    block = Block(block_number)
    identifier = 42
    balance = 79
    route = factories.make_route(factories.ADDR, balance)
    action_route_change = ActionRouteChange(identifier, route)

    log.log(block)
    # Getting __slots__ and __getstate__ error for this class:
    # http://stackoverflow.com/questions/2204155/why-am-i-getting-an-error-about-my-class-defining-slots-when-trying-to-pickl#2204702
    # log.log(action_route_change)

    result1 = log.get_transaction_by_id(1)
    # result2= log.get_transaction_by_id(2)

    assert isinstance(result1, Block)
    assert result1.block_number == block_number
