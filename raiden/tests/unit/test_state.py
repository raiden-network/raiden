from raiden.transfer.state import TransactionChannelNewBalance, TransactionOrder


def test_transaction_channel_new_balance_ordering():
    a = TransactionChannelNewBalance(bytes(1), 1, 1)
    b = TransactionChannelNewBalance(bytes(2), 2, 2)
    assert a != b
    assert a < b
    assert b > a

    a = TransactionChannelNewBalance(bytes(1), 1, 1)
    b = TransactionChannelNewBalance(bytes(2), 2, 1)
    assert a != b
    assert a < b
    assert b > a

    a = TransactionChannelNewBalance(bytes(3), 3, 3)
    b = TransactionChannelNewBalance(bytes(3), 3, 3)
    assert a == b
    assert not a > b
    assert not b > a


def test_transaction_order_ordering():
    a = TransactionOrder(1, TransactionChannelNewBalance(bytes(1), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(bytes(2), 2, 2))
    assert a != b
    assert a < b
    assert b > a

    a = TransactionOrder(1, TransactionChannelNewBalance(bytes(1), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(bytes(2), 2, 1))
    assert a != b
    assert a < b
    assert b > a

    a = TransactionOrder(3, TransactionChannelNewBalance(bytes(3), 3, 3))
    b = TransactionOrder(3, TransactionChannelNewBalance(bytes(3), 3, 3))
    assert a == b
    assert not a > b
    assert not b > a

    a = TransactionOrder(1, TransactionChannelNewBalance(bytes(1), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(bytes(1), 1, 1))
    assert a != b
    assert a < b
    assert b > a
