from raiden.transfer.state import TransactionChannelNewBalance, TransactionOrder
from raiden.utils import typing


def test_transaction_channel_new_balance_ordering():
    a = TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1)
    b = TransactionChannelNewBalance(typing.Address(bytes(20)), 2, 2)
    assert a != b
    assert a < b
    assert b > a

    a = TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1)
    b = TransactionChannelNewBalance(typing.Address(bytes(20)), 2, 1)
    assert a != b
    assert a < b
    assert b > a

    a = TransactionChannelNewBalance(typing.Address(bytes(20)), 3, 3)
    b = TransactionChannelNewBalance(typing.Address(bytes(20)), 3, 3)
    assert a == b
    assert not a > b
    assert not b > a


def test_transaction_order_ordering():
    a = TransactionOrder(1, TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(typing.Address(bytes(20)), 2, 2))
    assert a != b
    assert a < b
    assert b > a

    a = TransactionOrder(1, TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(typing.Address(bytes(20)), 2, 1))
    assert a != b
    assert a < b
    assert b > a

    a = TransactionOrder(3, TransactionChannelNewBalance(typing.Address(bytes(20)), 3, 3))
    b = TransactionOrder(3, TransactionChannelNewBalance(typing.Address(bytes(20)), 3, 3))
    assert a == b
    assert not a > b
    assert not b > a

    a = TransactionOrder(1, TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1))
    b = TransactionOrder(2, TransactionChannelNewBalance(typing.Address(bytes(20)), 1, 1))
    assert a != b
    assert a < b
    assert b > a
