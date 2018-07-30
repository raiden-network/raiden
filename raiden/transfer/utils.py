from web3 import Web3

from raiden.utils import typing
from raiden.constants import EMPTY_HASH


def hash_balance_data(
        transferred_amount: typing.TokenAmount,
        locked_amount: typing.TokenAmount,
        locksroot: typing.Locksroot,
) -> bytes:
    assert locksroot != b''
    assert len(locksroot) == 32
    if transferred_amount == 0 and locked_amount == 0 and locksroot == EMPTY_HASH:
        return EMPTY_HASH

    return Web3.soliditySha3(
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )
