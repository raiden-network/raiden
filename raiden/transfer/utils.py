from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.utils import typing


def hash_balance_data(
        transferred_amount: typing.TokenAmount,
        locked_amount: typing.TokenAmount,
        locksroot: typing.Locksroot,
) -> bytes:
    assert locksroot != b''
    assert len(locksroot) == 32
    if transferred_amount == 0 and locked_amount == 0 and locksroot == EMPTY_HASH:
        return EMPTY_HASH

    return Web3.soliditySha3(  # pylint: disable=no-value-for-parameter
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )
