from eth_utils import decode_hex
from web3 import Web3

from raiden.constants import EMPTY_HEX_HASH
from raiden.utils import typing


def hash_balance_data(
        transferred_amount: typing.TokenAmount,
        locked_amount: typing.TokenAmount,
        locksroot: typing.Locksroot,
) -> bytes(32):
    if transferred_amount == 0 and locked_amount == 0 and locksroot == b'':
        return decode_hex(
            EMPTY_HEX_HASH,
        )
    return Web3.soliditySha3(
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )
