from web3 import Web3

from raiden.utils import typing


def hash_balance_data(
        transferred_amount: typing.TokenAmount,
        locked_amount: typing.TokenAmount,
        locksroot: typing.Locksroot,
) -> bytes:
    if transferred_amount == 0 and locked_amount == 0 and locksroot == b'':
        return bytes(32)

    return Web3.soliditySha3(
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )
