from web3 import Web3
from eth_utils import to_normalized_address, to_checksum_address

from raiden.utils import typing


def hash_balance_data(
        transferred_amount: typing.TokenAmount,
        locked_amount: typing.TokenAmount,
        locksroot: typing.Locksroot,
) -> str:
    return Web3.soliditySha3(
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )


def calculate_channel_identifier(
        participant1: typing.T_Address,
        participant2: typing.T_Address,
) -> str:
    """ Calculate the channel identifier between two participants in the same
    way that the TokenNetwork contract does"""
    participant1 = to_normalized_address(participant1)
    participant2 = to_normalized_address(participant2)

    c_participant1 = to_checksum_address(participant1)
    c_participant2 = to_checksum_address(participant2)
    if participant1 < participant2:
        return Web3.soliditySha3(
            ['address', 'address'],
            [c_participant1, c_participant2],
        )
    else:
        return Web3.soliditySha3(
            ['address', 'address'],
            [c_participant2, c_participant1],
        )
