import random

from eth_utils import to_checksum_address
from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.storage import sqlite
from raiden.utils import typing
from raiden.utils.serialization import serialize_bytes


def get_state_change_with_balance_proof(
        storage: sqlite.SQLiteStorage,
        chain_id: typing.ChainID,
        token_network_identifier: typing.TokenNetworkID,
        channel_identifier: typing.ChannelID,
        balance_hash: typing.BalanceHash,
        sender: typing.Address,
) -> sqlite.StateChangeRecord:
    """ Returns the state change which contains the corresponding balance
    proof.
    """
    return storage.get_latest_state_change_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
        'balance_proof.sender': to_checksum_address(sender),
    })


def get_event_with_balance_proof(
        storage: sqlite.SQLiteStorage,
        chain_id: typing.ChainID,
        token_network_identifier: typing.TokenNetworkID,
        channel_identifier: typing.ChannelID,
        balance_hash: typing.BalanceHash,
) -> sqlite.EventRecord:
    """ Returns the event which contains the corresponding balance
    proof.
    """
    return storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
    })


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


def pseudo_random_generator_from_json(data):
    # JSON serializes a tuple as a list
    pseudo_random_generator = random.Random()
    state = list(data['pseudo_random_generator'])  # copy
    state[1] = tuple(state[1])  # fix type
    pseudo_random_generator.setstate(tuple(state))

    return pseudo_random_generator


def is_valid_secret_reveal(state_change, transfer_secrethash, secret):
    return secret != EMPTY_HASH and state_change.secrethash == transfer_secrethash
