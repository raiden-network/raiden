import random

from eth_utils import to_checksum_address
from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.storage import sqlite
from raiden.utils.serialization import serialize_bytes
from raiden.utils.typing import (
    Address,
    BalanceHash,
    ChainID,
    ChannelID,
    Locksroot,
    TokenAmount,
    TokenNetworkID,
)


def get_state_change_with_balance_proof_by_balance_hash(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        balance_hash: BalanceHash,
        sender: Address,
) -> sqlite.StateChangeRecord:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    return storage.get_latest_state_change_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
        'balance_proof.sender': to_checksum_address(sender),
    })


def get_state_change_with_balance_proof_by_locksroot(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        locksroot: Locksroot,
        sender: Address,
) -> sqlite.StateChangeRecord:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    return storage.get_latest_state_change_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.locksroot': serialize_bytes(locksroot),
        'balance_proof.sender': to_checksum_address(sender),
    })


def get_event_with_balance_proof_by_balance_hash(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        balance_hash: BalanceHash,
) -> sqlite.EventRecord:
    """ Returns the event which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    return storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
    })


def get_event_with_balance_proof_by_locksroot(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        locksroot: Locksroot,
) -> sqlite.EventRecord:
    """ Returns the event which contains the corresponding balance proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    return storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_identifier),
        'balance_proof.channel_identifier': str(channel_identifier),
        'balance_proof.locksroot': serialize_bytes(locksroot),
    })


def hash_balance_data(
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
) -> BalanceHash:
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
