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


def get_state_change_or_event_with_balance_proof(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        is_our_unlock: bool,
        is_partner_unlock: bool,
        our_balance_hash: BalanceHash,
        partner_balance_hash: BalanceHash,
        sender: Address,
) -> sqlite.Record:
    """ Returns the state change or event which contains the corresponding balance
    proof depending on who's balance hash we're looking for.
    """
    if is_partner_unlock:
        state_change_record = get_state_change_with_balance_proof(
            storage=storage,
            chain_id=chain_id,
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            balance_hash=partner_balance_hash,
            sender=sender,
        )
        state_change_identifier = state_change_record.state_change_identifier

        if state_change_identifier:
            return state_change_record

        event_record = get_event_with_balance_proof(
            storage=storage,
            chain_id=chain_id,
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            balance_hash=partner_balance_hash,
        )

        return event_record
    elif is_our_unlock:
        event_record = get_event_with_balance_proof(
            storage=storage,
            chain_id=chain_id,
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            balance_hash=our_balance_hash,
        )
        state_change_identifier = event_record.state_change_identifier

        if state_change_identifier:
            return event_record

        state_change_record = get_state_change_with_balance_proof(
            storage=storage,
            chain_id=chain_id,
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            balance_hash=our_balance_hash,
            sender=sender,
        )

        return state_change_record
    return 0


def get_state_change_with_balance_proof(
        storage: sqlite.SQLiteStorage,
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        balance_hash: BalanceHash,
        sender: Address,
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
        chain_id: ChainID,
        token_network_identifier: TokenNetworkID,
        channel_identifier: ChannelID,
        balance_hash: BalanceHash,
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
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
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
