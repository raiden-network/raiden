import random

from eth_utils import to_checksum_address
from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.storage.sqlite import SQLiteStorage
from raiden.utils import typing
from raiden.utils.serialization import serialize_bytes


def get_latest_known_balance_proof_from_state_changes(
        storage: SQLiteStorage,
        chain_id: typing.ChainID,
        token_network_id: typing.TokenNetworkID,
        channel_identifier: typing.ChannelID,
        balance_hash: typing.BalanceHash,
        sender: typing.Address,
) -> typing.Optional['BalanceProofSignedState']:
    """ Tries to find the balance proof with the provided balance hash
    in stored state changes. """
    state_change_record = storage.get_latest_state_change_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_id),
        'balance_proof.channel_identifier': channel_identifier,
        'balance_proof.sender': to_checksum_address(sender),
        'balance_hash': serialize_bytes(balance_hash),
    })
    if state_change_record.data:
        return state_change_record.data.balance_proof
    return None


def get_latest_known_balance_proof_from_events(
        storage: SQLiteStorage,
        chain_id: typing.ChainID,
        token_network_id: typing.TokenNetworkID,
        channel_identifier: typing.ChannelID,
        balance_hash: typing.BalanceHash,
) -> typing.Optional['BalanceProofSignedState']:
    """ Tries to find the balance proof with the provided balance hash
    in stored events. """
    event_record = storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': chain_id,
        'balance_proof.token_network_identifier': to_checksum_address(token_network_id),
        'balance_proof.channel_identifier': channel_identifier,
        'balance_hash': serialize_bytes(balance_hash),
    })
    if event_record.data:
        return event_record.data.balance_proof

    return None


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
