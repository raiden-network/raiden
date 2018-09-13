import random

from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.storage.sqlite import SQLiteStorage
from raiden.utils import typing
from raiden.utils.serialization import serialize_bytes


def get_latest_known_balance_proof(
        storage: SQLiteStorage,
        balance_hash: typing.BalanceHash,
) -> typing.Optional['BalanceProofSignedState']:
    """ Tries to find the balance proof with the provided balance hash
    in either latest state change or latest event. """
    state_change = storage.get_latest_state_change_by_data_field(
        'balance_hash',
        serialize_bytes(balance_hash),
    )
    if state_change:
        return state_change.balance_proof

    event = storage.get_latest_event_by_data_field(
        'balance_hash',
        serialize_bytes(balance_hash),
    )
    if event:
        return event.balance_proof

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
    state = tuple(state)
    pseudo_random_generator.setstate(state)

    return pseudo_random_generator
