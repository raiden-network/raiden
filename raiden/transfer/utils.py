import random
from random import Random
from typing import TYPE_CHECKING

from eth_utils import to_checksum_address
from web3 import Web3

from raiden.constants import EMPTY_HASH
from raiden.storage import sqlite
from raiden.utils import CanonicalIdentifier
from raiden.utils.serialization import serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BalanceHash,
    Locksroot,
    Secret,
    SecretHash,
    TokenAmount,
    Union,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal  # noqa: F401
    from raiden.transfer.state_change import ContractReceiveSecretReveal  # noqa: F401


def get_state_change_with_balance_proof_by_balance_hash(
        storage: sqlite.SQLiteStorage,
        canonical_identifier: CanonicalIdentifier,
        balance_hash: BalanceHash,
        sender: Address,
) -> sqlite.StateChangeRecord:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    return storage.get_latest_state_change_by_data_field({
        'balance_proof.chain_id': canonical_identifier.chain_identifier,
        'balance_proof.token_network_identifier': to_checksum_address(
            canonical_identifier.token_network_address,
        ),
        'balance_proof.channel_identifier': str(canonical_identifier.channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
        'balance_proof.sender': to_checksum_address(sender),
    })


def get_state_change_with_balance_proof_by_locksroot(
        storage: sqlite.SQLiteStorage,
        canonical_identifier: CanonicalIdentifier,
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
        'balance_proof.chain_id': canonical_identifier.chain_identifier,
        'balance_proof.token_network_identifier': to_checksum_address(
            canonical_identifier.token_network_address,
        ),
        'balance_proof.channel_identifier': str(canonical_identifier.channel_identifier),
        'balance_proof.locksroot': serialize_bytes(locksroot),
        'balance_proof.sender': to_checksum_address(sender),
    })


def get_event_with_balance_proof_by_balance_hash(
        storage: sqlite.SQLiteStorage,
        canonical_identifier: CanonicalIdentifier,
        balance_hash: BalanceHash,
) -> sqlite.EventRecord:
    """ Returns the event which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    return storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': canonical_identifier.chain_identifier,
        'balance_proof.token_network_identifier': to_checksum_address(
            canonical_identifier.token_network_address,
        ),
        'balance_proof.channel_identifier': str(canonical_identifier.channel_identifier),
        'balance_proof.balance_hash': serialize_bytes(balance_hash),
    })


def get_event_with_balance_proof_by_locksroot(
        storage: sqlite.SQLiteStorage,
        canonical_identifier: CanonicalIdentifier,
        locksroot: Locksroot,
        recipient: Address,
) -> sqlite.EventRecord:
    """ Returns the event which contains the corresponding balance proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    return storage.get_latest_event_by_data_field({
        'balance_proof.chain_id': canonical_identifier.chain_identifier,
        'balance_proof.token_network_identifier': to_checksum_address(
            canonical_identifier.token_network_address,
        ),
        'balance_proof.channel_identifier': str(canonical_identifier.channel_identifier),
        'balance_proof.locksroot': serialize_bytes(locksroot),
        'recipient': to_checksum_address(recipient),
    })


def hash_balance_data(
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
) -> BalanceHash:
    assert locksroot != b''
    assert len(locksroot) == 32
    if transferred_amount == 0 and locked_amount == 0 and locksroot == EMPTY_HASH:
        return BalanceHash(EMPTY_HASH)

    return Web3.soliditySha3(  # pylint: disable=no-value-for-parameter
        ['uint256', 'uint256', 'bytes32'],
        [transferred_amount, locked_amount, locksroot],
    )


def pseudo_random_generator_from_json(data: Any) -> Random:
    # JSON serializes a tuple as a list
    pseudo_random_generator = random.Random()
    state = list(data['pseudo_random_generator'])  # copy
    state[1] = tuple(state[1])  # fix type
    pseudo_random_generator.setstate(tuple(state))

    return pseudo_random_generator


def is_valid_secret_reveal(
        state_change: Union['ContractReceiveSecretReveal', 'ReceiveSecretReveal'],
        transfer_secrethash: SecretHash,
        secret: Secret,
) -> bool:
    return secret != EMPTY_HASH and state_change.secrethash == transfer_secrethash
