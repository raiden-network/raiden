""" Utilities to track and assert transferred messages. """
import random
import string

from raiden.constants import EMPTY_MERKLE_ROOT, UINT64_MAX, UINT256_MAX
from raiden.messages import Lock, LockedTransfer, RefundTransfer
from raiden.tests.utils.factories import UNIT_CHAIN_ID, UNIT_CHANNEL_ID, make_privkey_address
from raiden.tests.utils.tests import fixture_all_combinations
from raiden.transfer.state import balanceproof_from_envelope
from raiden.utils import sha3
from raiden.utils.signer import Signer

PRIVKEY, ADDRESS = make_privkey_address()
INVALID_ADDRESSES = [
    b' ',
    b' ' * 19,
    b' ' * 21,
]

VALID_SECRETS = [
    letter.encode() * 32
    for letter in string.ascii_uppercase[:7]
]
SECRETHASHES_SECRESTS = {
    sha3(secret): secret
    for secret in VALID_SECRETS
}
VALID_SECRETHASHES = list(SECRETHASHES_SECRESTS.keys())
SECRETHASHES_FOR_MERKLETREE = [
    VALID_SECRETHASHES[:1],
    VALID_SECRETHASHES[:2],
    VALID_SECRETHASHES[:3],
    VALID_SECRETHASHES[:7],
]

# zero is used to indicate novalue in solidity, that is why it's an invalid
# nonce value

REFUND_TRANSFER_INVALID_VALUES = list(fixture_all_combinations({
    'nonce': [-1, 0, UINT64_MAX + 1],
    'payment_identifier': [-1, UINT64_MAX + 1],
    'token': INVALID_ADDRESSES,
    'recipient': INVALID_ADDRESSES,
    'transferred_amount': [-1, UINT256_MAX + 1],
}))

MEDIATED_TRANSFER_INVALID_VALUES = list(fixture_all_combinations({
    'nonce': [-1, 0, UINT64_MAX + 1],
    'payment_identifier': [-1, UINT64_MAX + 1],
    'token': INVALID_ADDRESSES,
    'recipient': INVALID_ADDRESSES,
    'target': INVALID_ADDRESSES,
    'initiator': INVALID_ADDRESSES,
    'transferred_amount': [-1, UINT256_MAX + 1],
    'fee': [UINT256_MAX + 1],
}))


def make_lock(amount=7, expiration=1, secrethash=VALID_SECRETHASHES[0]):
    return Lock(
        amount=amount,
        expiration=expiration,
        secrethash=secrethash,
    )


def make_refund_transfer(
        message_identifier=None,
        payment_identifier=0,
        nonce=1,
        token_network_address=ADDRESS,
        token=ADDRESS,
        channel_identifier=UNIT_CHANNEL_ID,
        transferred_amount=0,
        locked_amount=None,
        amount=1,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0,
        secrethash=VALID_SECRETHASHES[0],
):

    if message_identifier is None:
        message_identifier = random.randint(0, UINT64_MAX)

    if locked_amount is None:
        locked_amount = amount
    else:
        assert locked_amount >= amount

    return RefundTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=token_network_address,
        token=token,
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=recipient,
        locksroot=locksroot,
        lock=make_lock(amount=amount, secrethash=secrethash),
        target=target,
        initiator=initiator,
        fee=fee,
    )


def make_mediated_transfer(
        message_identifier=None,
        payment_identifier=0,
        nonce=1,
        token_network_addresss=ADDRESS,
        token=ADDRESS,
        channel_identifier=UNIT_CHANNEL_ID,
        transferred_amount=0,
        locked_amount=None,
        amount=1,
        expiration=1,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0,
):

    if message_identifier is None:
        message_identifier = random.randint(0, UINT64_MAX)

    lock = make_lock(
        amount=amount,
        expiration=expiration,
    )

    if locksroot == EMPTY_MERKLE_ROOT:
        locksroot = sha3(lock.as_bytes)

    if locked_amount is None:
        locked_amount = amount
    else:
        assert locked_amount >= amount

    return LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=token_network_addresss,
        token=token,
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=recipient,
        locksroot=locksroot,
        lock=lock,
        target=target,
        initiator=initiator,
        fee=fee,
    )


def make_balance_proof(
        signer: Signer = None,
        message_identifier=None,
        payment_identifier=0,
        nonce=1,
        token_network_addresss=ADDRESS,
        token=ADDRESS,
        channel_identifier=UNIT_CHANNEL_ID,
        transferred_amount=0,
        locked_amount=None,
        amount=1,
        expiration=1,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0,
):
    mediated_transfer = make_mediated_transfer(
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_addresss=token_network_addresss,
        token=token,
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        amount=amount,
        expiration=expiration,
        locksroot=locksroot,
        recipient=recipient,
        target=target,
        initiator=initiator,
        fee=fee,
    )
    mediated_transfer.sign(signer)
    balance_proof = balanceproof_from_envelope(mediated_transfer)
    return balance_proof
