# -*- coding: utf-8 -*-
""" Utilities to track and assert transferred messages. """

import string

from raiden.network.transport import DummyTransport
from raiden.utils import sha3
from raiden.tests.utils.tests import fixture_all_combinations
from raiden.tests.utils.factories import make_privkey_address
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.messages import (
    DirectTransfer,
    Lock,
    LockedTransfer,
    RefundTransfer,
)


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
DIRECT_TRANSFER_INVALID_VALUES = list(fixture_all_combinations({
    'nonce': [-1, 0, 2 ** 64],
    'identifier': [-1, 2 ** 64],
    'token': INVALID_ADDRESSES,
    'recipient': INVALID_ADDRESSES,
    'transferred_amount': [-1, 2 ** 256],
}))

REFUND_TRANSFER_INVALID_VALUES = list(fixture_all_combinations({
    'nonce': [-1, 0, 2 ** 64],
    'identifier': [-1, 2 ** 64],
    'token': INVALID_ADDRESSES,
    'recipient': INVALID_ADDRESSES,
    'transferred_amount': [-1, 2 ** 256],
}))

MEDIATED_TRANSFER_INVALID_VALUES = list(fixture_all_combinations({
    'nonce': [-1, 0, 2 ** 64],
    'identifier': [-1, 2 ** 64],
    'token': INVALID_ADDRESSES,
    'recipient': INVALID_ADDRESSES,
    'target': INVALID_ADDRESSES,
    'initiator': INVALID_ADDRESSES,
    'transferred_amount': [-1, 2 ** 256],
    'fee': [2 ** 256],
}))


def make_lock(amount=7, expiration=1, secrethash=VALID_SECRETHASHES[0]):
    return Lock(
        amount,
        expiration,
        secrethash,
    )


def make_refund_transfer(
        identifier=0,
        nonce=1,
        registry_address=ADDRESS,
        token=ADDRESS,
        channel=ADDRESS,
        transferred_amount=0,
        amount=1,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0,
        secrethash=VALID_SECRETHASHES[0]):

    return RefundTransfer(
        identifier,
        nonce,
        registry_address,
        token,
        channel,
        transferred_amount,
        recipient,
        locksroot,
        make_lock(amount=amount, secrethash=secrethash),
        target,
        initiator,
        fee,
    )


def make_mediated_transfer(
        identifier=0,
        nonce=1,
        registry_address=ADDRESS,
        token=ADDRESS,
        channel=ADDRESS,
        transferred_amount=0,
        amount=1,
        expiration=1,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0):

    lock = make_lock(
        amount=amount,
        expiration=expiration,
    )

    if locksroot == EMPTY_MERKLE_ROOT:
        locksroot = sha3(lock.as_bytes)

    return LockedTransfer(
        identifier,
        nonce,
        registry_address,
        token,
        channel,
        transferred_amount,
        recipient,
        locksroot,
        lock,
        target,
        initiator,
        fee
    )


def make_direct_transfer(
        identifier=0,
        nonce=1,
        registry_address=ADDRESS,
        token=ADDRESS,
        channel=ADDRESS,
        transferred_amount=0,
        recipient=ADDRESS,
        locksroot=EMPTY_MERKLE_ROOT):

    return DirectTransfer(
        identifier,
        nonce,
        registry_address,
        token,
        channel,
        transferred_amount,
        recipient,
        locksroot,
    )


def setup_messages_cb():
    """ Record the messages sent so that we can assert on them. """
    messages = []

    def callback(sender_raiden, host_port, msg):  # pylint: disable=unused-argument
        messages.append(msg)

    DummyTransport.network.on_send_cbs.append(callback)

    return messages


def dump_messages(message_list):
    print('dumping {} messages'.format(len(message_list)))

    for message in message_list:
        print(message)
