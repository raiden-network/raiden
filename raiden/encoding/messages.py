# -*- coding: utf-8 -*-
import structlog

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.encoding.encoders import integer, optional_bytes
from raiden.encoding.format import (
    buffer_for,
    make_field,
    namedbuffer,
    pad,
)


def cmdid(id_):
    return make_field('cmdid', 1, 'B', integer(id_, id_))


def make_message(message, **attrs):
    klass = CMDID_MESSAGE[message]
    message = klass(buffer_for(klass))

    for name, value in attrs.items():
        setattr(message, name, value)

    return message


PROCESSED = 0
PING = 1
PONG = 2
SECRETREQUEST = 3
SECRET = 4
DIRECTTRANSFER = 5
LOCKEDTRANSFER = 7
REFUNDTRANSFER = 8
REVEALSECRET = 11
DELIVERED = 12


# pylint: disable=invalid-name
log = structlog.get_logger(__name__)


nonce = make_field('nonce', 8, '8s', integer(0, UINT64_MAX))
payment_identifier = make_field('payment_identifier', 8, '8s', integer(0, UINT64_MAX))
message_identifier = make_field('message_identifier', 8, '8s', integer(0, UINT64_MAX))
delivered_message_identifier = make_field(
    'delivered_message_identifier',
    8,
    '8s',
    integer(0, UINT64_MAX),
)
expiration = make_field('expiration', 32, '32s', integer(0, UINT256_MAX))

token_network_address = make_field('token_network_address', 20, '20s')
token = make_field('token', 20, '20s')
recipient = make_field('recipient', 20, '20s')
target = make_field('target', 20, '20s')
initiator = make_field('initiator', 20, '20s')
channel = make_field('channel', 20, '20s')

locksroot = make_field('locksroot', 32, '32s')
secrethash = make_field('secrethash', 32, '32s')
secret = make_field('secret', 32, '32s')
transferred_amount = make_field('transferred_amount', 32, '32s', integer(0, UINT256_MAX))
locked_amount = make_field('locked_amount', 32, '32s', integer(0, UINT256_MAX))
amount = make_field('amount', 32, '32s', integer(0, UINT256_MAX))
fee = make_field('fee', 32, '32s', integer(0, UINT256_MAX))

optional_secret = make_field('secret', 32, '32s', optional_bytes())

signature = make_field('signature', 65, '65s')

Processed = namedbuffer(
    'processed',
    [
        cmdid(PROCESSED),
        pad(3),
        message_identifier,
        signature,
    ],
)

Delivered = namedbuffer(
    'delivered',
    [
        cmdid(DELIVERED),
        pad(3),
        delivered_message_identifier,
        signature,
    ],
)

Ping = namedbuffer(
    'ping',
    [
        cmdid(PING),
        pad(3),
        nonce,
        signature,
    ],
)

Pong = namedbuffer(
    'pong',
    [
        cmdid(PONG),
        pad(3),
        nonce,
        signature,
    ],
)

SecretRequest = namedbuffer(
    'secret_request',
    [
        cmdid(SECRETREQUEST),
        pad(3),
        message_identifier,
        payment_identifier,
        secrethash,
        amount,
        signature,
    ],
)

Secret = namedbuffer(
    'secret',
    [
        cmdid(SECRET),
        pad(3),
        message_identifier,
        payment_identifier,
        token_network_address,
        secret,
        nonce,
        channel,
        transferred_amount,
        locked_amount,
        locksroot,
        signature,
    ],
)

RevealSecret = namedbuffer(
    'reveal_secret',
    [
        cmdid(REVEALSECRET),
        pad(3),
        message_identifier,
        secret,
        signature,
    ],
)

DirectTransfer = namedbuffer(
    'direct_transfer',
    [
        cmdid(DIRECTTRANSFER),
        pad(3),
        nonce,
        message_identifier,
        payment_identifier,
        token_network_address,
        token,
        channel,
        recipient,
        transferred_amount,
        locked_amount,
        locksroot,
        signature,
    ],
)

LockedTransfer = namedbuffer(
    'mediated_transfer',
    [
        cmdid(LOCKEDTRANSFER),
        pad(3),
        nonce,
        message_identifier,
        payment_identifier,
        expiration,
        token_network_address,
        token,
        channel,
        recipient,
        target,
        initiator,
        locksroot,
        secrethash,
        transferred_amount,
        locked_amount,
        amount,
        fee,
        signature,
    ],
)

RefundTransfer = namedbuffer(
    'refund_transfer',
    [
        cmdid(REFUNDTRANSFER),
        pad(3),
        nonce,
        message_identifier,
        payment_identifier,
        expiration,
        token_network_address,
        token,
        channel,
        recipient,
        target,
        initiator,
        locksroot,
        secrethash,
        transferred_amount,
        locked_amount,
        amount,
        fee,
        signature,
    ],
)

Lock = namedbuffer(
    'lock',
    [
        expiration,
        amount,
        secrethash,
    ],
)


CMDID_MESSAGE = {
    PROCESSED: Processed,
    PING: Ping,
    PONG: Pong,
    SECRETREQUEST: SecretRequest,
    SECRET: Secret,
    REVEALSECRET: RevealSecret,
    DIRECTTRANSFER: DirectTransfer,
    LOCKEDTRANSFER: LockedTransfer,
    REFUNDTRANSFER: RefundTransfer,
    DELIVERED: Delivered,
}


def wrap(data):
    """ Try to decode data into a message, might return None if the data is invalid. """
    try:
        cmdid = data[0]
    except IndexError:
        log.warn('data is empty')
        return

    try:
        message_type = CMDID_MESSAGE[cmdid]
    except KeyError:
        log.error('unknown cmdid %s', cmdid)
        return

    try:
        message = message_type(data)
    except ValueError:
        log.error('trying to decode invalid message')
        return

    return message
