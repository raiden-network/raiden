# -*- coding: utf-8 -*-
from ethereum import slogging

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


ACK = 0
PING = 1
SECRETREQUEST = 3
SECRET = 4
DIRECTTRANSFER = 5
MEDIATEDTRANSFER = 7
REFUNDTRANSFER = 8
REVEALSECRET = 11


# pylint: disable=invalid-name
log = slogging.get_logger(__name__)


nonce = make_field('nonce', 8, '8s', integer(0, UINT64_MAX))
identifier = make_field('identifier', 8, '8s', integer(0, UINT64_MAX))
expiration = make_field('expiration', 8, '8s', integer(0, UINT64_MAX))

token = make_field('token', 20, '20s')
recipient = make_field('recipient', 20, '20s')
target = make_field('target', 20, '20s')
initiator = make_field('initiator', 20, '20s')
sender = make_field('sender', 20, '20s')
channel = make_field('channel', 20, '20s')

locksroot = make_field('locksroot', 32, '32s')
hashlock = make_field('hashlock', 32, '32s')
secret = make_field('secret', 32, '32s')
echo = make_field('echo', 32, '32s')
transferred_amount = make_field('transferred_amount', 32, '32s', integer(0, UINT256_MAX))
amount = make_field('amount', 32, '32s', integer(0, UINT256_MAX))
fee = make_field('fee', 32, '32s', integer(0, UINT256_MAX))

optional_secret = make_field('secret', 32, '32s', optional_bytes())

signature = make_field('signature', 65, '65s')

Ack = namedbuffer(
    'ack',
    [
        cmdid(ACK),  # [0:1]
        pad(3),      # [1:4]
        sender,
        echo,
    ]
)

Ping = namedbuffer(
    'ping',
    [
        cmdid(PING),  # [0:1]
        pad(3),       # [1:4]
        nonce,        # [4:12]
        signature,    # [12:77]
    ]
)

SecretRequest = namedbuffer(
    'secret_request',
    [
        cmdid(SECRETREQUEST),  # [0:1]
        pad(3),                # [1:4]
        identifier,            # [4:12]
        hashlock,              # [12:46]
        amount,
        signature,
    ]
)

Secret = namedbuffer(
    'secret',
    [
        cmdid(SECRET),
        pad(3),
        identifier,
        secret,
        nonce,
        channel,
        transferred_amount,
        locksroot,
        signature,
    ]
)

RevealSecret = namedbuffer(
    'reveal_secret',
    [
        cmdid(REVEALSECRET),  # [0:1]
        pad(3),               # [1:4]
        secret,               # [4:36]
        signature,
    ]
)

DirectTransfer = namedbuffer(
    'direct_transfer',
    [
        cmdid(DIRECTTRANSFER),
        pad(3),
        nonce,
        identifier,
        token,
        channel,
        recipient,
        transferred_amount,
        locksroot,
        signature,
    ]
)

MediatedTransfer = namedbuffer(
    'mediated_transfer',
    [
        cmdid(MEDIATEDTRANSFER),
        pad(3),
        nonce,
        identifier,
        expiration,
        token,
        channel,
        recipient,
        target,
        initiator,
        locksroot,
        hashlock,
        transferred_amount,
        amount,
        fee,
        signature,
    ]
)

RefundTransfer = namedbuffer(
    'refund_transfer',
    [
        cmdid(REFUNDTRANSFER),
        pad(3),
        nonce,
        identifier,
        expiration,
        token,
        channel,
        recipient,
        target,
        initiator,
        locksroot,
        hashlock,
        transferred_amount,
        amount,
        fee,
        signature,
    ]
)

Lock = namedbuffer(
    'lock',
    [
        expiration,
        amount,
        hashlock,
    ]
)


CMDID_MESSAGE = {
    ACK: Ack,
    PING: Ping,
    SECRETREQUEST: SecretRequest,
    SECRET: Secret,
    REVEALSECRET: RevealSecret,
    DIRECTTRANSFER: DirectTransfer,
    MEDIATEDTRANSFER: MediatedTransfer,
    REFUNDTRANSFER: RefundTransfer,
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
