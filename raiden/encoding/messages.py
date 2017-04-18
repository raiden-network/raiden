# -*- coding: utf-8 -*-
import struct

from ethereum import slogging

from raiden.encoding.encoders import integer, optional_bytes
from raiden.encoding.format import buffer_for, make_field, namedbuffer, pad, BYTE
from raiden.encoding.signing import recover_publickey


def to_bigendian(number):
    return struct.pack('>B', number)


def from_bigendian(number):
    return struct.unpack('>B', number)


def cmdid(id_):
    return make_field('cmdid', 1, 'B', integer(id_, id_))


def make_message(message, **attrs):
    klass = CMDID_MESSAGE[message]
    message = klass(buffer_for(klass))
    message.cmdid = from_bigendian(message)

    for name, value in attrs.items():
        setattr(message, name, value)

    return message


ACK_CMDID = 0
PING_CMDID = 1
SECRETREQUEST_CMDID = 3
SECRET_CMDID = 4
DIRECTTRANSFER_CMDID = 5
LOCKEDTRANSFER_CMDID = 6
MEDIATEDTRANSFER_CMDID = 7
REFUNDTRANSFER_CMDID = 8
TOKENSWAP_CMDID = 9
REVEALSECRET_CMDID = 11

ACK = to_bigendian(ACK_CMDID)
PING = to_bigendian(PING_CMDID)
SECRETREQUEST = to_bigendian(SECRETREQUEST_CMDID)
SECRET = to_bigendian(SECRET_CMDID)
REVEALSECRET = to_bigendian(REVEALSECRET_CMDID)
DIRECTTRANSFER = to_bigendian(DIRECTTRANSFER_CMDID)
LOCKEDTRANSFER = to_bigendian(LOCKEDTRANSFER_CMDID)
MEDIATEDTRANSFER = to_bigendian(MEDIATEDTRANSFER_CMDID)
TOKENSWAP = to_bigendian(TOKENSWAP_CMDID)
REFUNDTRANSFER = to_bigendian(REFUNDTRANSFER_CMDID)


# pylint: disable=invalid-name
log = slogging.get_logger(__name__)


nonce = make_field('nonce', 8, '8s', integer(0, BYTE ** 8))
identifier = make_field('identifier', 8, '8s', integer(0, BYTE ** 8))
expiration = make_field('expiration', 8, '8s', integer(0, BYTE ** 8))

token = make_field('token', 20, '20s')
recipient = make_field('recipient', 20, '20s')
target = make_field('target', 20, '20s')
initiator = make_field('initiator', 20, '20s')
sender = make_field('sender', 20, '20s')

locksroot = make_field('locksroot', 32, '32s')
hashlock = make_field('hashlock', 32, '32s')
secret = make_field('secret', 32, '32s')
echo = make_field('echo', 32, '32s')
transferred_amount = make_field('transferred_amount', 32, '32s', integer(0, BYTE ** 32))
amount = make_field('amount', 32, '32s', integer(0, BYTE ** 32))
fee = make_field('fee', 32, '32s', integer(0, BYTE ** 32))

optional_locksroot = make_field('locksroot', 32, '32s', optional_bytes())
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
        cmdid(SECRET),  # [0:1]
        pad(3),         # [1:4]
        identifier,     # [4:12]
        secret,         # [12:44]
        token,
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
        cmdid(DIRECTTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        identifier,             # [12:20]
        token,                  # [20:40]
        recipient,              # [40:60]
        transferred_amount,
        optional_locksroot,
        signature,
    ]
)

LockedTransfer = namedbuffer(
    'locked_transfer',
    [
        cmdid(LOCKEDTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        identifier,             # [12:20]
        expiration,             # [20:28]
        token,                  # [28:48]
        recipient,              # [48:68]
        locksroot,
        transferred_amount,
        amount,
        hashlock,
        signature,
    ]
)

MediatedTransfer = namedbuffer(
    'mediated_transfer',
    [
        cmdid(MEDIATEDTRANSFER),  # [0:1]
        pad(3),                   # [1:4]
        nonce,                    # [4:12]
        identifier,               # [12:20]
        expiration,               # [20:28]
        token,                    # [28:48]
        recipient,                # [48:68]
        target,                   # [68:88]
        initiator,                # [88:108]
        locksroot,                # [108:140]
        hashlock,                 # [140:172]
        transferred_amount,       # [172:204]
        amount,                   # [204:236]
        fee,                      # [236:268]
        signature,                # [268:333]
    ]
)

TokenSwap = namedbuffer(
    'token_swap',
    [
        cmdid(TOKENSWAP),  # [0:1]
        pad(3),                   # [1:4]
        nonce,                    # [4:12]
        identifier,               # [12:20]
        expiration,               # [20:28]
        token,                    # [28:48]
        recipient,                # [48:68]
        target,                   # [68:88]
        initiator,                # [88:108]
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
        cmdid(REFUNDTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        identifier,             # [12:20]
        expiration,             # [20:28]
        token,                  # [28:48]
        recipient,              # [48:68]
        locksroot,              # [68:100]
        transferred_amount,     # [100:132]
        amount,                 # [132:164]
        hashlock,               # [164:196]
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
    LOCKEDTRANSFER: LockedTransfer,
    MEDIATEDTRANSFER: MediatedTransfer,
    TOKENSWAP: TokenSwap,
    REFUNDTRANSFER: RefundTransfer,
}


def wrap_and_validate(data):
    ''' Try to decode data into a message and validate the signature, might
    return None if the data is invalid.
    '''
    try:
        first_byte = data[0]
    except KeyError:
        log.warn('data is empty')
        return

    try:
        message_type = CMDID_MESSAGE[first_byte]
    except KeyError:
        log.error('unknown cmdid %s', first_byte)
        return

    try:
        message = message_type(data)
    except ValueError:
        log.error('trying to decode invalid message')
        return

    assert message_type.fields_spec[-1].name == 'signature', 'signature is not the last field'
    # this slice must be from the end of the buffer
    message_data = message.data[:-signature.size_bytes]
    message_signature = message.data[-signature.size_bytes:]

    try:
        publickey = recover_publickey(message_data, message_signature)
    except Exception:
        log.error('invalid signature')
        return

    return message, publickey


def wrap(data):
    ''' Try to decode data into a message, might return None if the data is invalid. '''
    try:
        first_byte = data[0]
    except KeyError:
        log.warn('data is empty')
        return

    try:
        message_type = CMDID_MESSAGE[first_byte]
    except KeyError:
        log.error('unknown cmdid %s', first_byte)
        return

    try:
        message = message_type(data)
    except ValueError:
        log.error('trying to decode invalid message')
        return

    return message
