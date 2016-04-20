# -*- coding: utf8 -*-
import struct

from ethereum import slogging

from raiden.encoding.format import buffer_for, make_field, namedbuffer, pad, BYTE
from raiden.encoding.encoders import integer, optional_bytes
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
REJECTED_CMDID = 2
SECRETREQUEST_CMDID = 3
SECRET_CMDID = 4
DIRECTTRANSFER_CMDID = 5
LOCKEDTRANSFER_CMDID = 6
MEDIATEDTRANSFER_CMDID = 7
CANCELTRANSFER_CMDID = 8
TRANSFERTIMEOUT_CMDID = 9
CONFIRMTRANSFER_CMDID = 10

ACK = to_bigendian(ACK_CMDID)
PING = to_bigendian(PING_CMDID)
# REJECTED = to_bigendian(REJECTED_CMDID)
SECRETREQUEST = to_bigendian(SECRETREQUEST_CMDID)
SECRET = to_bigendian(SECRET_CMDID)
DIRECTTRANSFER = to_bigendian(DIRECTTRANSFER_CMDID)
LOCKEDTRANSFER = to_bigendian(LOCKEDTRANSFER_CMDID)
MEDIATEDTRANSFER = to_bigendian(MEDIATEDTRANSFER_CMDID)
CANCELTRANSFER = to_bigendian(CANCELTRANSFER_CMDID)
TRANSFERTIMEOUT = to_bigendian(TRANSFERTIMEOUT_CMDID)
CONFIRMTRANSFER = to_bigendian(CONFIRMTRANSFER_CMDID)


# pylint: disable=invalid-name
log = slogging.get_logger('messages')


nonce = make_field('nonce', 8, '8s', integer(0, BYTE ** 8))
expiration = make_field('expiration', 8, '8s', integer(0, BYTE ** 8))

asset = make_field('asset', 20, '20s')
recipient = make_field('recipient', 20, '20s')
target = make_field('target', 20, '20s')
initiator = make_field('initiator', 20, '20s')
sender = make_field('sender', 20, '20s')

locksroot = make_field('locksroot', 32, '32s')
hashlock = make_field('hashlock', 32, '32s')
secret = make_field('secret', 32, '32s')
echo = make_field('echo', 32, '32s')
balance = make_field('balance', 32, '32s', integer(0, BYTE ** 32))
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

# FIXME: we need to know the type of each arg
# Reject = Message('reject', [cmdid(REJECTED), pad(3), echo, erroid, args])

SecretRequest = namedbuffer(
    'secret_request',
    [
        cmdid(SECRETREQUEST),  # [0:1]
        pad(3),                # [1:4]
        hashlock,              # [4:36]
        signature,             # [36:101]
    ]
)

Secret = namedbuffer(
    'secret',
    [
        cmdid(SECRET),  # [0:1]
        pad(3),         # [1:4]
        secret,         # [4:36]
        signature,      # [36:101]
    ]
)

DirectTransfer = namedbuffer(
    'transfer',
    [
        cmdid(DIRECTTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        asset,                  # [12:32]
        recipient,              # [32:52]
        balance,
        optional_locksroot,
        optional_secret,
        signature,
    ]
)

LockedTransfer = namedbuffer(
    'locked_transfer',
    [
        cmdid(LOCKEDTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        expiration,             # [12:20]
        asset,                  # [20:40]
        recipient,              # [40:60]
        locksroot,
        balance,
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
        expiration,               # [12:20]
        asset,                    # [20:40]
        recipient,                # [40:60]
        target,                   # [60:80]
        initiator,                # [80:100]
        locksroot,
        hashlock,
        balance,
        amount,
        fee,
        signature,
    ]
)

CancelTransfer = namedbuffer(
    'cancel_transfer',
    [
        cmdid(CANCELTRANSFER),  # [0:1]
        pad(3),                 # [1:4]
        nonce,                  # [4:12]
        expiration,             # [12:20]
        asset,                  # [20:40]
        recipient,              # [40:60]
        locksroot,
        balance,
        amount,
        hashlock,
        signature,
    ]
)

TransferTimeout = namedbuffer(
    'transfer_timeout',
    [
        cmdid(TRANSFERTIMEOUT),  # [0:1]
        pad(3),                  # [1:4]
        hashlock,                # [4:36]
        echo,                    # [36:68]
        signature,               # [68:133]
    ]
)

ConfirmTransfer = namedbuffer(
    'confirm_transfer',
    [
        cmdid(CONFIRMTRANSFER),  # [0:1]
        pad(3),                  # [1:4]
        hashlock,                # [4:36]
        signature,               # [36:101]
    ]
)


CMDID_MESSAGE = {
    ACK: Ack,
    PING: Ping,
    # REJECTED: Rejected,
    SECRETREQUEST: SecretRequest,
    SECRET: Secret,
    DIRECTTRANSFER: DirectTransfer,
    LOCKEDTRANSFER: LockedTransfer,
    MEDIATEDTRANSFER: MediatedTransfer,
    CANCELTRANSFER: CancelTransfer,
    TRANSFERTIMEOUT: TransferTimeout,
    CONFIRMTRANSFER: ConfirmTransfer,
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
        log.error('unknown cmdid {}'.format(first_byte))

    try:
        message = message_type(data)
    except ValueError:
        log.error('trying to decode invalid message')

    assert message_type.fields_spec[-1].name == 'signature', 'signature is not the last field'
    message_data = message.data[:-signature.size_bytes]

    try:
        publickey = recover_publickey(message_data, message.signature)
    except ValueError:
        log.error('invalid signature')

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
        log.error('unknown cmdid {}'.format(first_byte))
        return

    try:
        message = message_type(data)
    except ValueError:
        log.error('trying to decode invalid message')
        return

    return message
