# -*- coding: utf8 -*-
# Copyright (c) 2015 Heiko Hees
import warnings

from ethereum.slogging import getLogger

from raiden.encoding import messages, signing
from raiden.encoding.format import buffer_for
from raiden.utils import sha3, ishash, big_endian_to_int, pex

__all__ = (
    'BaseError',
    'Ack',
    'Ping',
    # 'Rejected',
    'SecretRequest',
    'Secret',
    'DirectTransfer',
    'Lock',
    'LockedTransfer',
    'MediatedTransfer',
    'CancelTransfer',
    'TransferTimeout',
    'ConfirmTransfer',
)

log = getLogger(__name__)  # pylint: disable=invalid-name


class BaseError(Exception):
    errorid = 0
    echo = ''
    error_map = dict()

    def __init__(self, msg_or_echo, *args):
        if isinstance(msg_or_echo, SignedMessage):
            self.echo = msg_or_echo.hash
        else:
            assert ishash(msg_or_echo)
            self.echo = msg_or_echo
        super(BaseError, self).__init__(*args)

    # def asmessage(self):
    #     return Rejected(self.echo, self.errorid, *self.args)

    @classmethod
    def register(cls):
        assert issubclass(cls, BaseError)
        BaseError.error_map[cls.errorid] = cls

BaseError.register()

# pylint: disable=too-few-public-methods,too-many-arguments


class MessageHashable(object):
    pass


class Message(MessageHashable):
    # pylint: disable=no-member

    @property
    def hash(self):
        warnings.warn('Expensive comparison called')
        packed = self.packed()
        return sha3(packed.data)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.hash == other.hash

    def __hash__(self):
        return big_endian_to_int(self.hash)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        packed = self.packed()

        return '<{klass} [{content}]>'.format(
            klass=self.__class__.__name__,
            content=pex(packed.data),
        )

    @classmethod
    def decode(cls, packed):
        packed = messages.wrap(packed)
        return cls.unpack(packed)

    def encode(self):
        packed = self.packed()
        return bytes(packed.data)

    def packed(self):
        klass = messages.CMDID_MESSAGE[self.cmdid]
        data = buffer_for(klass)
        data[0] = self.cmdid
        packed = klass(data)
        self.pack(packed)

        return packed


class SignedMessage(Message):
    # signing is a bit problematic, we need to pack the data to sign, but the
    # current API assumes that signing is called before, this can be improved
    # by changing the order to packing then signing
    def __init__(self):
        super(SignedMessage, self).__init__()
        self.signature = b''
        self.sender = b''

    def sign(self, private_key):
        packed = self.packed()

        field = packed.fields_spec[-1]
        assert field.name == 'signature', 'signature is not the last field'

        message_data = packed.data[:-field.size_bytes]
        signature, public_key = signing.sign(message_data, private_key)

        packed.signature = signature

        self.sender = signing.address_from_key(public_key)
        self.signature = packed.signature

        return self

    @classmethod
    def decode(cls, data):
        result = messages.wrap_and_validate(data)
        # result = messages.wrap(data)

        if result is None:
            return

        packed, public_key = result
        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = signing.address_from_key(public_key)
        return message


class Ack(Message):
    """ All accepted messages should be confirmed by an `Ack` which echoes the
    orginals Message hash.

    We don't sign Acks because attack vector can be mitigated and to speed up
    things.
    """
    cmdid = messages.ACK

    def __init__(self, sender, echo):
        self.sender = sender
        self.echo = echo

    @staticmethod
    def unpack(packed):
        return Ack(
            packed.sender,
            packed.echo,
        )

    def pack(self, packed):
        packed.echo = self.echo
        packed.sender = self.sender


class Ping(SignedMessage):
    """ Ping, should be responded by an Ack message. """
    cmdid = messages.PING

    def __init__(self, nonce):
        super(Ping, self).__init__()
        self.nonce = nonce

    @staticmethod
    def unpack(packed):
        ping = Ping(packed.nonce)
        ping.signature = packed.signature
        return ping

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.signature = self.signature


# class Rejected(SignedMessage):
#     """ All rejected messages should be confirmed by a `Rejected` which
#     echoes the orginals Message hash.
#     """
#
#     cmdid = messages.REJECT
#
#     def __init__(self, echo, errorid, *args):
#         self.echo = echo
#         self.errorid = errorid
#         self.args = args
#
#     def aserror(self):
#         cls = BaseError[self.errorid]
#         return cls(self.echo, *self.args)
#
#     @staticmethod
#     def unpack(packed):
#         rejected =  Rejected(packed.echo, packed.errorid, *packed.args)
#         rejected.signature = packed.signature
#         return rejected
#
#     def pack(self, packed):
#         packed.echo = self.echo
#         packed.errorid = self.errorid
#         packed.args = self.args
#         packed.signature = self.signature


class SecretRequest(SignedMessage):
    """ Requests the secret which unlocks a hashlock. """
    cmdid = messages.SECRETREQUEST

    def __init__(self, hashlock):
        super(SecretRequest, self).__init__()
        self.hashlock = hashlock

    @staticmethod
    def unpack(packed):
        secret_request = SecretRequest(packed.hashlock)
        secret_request.signature = packed.signature
        return secret_request

    def pack(self, packed):
        packed.hashlock = self.hashlock
        packed.signature = self.signature


class Secret(SignedMessage):
    """ Provides the secret to a hashlock. """
    cmdid = messages.SECRET

    def __init__(self, secret):
        super(Secret, self).__init__()
        self.secret = secret
        self._hashlock = None

    @property
    def hashlock(self):
        if self._hashlock is None:
            self._hashlock = sha3(self.secret)
        return self._hashlock

    @staticmethod
    def unpack(packed):
        secret = Secret(packed.secret)
        secret.signature = packed.signature
        return secret

    def pack(self, packed):
        packed.secret = self.secret
        packed.signature = self.signature


class DirectTransfer(SignedMessage):
    """ An direct asset exchange, used when both participants have a previously
    openned channel.

    Args:
        nonce: A sequential nonce, used to protected against replay attacks and
            to give a total order for the messages. This nonce is per
            participant, not shared.
        asset: The address of the asset being exchanged in the channel.
        transfered_amount: The total amount of asset that wast transfered to
            the channel partner. This value is monotonicly increasing and can
            be larger than a channels deposit, since the channels are
            bidirecional.
        recipient: The address of raiden node participating in the channel.
        locksroot: The root of a merkle tree which records the current
            outstanding locks.
        secret: If provided allows to settle a formerly locked transfer,
            the given secret is already reflected in the locksroot.
    """

    cmdid = messages.DIRECTTRANSFER

    def __init__(self, nonce, asset, transfered_amount, recipient, locksroot, secret=None):
        super(DirectTransfer, self).__init__()
        self.nonce = nonce
        self.asset = asset
        self.transfered_amount = transfered_amount  #: total amount of asset sent to partner
        self.recipient = recipient  #: partner's address
        self.locksroot = locksroot  #: the merkle root that represent all pending locked transfers
        self.secret = secret or ''  #: secret for settling a locked amount

    @staticmethod
    def unpack(packed):
        transfer = DirectTransfer(
            packed.nonce,
            packed.asset,
            packed.transfered_amount,
            packed.recipient,
            packed.locksroot,
            packed.secret,
        )
        transfer.signature = packed.signature

        return transfer

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.asset = self.asset
        packed.transfered_amount = self.transfered_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.secret = self.secret
        packed.signature = self.signature


class Lock(MessageHashable):
    """ Describes a locked `amount`.

    Args:
        amount: Amount of the asset being transfered.
        expiration: Highest block_number until the lock can be unlocked.
        hashlock: Hashed secret `sha3(secret)` used to register the transfer,
            the real `secret` is necessary to release the locked amount.
    """
    # Lock extends MessageHashable but it is not a message, it is a
    # serializable structure that is reused in some messages

    def __init__(self, amount, expiration, hashlock):
        # guarantee that `amount` can be serialized using the available bytes
        # in the fixed length format
        if amount < 0:
            raise ValueError('amount {} needs to be positive'.format(amount))

        if amount > 2 ** 256:
            raise ValueError('amount {} is too large'.format(amount))

        assert ishash(hashlock)
        self.amount = amount
        self.expiration = expiration
        self.hashlock = hashlock
        self._asbytes = None

    @property
    def as_bytes(self):
        if self._asbytes is None:
            packed = messages.Lock(buffer_for(messages.Lock))
            packed.amount = self.amount
            packed.expiration = self.expiration
            packed.hashlock = self.hashlock

            self._asbytes = packed.data

        return self._asbytes

    @classmethod
    def from_bytes(cls, serialized):
        packed = messages.Lock(serialized)

        return cls(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )


class LockedTransfer(SignedMessage):
    """ A transfer which signs that the partner can claim `locked_amount` if
    she knows the secret to `hashlock`.

    The asset amount is implicitely represented in the `locksroot` and won't be
    reflected in the `transfered_amount` until the secret is revealed.

    This signs Carol, that she can claim locked_amount from Bob if she knows the secret to hashlock

    If the secret to hashlock becomes public, but Bob fails to sign Carol a netted balance,
    with an updated rootlock which reflects the deletion of the lock, then
        Carol can request settlement on chain by providing:
            any signed [nonce, asset, balance, recipient, locksroot, ...]
            along a merkle proof from locksroot to the not yet netted formerly locked amount
    """
    cmdid = messages.LOCKEDTRANSFER

    def __init__(self, nonce, asset, transfered_amount, recipient, locksroot, lock):
        super(LockedTransfer, self).__init__()
        self.nonce = nonce
        self.asset = asset
        self.transfered_amount = transfered_amount
        self.recipient = recipient
        self.locksroot = locksroot

        self.lock = lock

    def to_mediatedtransfer(self, target, initiator='', fee=0):
        return MediatedTransfer(
            self.nonce,
            self.asset,
            self.transfered_amount,
            self.recipient,
            self.locksroot,
            self.lock,
            target,
            initiator,
            fee,
        )

    def to_canceltransfer(self):
        return CancelTransfer(
            self.nonce,
            self.asset,
            self.transfered_amount,
            self.recipient,
            self.locksroot,
            self.lock,
        )

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )

        locked_transfer = LockedTransfer(
            packed.nonce,
            packed.asset,
            packed.transfered_amount,
            packed.recipient,
            packed.locksroot,
            lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.asset = self.asset
        packed.transfered_amount = self.transfered_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.hashlock = lock.hashlock

        packed.signature = self.signature


class MediatedTransfer(LockedTransfer):

    """
    A MediatedTransfer has a `target` address to which a chain of transfers shall be established.
    Here the `haslock` is mandatory.

    `fee` is the remaining fee a recipient shall use to complete the mediated transfer.
    The recipient can deduct his own fee from the amount and lower `fee` to the remaining fee.
    Just as the recipient can fail to forward at all, or the assumed amount,
    it can deduct a too high fee, but this would render completion of the transfer unlikely.

    The initiator of a mediated transfer will calculate fees based on the likely fees along the
    path. Note, it can not determin the path, as it does not know which nodes are available.

    Initial `amount` should be expected received amount + fees.

    Fees are always payable by the initiator.

    `initiator` is the party that knows the secret to the `hashlock`
    """

    cmdid = messages.MEDIATEDTRANSFER

    def __init__(self, nonce, asset, transfered_amount, recipient, locksroot,
                 lock, target, initiator, fee=0):

        if nonce > 2 ** 64:
            raise ValueError('nonce is too large')

        if fee > 2 ** 256:
            raise ValueError('fee is too large')

        if transfered_amount > 2 ** 256:
            raise ValueError('transfered_amount is too large')

        super(MediatedTransfer, self).__init__(nonce, asset, transfered_amount, recipient, locksroot, lock)
        self.target = target
        self.fee = fee
        self.initiator = initiator

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )

        mediated_transfer = MediatedTransfer(
            packed.nonce,
            packed.asset,
            packed.transfered_amount,
            packed.recipient,
            packed.locksroot,
            lock,
            packed.target,
            packed.initiator,
            packed.fee,
        )
        mediated_transfer.signature = packed.signature
        return mediated_transfer

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.asset = self.asset
        packed.transfered_amount = self.transfered_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.target = self.target
        packed.initiator = self.initiator
        packed.fee = self.fee

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.hashlock = lock.hashlock

        packed.signature = self.signature


class CancelTransfer(LockedTransfer):
    """ Indicates that no route is available, and that another path should be
    tried.
    """
    cmdid = messages.CANCELTRANSFER

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )

        locked_transfer = CancelTransfer(
            packed.nonce,
            packed.asset,
            packed.transfered_amount,
            packed.recipient,
            packed.locksroot,
            lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.asset = self.asset
        packed.transfered_amount = self.transfered_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.hashlock = lock.hashlock

        packed.signature = self.signature


class TransferTimeout(SignedMessage):
    """ Indicates that timeout happened during mediated transfer.

    This message is used when a node in a mediated chain doesn't consider any
    of it's following nodes available. If node `A` is trying to send a transfer
    to `D` throught `B1`, if `B1` consider all candidates for `c` unavailable
    it will send a TransferTimeout back to `A`. `A` can try all other
    candidates for `b` until it considers all it's paths unavailable.
    """
    cmdid = messages.TRANSFERTIMEOUT

    def __init__(self, echo, hashlock):
        super(TransferTimeout, self).__init__()
        self.echo = echo
        self.hashlock = hashlock

    @staticmethod
    def unpack(packed):
        transfer_timeout = TransferTimeout(
            packed.echo,
            packed.hashlock,
        )
        transfer_timeout.signature = packed.signature
        return transfer_timeout

    def pack(self, packed):
        packed.echo = self.echo
        packed.hashlock = self.hashlock
        packed.signature = self.signature


class ConfirmTransfer(SignedMessage):
    """ `ConfirmTransfer` which signs, that `target` has received a transfer. """
    cmdid = messages.CONFIRMTRANSFER

    def __init__(self, hashlock):
        super(ConfirmTransfer, self).__init__()
        self.hashlock = hashlock

    @staticmethod
    def unpack(packed):
        confirm_transfer = ConfirmTransfer(
            packed.hashlock,
        )
        confirm_transfer.signature = packed.signature
        return confirm_transfer

    def pack(self, packed):
        packed.hashlock = self.hashlock
        packed.signature = self.signature


CMDID_TO_CLASS = {
    messages.ACK: Ack,
    messages.PING: Ping,
    # REJECTED: Rejected,
    messages.SECRETREQUEST: SecretRequest,
    messages.SECRET: Secret,
    messages.DIRECTTRANSFER: DirectTransfer,
    # LockedTransfer is not intended to be sent across the wire, it is a
    # "marker" for messages with locks
    # messages.LOCKEDTRANSFER: LockedTransfer,
    messages.MEDIATEDTRANSFER: MediatedTransfer,
    messages.CANCELTRANSFER: CancelTransfer,
    messages.TRANSFERTIMEOUT: TransferTimeout,
    messages.CONFIRMTRANSFER: ConfirmTransfer,
}


def decode(data):
    klass = CMDID_TO_CLASS[data[0]]
    return klass.decode(data)
