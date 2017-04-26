# -*- coding: utf-8 -*-
from ethereum.slogging import getLogger
from ethereum.utils import big_endian_to_int

from raiden.encoding import messages, signing
from raiden.encoding.format import buffer_for
from raiden.utils import publickey_to_address, sha3, ishash, pex

__all__ = (
    'Ack',
    'Ping',
    'SecretRequest',
    'Secret',
    'DirectTransfer',
    'Lock',
    'LockedTransfer',
    'MediatedTransfer',
    'RefundTransfer',
)

log = getLogger(__name__)  # pylint: disable=invalid-name


def assert_transfer_values(identifier, nonce, token, transferred_amount, recipient):
    if identifier < 0:
        raise ValueError('identifier cannot be negative')

    if identifier >= 2 ** 64:
        raise ValueError('identifier is too large')

    if nonce <= 0:
        raise ValueError('nonce cannot be zero or negative')

    if nonce >= 2 ** 64:
        raise ValueError('nonce is too large')

    if len(token) != 20:
        raise ValueError('token is an invalid address')

    if transferred_amount < 0:
        raise ValueError('transferred_amount cannot be negative')

    if transferred_amount >= 2 ** 256:
        raise ValueError('transferred_amount is too large')

    if len(recipient) != 20:
        raise ValueError('recipient is an invalid address')


def decode(data):
    klass = CMDID_TO_CLASS[data[0]]
    return klass.decode(data)


class MessageHashable(object):
    pass


class Message(MessageHashable):
    # pylint: disable=no-member

    @property
    def hash(self):
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

        return '<{klass} [msghash={msghash}]>'.format(
            klass=self.__class__.__name__,
            msghash=pex(sha3(packed.data)),
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

    def sign(self, private_key, node_address):
        """ Sign message using `private_key`. """
        packed = self.packed()

        field = type(packed).fields_spec[-1]
        assert field.name == 'signature', 'signature is not the last field'

        # this slice must be from the end of the buffer
        message_data = packed.data[:-field.size_bytes]
        signature = signing.sign(message_data, private_key)

        packed.signature = signature

        self.sender = node_address
        self.signature = signature

    @classmethod
    def decode(cls, data):
        result = messages.wrap_and_validate(data)

        if result is None:
            return

        packed, public_key = result
        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = publickey_to_address(public_key)
        return message


class Ack(Message):
    """ All accepted messages should be confirmed by an `Ack` which echoes the
    orginals Message hash.

    We don't sign Acks because attack vector can be mitigated and to speed up
    things.
    """
    cmdid = messages.ACK

    def __init__(self, sender, echo):
        super(Ack, self).__init__()
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

    def __repr__(self):
        return '<{} [echohash:{}]>'.format(
            self.__class__.__name__,
            pex(self.echo),
        )


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


class SecretRequest(SignedMessage):
    """ Requests the secret which unlocks a hashlock. """
    cmdid = messages.SECRETREQUEST

    def __init__(self, identifier, hashlock, amount):
        super(SecretRequest, self).__init__()
        self.identifier = identifier
        self.hashlock = hashlock
        self.amount = amount

    def __repr__(self):
        return '<{} [hashlock:{} amount:{}]>'.format(
            self.__class__.__name__,
            pex(self.hashlock),
            self.amount,
        )

    @staticmethod
    def unpack(packed):
        secret_request = SecretRequest(packed.identifier, packed.hashlock, packed.amount)
        secret_request.signature = packed.signature
        return secret_request

    def pack(self, packed):
        packed.identifier = self.identifier
        packed.hashlock = self.hashlock
        packed.amount = self.amount
        packed.signature = self.signature


class Secret(SignedMessage):
    """ Message used to do state changes on a partner Raiden Channel.

    Locksroot changes need to be synchronized among both participants, the
    protocol is for only the side unlocking to send the Secret message allowing
    the other party to withdraw.
    """
    cmdid = messages.SECRET

    def __init__(self, identifier, secret, token):
        super(Secret, self).__init__()
        self.identifier = identifier
        self.secret = secret
        self.token = token
        self._hashlock = None

    def __repr__(self):
        return '<{} [sender:{} hashlock:{} token:{} hash:{}]>'.format(
            self.__class__.__name__,
            pex(self.sender),
            pex(self.hashlock),
            pex(self.token),
            pex(self.hash),
        )

    @property
    def hashlock(self):
        if self._hashlock is None:
            self._hashlock = sha3(self.secret)
        return self._hashlock

    @staticmethod
    def unpack(packed):
        secret = Secret(packed.identifier, packed.secret, packed.token)
        secret.signature = packed.signature
        return secret

    def pack(self, packed):
        packed.identifier = self.identifier
        packed.secret = self.secret
        packed.token = self.token
        packed.signature = self.signature


class RevealSecret(SignedMessage):
    """Message used to reveal a secret to party known to have interest in it.

    This message is not sufficient for state changes in the raiden Channel, the
    reason is that a node participating in split transfer or in both mediated
    transfer for an exchange might can reveal the secret to it's partners, but
    that must not update the internal channel state.
    """
    cmdid = messages.REVEALSECRET

    def __init__(self, secret):
        super(RevealSecret, self).__init__()
        self.secret = secret
        self._hashlock = None

    def __repr__(self):
        return '<{} [hashlock:{}]>'.format(
            self.__class__.__name__,
            pex(self.hashlock),
        )

    @property
    def hashlock(self):
        if self._hashlock is None:
            self._hashlock = sha3(self.secret)
        return self._hashlock

    @staticmethod
    def unpack(packed):
        reveal_secret = RevealSecret(packed.secret)
        reveal_secret.signature = packed.signature
        return reveal_secret

    def pack(self, packed):
        packed.secret = self.secret
        packed.signature = self.signature


class DirectTransfer(SignedMessage):
    """ A direct token exchange, used when both participants have a previously
    opened channel.

    Signs the unidirectional settled `balance` of `token` to `recipient` plus
    locked transfers.

    Settled refers to the inclusion of formerly locked amounts.
    Locked amounts are not included in the balance yet, but represented
    by the `locksroot`.

    Args:
        nonce: A sequential nonce, used to protected against replay attacks and
            to give a total order for the messages. This nonce is per
            participant, not shared.
        token: The address of the token being exchanged in the channel.
        transferred_amount: The total amount of token that was transferred to
            the channel partner. This value is monotonically increasing and can
            be larger than a channels deposit, since the channels are
            bidirecional.
        recipient: The address of the raiden node participating in the channel.
        locksroot: The root of a merkle tree which records the current
            outstanding locks.
    """

    cmdid = messages.DIRECTTRANSFER

    def __init__(self, identifier, nonce, token, transferred_amount, recipient, locksroot):
        assert_transfer_values(
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
        )

        super(DirectTransfer, self).__init__()
        self.identifier = identifier
        self.nonce = nonce
        self.token = token
        self.transferred_amount = transferred_amount  #: total amount of token sent to partner
        self.recipient = recipient  #: partner's address
        self.locksroot = locksroot  #: the merkle root that represent all pending locked transfers

    @staticmethod
    def unpack(packed):
        transfer = DirectTransfer(
            packed.identifier,
            packed.nonce,
            packed.token,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
        )
        transfer.signature = packed.signature

        return transfer

    def pack(self, packed):
        packed.identifier = self.identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.signature = self.signature


class Lock(MessageHashable):
    """ Describes a locked `amount`.

    Args:
        amount: Amount of the token being transferred.
        expiration: Highest block_number until which the transfer can be settled
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

        if amount >= 2 ** 256:
            raise ValueError('amount {} is too large'.format(amount))

        if expiration < 0:
            raise ValueError('expiration {} needs to be positive'.format(amount))

        if expiration >= 2 ** 256:
            raise ValueError('expiration {} is too large'.format(amount))

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

        # convert bytearray to bytes
        return bytes(self._asbytes)

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

    The token amount is implicitly represented in the `locksroot` and won't be
    reflected in the `transferred_amount` until the secret is revealed.

    This signs Carol, that she can claim locked_amount from Bob if she knows the secret to hashlock

    If the secret to hashlock becomes public, but Bob fails to sign Carol a netted balance,
    with an updated rootlock which reflects the deletion of the lock, then
    Carol can request settlement on chain by providing:
        any signed [nonce, token, balance, recipient, locksroot, ...]
        along a merkle proof from locksroot to the not yet netted formerly locked amount
    """
    def __init__(self, identifier, nonce, token, transferred_amount, recipient, locksroot, lock):
        super(LockedTransfer, self).__init__()

        assert_transfer_values(
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
        )

        self.identifier = identifier
        self.nonce = nonce
        self.token = token
        self.transferred_amount = transferred_amount
        self.recipient = recipient
        self.locksroot = locksroot
        self.lock = lock

    def to_mediatedtransfer(self, target, initiator='', fee=0):
        return MediatedTransfer(
            self.identifier,
            self.nonce,
            self.token,
            self.transferred_amount,
            self.recipient,
            self.locksroot,
            self.lock,
            target,
            initiator,
            fee,
        )

    def to_refundtransfer(self):
        return RefundTransfer(
            self.identifier,
            self.nonce,
            self.token,
            self.transferred_amount,
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
            packed.identifier,
            packed.nonce,
            packed.token,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
            lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.identifier = self.identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.hashlock = lock.hashlock

        packed.signature = self.signature


class MediatedTransfer(LockedTransfer):

    """
    A MediatedTransfer has a `target` address to which a chain of transfers shall
    be established. Here the `haslock` is mandatory.

    `fee` is the remaining fee a recipient shall use to complete the mediated transfer.
    The recipient can deduct his own fee from the amount and lower `fee` to the remaining fee.
    Just as the recipient can fail to forward at all, or the assumed amount,
    it can deduct a too high fee, but this would render completion of the transfer unlikely.

    The initiator of a mediated transfer will calculate fees based on the likely fees along the
    path. Note, it can not determine the path, as it does not know which nodes are available.

    Initial `amount` should be expected received amount + fees.

    Fees are always payable by the initiator.

    `initiator` is the party that knows the secret to the `hashlock`
    """

    cmdid = messages.MEDIATEDTRANSFER

    def __init__(
            self,
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
            locksroot,
            lock,
            target,
            initiator,
            fee=0):

        if len(target) != 20:
            raise ValueError('target is an invalid address')

        if len(initiator) != 20:
            raise ValueError('initiator is an invalid address')

        if fee >= 2 ** 256:
            raise ValueError('fee is too large')

        super(MediatedTransfer, self).__init__(
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
            locksroot,
            lock,
        )

        self.target = target
        self.fee = fee
        self.initiator = initiator

    def __repr__(self):
        representation = (
            '<{} [token:{} nonce:{} transferred_amount:{} lock_amount:{} hash:{} locksroot:{}]>'
        ).format(
            self.__class__.__name__,
            pex(self.token),
            self.nonce,
            self.transferred_amount,
            self.lock.amount,
            pex(self.hash),
            pex(self.locksroot),
        )

        return representation

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )

        mediated_transfer = MediatedTransfer(
            packed.identifier,
            packed.nonce,
            packed.token,
            packed.transferred_amount,
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
        packed.identifier = self.identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.transferred_amount = self.transferred_amount
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


class RefundTransfer(LockedTransfer):
    """ Indicates that no route is available and transfer the amount back to
    the previous node, allowing it to try another path to complete the
    transfer.
    """
    cmdid = messages.REFUNDTRANSFER

    def __init__(
            self,
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
            locksroot,
            lock):

        super(RefundTransfer, self).__init__(
            identifier,
            nonce,
            token,
            transferred_amount,
            recipient,
            locksroot,
            lock,
        )

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.hashlock,
        )

        locked_transfer = RefundTransfer(
            packed.identifier,
            packed.nonce,
            packed.token,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
            lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.token = self.token
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.hashlock = lock.hashlock

        packed.signature = self.signature


CMDID_TO_CLASS = {
    messages.ACK: Ack,
    messages.PING: Ping,
    messages.SECRETREQUEST: SecretRequest,
    messages.SECRET: Secret,
    messages.REVEALSECRET: RevealSecret,
    messages.DIRECTTRANSFER: DirectTransfer,
    messages.MEDIATEDTRANSFER: MediatedTransfer,
    messages.REFUNDTRANSFER: RefundTransfer,
}
