# -*- coding: utf-8 -*-
from binascii import unhexlify

from ethereum.slogging import getLogger
from ethereum.utils import big_endian_to_int

from raiden.constants import (
    UINT256_MAX,
    UINT64_MAX,
)
from raiden.encoding.format import buffer_for
from raiden.encoding import messages, signing
from raiden.encoding.signing import recover_publickey_safe
from raiden.utils import publickey_to_address, sha3, ishash, pex
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.exceptions import InvalidProtocolMessage
from raiden.transfer.balance_proof import pack_signing_data

__all__ = (
    'Processed',
    'Ping',
    'SecretRequest',
    'Secret',
    'DirectTransfer',
    'Lock',
    'LockedTransferBase',
    'LockedTransfer',
    'RefundTransfer',
)

log = getLogger(__name__)  # pylint: disable=invalid-name


def assert_envelope_values(nonce, channel, transferred_amount, locksroot):
    if nonce <= 0:
        raise ValueError('nonce cannot be zero or negative')

    if nonce > UINT64_MAX:
        raise ValueError('nonce is too large')

    if len(channel) != 20:
        raise ValueError('channel is an invalid address')

    if transferred_amount < 0:
        raise ValueError('transferred_amount cannot be negative')

    if transferred_amount > UINT256_MAX:
        raise ValueError('transferred_amount is too large')

    if len(locksroot) != 32:
        raise ValueError('locksroot must have length 32')


def assert_transfer_values(payment_identifier, token, recipient):
    if payment_identifier < 0:
        raise ValueError('payment_identifier cannot be negative')

    if payment_identifier > UINT64_MAX:
        raise ValueError('payment_identifier is too large')

    if len(token) != 20:
        raise ValueError('token is an invalid address')

    if len(recipient) != 20:
        raise ValueError('recipient is an invalid address')


def decode(data):
    try:
        klass = CMDID_TO_CLASS[data[0]]
    except KeyError:
        raise InvalidProtocolMessage('Invalid message type (data[0] = {})'.format(hex(data[0])))
    return klass.decode(data)


class Message:
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
    def decode(cls, data):
        packed = messages.wrap(data)
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
        super().__init__()
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
        packed = messages.wrap(data)

        if packed is None:
            return None

        # signature must be at the end
        message_type = type(packed)
        signature = message_type.fields_spec[-1]
        assert signature.name == 'signature', 'signature is not the last field'

        data_that_was_signed = data[:-signature.size_bytes]
        message_signature = data[-signature.size_bytes:]

        publickey = recover_publickey_safe(data_that_was_signed, message_signature)

        if publickey is None:
            return None

        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = publickey_to_address(publickey)
        return message


class EnvelopeMessage(SignedMessage):
    def __init__(self):
        super().__init__()
        self.nonce = 0
        self.transferred_amount = 0
        self.locksroot = EMPTY_MERKLE_ROOT
        self.channel = b''

    @property
    def message_hash(self):
        packed = self.packed()
        klass = type(packed)

        field = klass.fields_spec[-1]
        assert field.name == 'signature', 'signature is not the last field'

        data = packed.data
        message_data = data[:-field.size_bytes]
        message_hash = sha3(message_data)

        return message_hash

    def sign(self, private_key, node_address):
        packed = self.packed()
        klass = type(packed)

        field = klass.fields_spec[-1]
        assert field.name == 'signature', 'signature is not the last field'

        data = packed.data
        data_to_sign = pack_signing_data(
            klass.get_bytes_from(data, 'nonce'),
            klass.get_bytes_from(data, 'transferred_amount'),
            klass.get_bytes_from(data, 'channel'),
            klass.get_bytes_from(data, 'locksroot'),
            self.message_hash,
        )
        signature = signing.sign(data_to_sign, private_key)

        packed.signature = signature

        self.sender = node_address
        self.signature = signature

    @classmethod
    def decode(cls, data):
        packed = messages.wrap(data)

        if packed is None:
            return None

        # signature must be at the end
        message_type = type(packed)
        signature = message_type.fields_spec[-1]
        assert signature.name == 'signature', 'signature is not the last field'

        message_data = data[:-signature.size_bytes]
        message_signature = data[-signature.size_bytes:]
        message_hash = sha3(message_data)

        data_that_was_signed = pack_signing_data(
            message_type.get_bytes_from(data, 'nonce'),
            message_type.get_bytes_from(data, 'transferred_amount'),
            message_type.get_bytes_from(data, 'channel'),
            message_type.get_bytes_from(data, 'locksroot'),
            message_hash,
        )

        publickey = recover_publickey_safe(data_that_was_signed, message_signature)

        if publickey is None:
            return None

        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = publickey_to_address(publickey)
        return message


class Processed(SignedMessage):
    """ All accepted messages should be confirmed by a `Processed` message which echoes the
    orginals Message hash.

    We don't sign `Processed` messages because attack vector can be mitigated and to speed up
    things.
    """
    cmdid = messages.PROCESSED

    def __init__(self, sender, processed_message_identifier):
        super().__init__()
        self.sender = sender
        self.processed_message_identifier = processed_message_identifier

    @staticmethod
    def unpack(packed):
        processed = Processed(
            packed.sender,
            packed.processed_message_identifier,
        )
        processed.signature = packed.signature
        return processed

    def pack(self, packed):
        packed.processed_message_identifier = self.processed_message_identifier
        packed.sender = self.sender
        packed.signature = self.signature

    def __repr__(self):
        return '<{} [processed_msgid:{}]>'.format(
            self.__class__.__name__,
            self.processed_message_identifier,
        )


class Delivered(SignedMessage):
    cmdid = messages.DELIVERED

    def __init__(self, delivered_message_identifier):
        super().__init__()
        self.delivered_message_identifier = delivered_message_identifier

    @staticmethod
    def unpack(packed):
        delivered = Delivered(
            packed.delivered_message_identifier,
        )
        delivered.signature = packed.signature
        return delivered

    def pack(self, packed):
        packed.delivered_message_identifier = self.delivered_message_identifier
        packed.signature = self.signature

    def __repr__(self):
        return '<{} [delivered_msgid:{}]>'.format(
            self.__class__.__name__,
            self.delivered_message_identifier,
        )


class Pong(SignedMessage):
    """ Response to a Ping message. """
    cmdid = messages.PONG

    def __init__(self, nonce):
        super().__init__()
        self.nonce = nonce

    @staticmethod
    def unpack(packed):
        pong = Pong(packed.nonce)
        pong.signature = packed.signature
        return pong

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.signature = self.signature


class Ping(SignedMessage):
    """ Healthcheck message. """
    cmdid = messages.PING

    def __init__(self, nonce):
        super().__init__()
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
    """ Requests the secret which unlocks a secrethash. """
    cmdid = messages.SECRETREQUEST

    def __init__(self, message_identifier, payment_identifier, secrethash, amount):
        super().__init__()
        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.secrethash = secrethash
        self.amount = amount

    def __repr__(self):
        return '<{} [msgid:{} paymentid:{} secrethash:{} amount:{} hash:{}]>'.format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.secrethash),
            self.amount,
            pex(self.hash),
        )

    @staticmethod
    def unpack(packed):
        secret_request = SecretRequest(
            packed.message_identifier,
            packed.payment_identifier,
            packed.secrethash,
            packed.amount,
        )
        secret_request.signature = packed.signature
        return secret_request

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.secrethash = self.secrethash
        packed.amount = self.amount
        packed.signature = self.signature

    @staticmethod
    def from_event(event):
        return SecretRequest(
            event.message_identifier,
            event.payment_identifier,
            event.secrethash,
            event.amount,
        )

    def to_dict(self):
        return {
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secrethash': self.secrethash.hex(),
            'amount': self.amount,
        }

    @staticmethod
    def from_dict(data):
        return SecretRequest(
            data['message_identifier'],
            data['payment_identifier'],
            unhexlify(data['secrethash']),
            data['amount'],
        )


class Secret(EnvelopeMessage):
    """ Message used to do state changes on a partner Raiden Channel.

    Locksroot changes need to be synchronized among both participants, the
    protocol is for only the side unlocking to send the Secret message allowing
    the other party to withdraw.
    """
    cmdid = messages.SECRET

    def __init__(
            self,
            message_identifier,
            payment_identifier,
            nonce,
            channel,
            transferred_amount,
            locksroot,
            secret,
    ):
        super().__init__()

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locksroot,
        )

        if payment_identifier < 0:
            raise ValueError('payment_identifier cannot be negative')

        if payment_identifier > UINT64_MAX:
            raise ValueError('payment_identifier is too large')

        if len(secret) != 32:
            raise ValueError('secret must have 32 bytes')

        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.secret = secret
        self.nonce = nonce
        self.channel = channel
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self._secrethash = None

    def __repr__(self):
        return (
            '<{} [msgid:{} paymentid:{} channel:{} nonce:{} transferred_amount:{} locksroot:{} '
            'hash:{} secrethash:{}]>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            pex(self.locksroot),
            pex(self.hash),
            pex(self.secrethash),
        )

    @property
    def secrethash(self):
        if self._secrethash is None:
            self._secrethash = sha3(self.secret)
        return self._secrethash

    @staticmethod
    def unpack(packed):
        secret = Secret(
            packed.message_identifier,
            packed.payment_identifier,
            packed.nonce,
            packed.channel,
            packed.transferred_amount,
            packed.locksroot,
            packed.secret,
        )
        secret.signature = packed.signature
        return secret

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.locksroot = self.locksroot
        packed.secret = self.secret
        packed.signature = self.signature

    @staticmethod
    def from_event(event):
        return Secret(
            event.message_identifier,
            event.payment_identifier,
            event.balance_proof.nonce,
            event.balance_proof.channel_address,
            event.balance_proof.transferred_amount,
            event.balance_proof.locksroot,
            event.secret,
        )

    def to_dict(self):
        return {
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secret': self.secret.hex(),
            'nonce': self.nonce,
            'channel': self.channel.hex(),
            'transferred_amount': self.transferred_amount,
            'locksroot': self.locksroot.hex(),
            'signature': self.signature.hex(),
        }

    @staticmethod
    def from_dict(data):
        message = Secret(
            data['message_identifier'],
            data['payment_identifier'],
            unhexlify(data['secret']),
            data['nonce'],
            unhexlify(data['channel']),
            data['transferred_amount'],
            unhexlify(data['locksroot']),
        )
        message.signature = unhexlify(data['signature'])
        return message


class RevealSecret(SignedMessage):
    """Message used to reveal a secret to party known to have interest in it.

    This message is not sufficient for state changes in the raiden Channel, the
    reason is that a node participating in split transfer or in both mediated
    transfer for an exchange might can reveal the secret to it's partners, but
    that must not update the internal channel state.
    """
    cmdid = messages.REVEALSECRET

    def __init__(self, message_identifier, secret):
        super().__init__()
        self.message_identifier = message_identifier
        self.secret = secret
        self._secrethash = None

    def __repr__(self):
        return '<{} [msgid:{} secrethash:{} hash:{}]>'.format(
            self.__class__.__name__,
            self.message_identifier,
            pex(self.secrethash),
            pex(self.hash),
        )

    @property
    def secrethash(self):
        if self._secrethash is None:
            self._secrethash = sha3(self.secret)
        return self._secrethash

    @staticmethod
    def unpack(packed):
        reveal_secret = RevealSecret(
            packed.message_identifier,
            packed.secret,
        )
        reveal_secret.signature = packed.signature
        return reveal_secret

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.secret = self.secret
        packed.signature = self.signature

    @staticmethod
    def from_event(event):
        return RevealSecret(
            event.message_identifier,
            event.secret,
        )

    def to_dict(self):
        return {
            'message_identifier': self.message_identifier,
            'secret': self.secret.hex(),
        }

    @staticmethod
    def from_dict(data):
        return RevealSecret(
            data['message_identifier'],
            unhexlify(data['secret']),
        )


class DirectTransfer(EnvelopeMessage):
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

    def __init__(
            self,
            message_identifier,
            payment_identifier,
            nonce,
            token,
            channel,
            transferred_amount,
            recipient,
            locksroot):

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locksroot,
        )
        assert_transfer_values(payment_identifier, token, recipient)

        super().__init__()
        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.nonce = nonce
        self.token = token
        self.channel = channel
        self.transferred_amount = transferred_amount  #: total amount of token sent to partner
        self.recipient = recipient  #: partner's address
        self.locksroot = locksroot  #: the merkle root that represent all pending locked transfers

    @staticmethod
    def unpack(packed):
        transfer = DirectTransfer(
            packed.message_identifier,
            packed.payment_identifier,
            packed.nonce,
            packed.token,
            packed.channel,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
        )
        transfer.signature = packed.signature

        return transfer

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.signature = self.signature

    @staticmethod
    def from_event(event):
        balance_proof = event.balance_proof

        return DirectTransfer(
            event.message_identifier,
            event.payment_identifier,
            balance_proof.nonce,
            event.token,
            balance_proof.channel_address,
            balance_proof.transferred_amount,
            event.recipient,
            balance_proof.locksroot,
        )

    def __repr__(self):
        representation = (
            '<{} ['
            'msgid:{} paymentid:{} channel:{} nonce:{} transferred_amount:{} locksroot:{} hash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            pex(self.locksroot),
            pex(self.hash),
        )

        return representation

    def to_dict(self):
        return {
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token': self.token.hex(),
            'channel': self.channel.hex(),
            'transferred_amount': self.transferred_amount,
            'recipient': self.recipient.hex(),
            'locksroot': self.locksroot.hex(),
            'signature': self.signature.hex(),
        }

    @staticmethod
    def from_dict(data):
        message = DirectTransfer(
            data['message_identifier'],
            data['payment_identifier'],
            data['nonce'],
            unhexlify(data['token']),
            unhexlify(data['channel']),
            data['transferred_amount'],
            unhexlify(data['recipient']),
            unhexlify(data['locksroot']),
        )
        message.signature = unhexlify(data['signature'])
        return message


class Lock:
    """ Describes a locked `amount`.

    Args:
        amount: Amount of the token being transferred.
        expiration: Highest block_number until which the transfer can be settled
        secrethash: Hashed secret `sha3(secret)` used to register the transfer,
        the real `secret` is necessary to release the locked amount.
    """
    # Lock is not a message, it is a serializable structure that is reused in
    # some messages

    def __init__(self, amount, expiration, secrethash):
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

        assert ishash(secrethash)
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self._asbytes = None

    @property
    def as_bytes(self):
        if self._asbytes is None:
            packed = messages.Lock(buffer_for(messages.Lock))
            packed.amount = self.amount
            packed.expiration = self.expiration
            packed.secrethash = self.secrethash

            self._asbytes = packed.data

        # convert bytearray to bytes
        return bytes(self._asbytes)

    @property
    def lockhash(self):
        return sha3(self.as_bytes)

    @classmethod
    def from_bytes(cls, serialized):
        packed = messages.Lock(serialized)

        return cls(
            packed.amount,
            packed.expiration,
            packed.secrethash,
        )

    @staticmethod
    def from_state(state):
        lock = Lock(
            state.amount,
            state.expiration,
            state.secrethash,
        )

        return lock

    def __eq__(self, other):
        if isinstance(other, Lock):
            return self.as_bytes == other.as_bytes
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self):
        return {
            'amount': self.amount,
            'expiration': self.expiration,
            'secrethash': self.secrethash.hex(),
        }

    @staticmethod
    def from_dict(data):
        return Lock(data['amount'], data['expiration'], unhexlify(data['secrethash']))


class LockedTransferBase(EnvelopeMessage):
    """ A transfer which signs that the partner can claim `locked_amount` if
    she knows the secret to `secrethash`.

    The token amount is implicitly represented in the `locksroot` and won't be
    reflected in the `transferred_amount` until the secret is revealed.

    This signs Carol, that she can claim locked_amount from Bob if she knows
    the secret to secrethash.

    If the secret to secrethash becomes public, but Bob fails to sign Carol a
    netted balance, with an updated rootlock which reflects the deletion of the
    lock, then Carol can request settlement on chain by providing: any signed
    [nonce, token, balance, recipient, locksroot, ...] along a merkle proof
    from locksroot to the not yet netted formerly locked amount.
    """
    def __init__(
            self,
            message_identifier,
            payment_identifier,
            nonce,
            token,
            channel,
            transferred_amount,
            recipient,
            locksroot,
            lock):
        super().__init__()

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locksroot,
        )

        assert_transfer_values(payment_identifier, token, recipient)

        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.nonce = nonce
        self.token = token
        self.channel = channel
        self.transferred_amount = transferred_amount
        self.recipient = recipient
        self.locksroot = locksroot
        self.lock = lock

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.secrethash,
        )

        locked_transfer = LockedTransferBase(
            packed.message_identifier,
            packed.payment_identifier,
            packed.nonce,
            packed.token,
            packed.channel,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
            lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.secrethash = lock.secrethash

        packed.signature = self.signature


class LockedTransfer(LockedTransferBase):
    """
    A LockedTransfer has a `target` address to which a chain of transfers shall
    be established. Here the `secrethash` is mandatory.

    `fee` is the remaining fee a recipient shall use to complete the mediated transfer.
    The recipient can deduct his own fee from the amount and lower `fee` to the remaining fee.
    Just as the recipient can fail to forward at all, or the assumed amount,
    it can deduct a too high fee, but this would render completion of the transfer unlikely.

    The initiator of a mediated transfer will calculate fees based on the likely fees along the
    path. Note, it can not determine the path, as it does not know which nodes are available.

    Initial `amount` should be expected received amount + fees.

    Fees are always payable by the initiator.

    `initiator` is the party that knows the secret to the `secrethash`
    """

    cmdid = messages.LOCKEDTRANSFER

    def __init__(
            self,
            message_identifier,
            payment_identifier,
            nonce,
            token,
            channel,
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

        if fee > UINT256_MAX:
            raise ValueError('fee is too large')

        super().__init__(
            message_identifier,
            payment_identifier,
            nonce,
            token,
            channel,
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
            '<{} [msgid:{} paymentid:{} channel:{} nonce:{} transferred_amount:{} locksroot:{} '
            'hash:{} secrethash:{} expiration:{} amount:{}]>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            pex(self.locksroot),
            pex(self.hash),
            pex(self.lock.secrethash),
            self.lock.expiration,
            self.lock.amount,
        )

        return representation

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.secrethash,
        )

        mediated_transfer = LockedTransfer(
            packed.message_identifier,
            packed.payment_identifier,
            packed.nonce,
            packed.token,
            packed.channel,
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
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.target = self.target
        packed.initiator = self.initiator
        packed.fee = self.fee

        lock = self.lock
        packed.amount = lock.amount
        packed.expiration = lock.expiration
        packed.secrethash = lock.secrethash

        packed.signature = self.signature

    @staticmethod
    def from_event(event: 'SendLockedTransfer') -> 'LockedTransfer':
        transfer = event.transfer
        lock = transfer.lock
        balance_proof = transfer.balance_proof
        lock = Lock(
            lock.amount,
            lock.expiration,
            lock.secrethash,
        )
        fee = 0

        return LockedTransfer(
            event.message_identifier,
            transfer.payment_identifier,
            balance_proof.nonce,
            transfer.token,
            balance_proof.channel_address,
            balance_proof.transferred_amount,
            event.recipient,
            balance_proof.locksroot,
            lock,
            transfer.target,
            transfer.initiator,
            fee,
        )

    def to_dict(self):
        return {
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token': self.token.hex(),
            'channel': self.channel.hex(),
            'transferred_amount': self.transferred_amount,
            'recipient': self.recipient.hex(),
            'locksroot': self.locksroot.hex(),
            'lock': self.lock.to_dict(),
            'target': self.target.hex(),
            'initiator': self.initiator.hex(),
            'fee': self.fee,
            'signature': self.signature.hex(),
        }

    @staticmethod
    def from_dict(data):
        message = LockedTransfer(
            data['message_identifier'],
            data['payment_identifier'],
            data['nonce'],
            unhexlify(data['token']),
            unhexlify(data['channel']),
            data['transferred_amount'],
            unhexlify(data['recipient']),
            unhexlify(data['locksroot']),
            Lock.from_dict(data['lock']),
            unhexlify(data['target']),
            unhexlify(data['initiator']),
            data['fee'],
        )
        message.signature = unhexlify(data['signature'])
        return message


class RefundTransfer(LockedTransfer):
    """ A special LockedTransfer sent from a payee to a payer indicating that
    no route is available, this transfer will effectively refund the payer the
    transfer amount allowing him to try a new path to complete the transfer.
    """
    cmdid = messages.REFUNDTRANSFER

    @staticmethod
    def unpack(packed):
        lock = Lock(
            packed.amount,
            packed.expiration,
            packed.secrethash,
        )

        locked_transfer = RefundTransfer(
            packed.message_identifier,
            packed.payment_identifier,
            packed.nonce,
            packed.token,
            packed.channel,
            packed.transferred_amount,
            packed.recipient,
            packed.locksroot,
            lock,
            packed.target,
            packed.initiator,
            packed.fee,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    @staticmethod
    def from_event(event):
        balance_proof = event.balance_proof
        lock = Lock(
            event.lock.amount,
            event.lock.expiration,
            event.lock.secrethash,
        )
        fee = 0

        return RefundTransfer(
            event.payment_identifier,
            event.message_identifier,
            balance_proof.nonce,
            event.token,
            balance_proof.channel_address,
            balance_proof.transferred_amount,
            event.recipient,
            balance_proof.locksroot,
            lock,
            event.target,
            event.initiator,
            fee,
        )

    @staticmethod
    def from_dict(data):
        message = RefundTransfer(
            data['message_identifier'],
            data['payment_identifier'],
            data['nonce'],
            unhexlify(data['token']),
            unhexlify(data['channel']),
            data['transferred_amount'],
            unhexlify(data['recipient']),
            unhexlify(data['locksroot']),
            Lock.from_dict(data['lock']),
            unhexlify(data['target']),
            unhexlify(data['initiator']),
            data['fee'],
        )
        message.signature = unhexlify(data['signature'])
        return message


CMDID_TO_CLASS = {
    messages.PROCESSED: Processed,
    messages.PING: Ping,
    messages.PONG: Pong,
    messages.SECRETREQUEST: SecretRequest,
    messages.SECRET: Secret,
    messages.REVEALSECRET: RevealSecret,
    messages.DIRECTTRANSFER: DirectTransfer,
    messages.LOCKEDTRANSFER: LockedTransfer,
    messages.REFUNDTRANSFER: RefundTransfer,
    messages.DELIVERED: Delivered,
}
