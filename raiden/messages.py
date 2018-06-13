# -*- coding: utf-8 -*-
from eth_utils import (
    big_endian_to_int,
    encode_hex,
    to_normalized_address,
    to_canonical_address,
)
import structlog

import raiden_libs.messages
from raiden_libs.utils import sign_data

from raiden.constants import (
    UINT256_MAX,
    UINT64_MAX,
)
from raiden.encoding import messages, signing
from raiden.encoding.format import buffer_for
from raiden.exceptions import InvalidProtocolMessage
from raiden.transfer.balance_proof import pack_signing_data
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.utils import (
    data_decoder,
    data_encoder,
    ishash,
    pex,
    sha3
)
from raiden.transfer.events import (
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    SendBalanceProof,
    SendLockedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
    SendSecretRequest,
)

__all__ = (
    'Delivered',
    'DirectTransfer',
    'Lock',
    'LockedTransfer',
    'LockedTransferBase',
    'Ping',
    'Processed',
    'RefundTransfer',
    'Secret',
    'SecretRequest',
    'SignedMessage',
    'decode',
    'from_dict',
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def assert_envelope_values(nonce, channel, transferred_amount, locked_amount, locksroot):
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

    if locked_amount < 0:
        raise ValueError('locked_amount cannot be negative')

    if locked_amount > UINT256_MAX:
        raise ValueError('locked_amount is too large')

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


def from_dict(data):
    try:
        klass = CLASSNAME_TO_CLASS[data['type']]
    except KeyError:
        raise InvalidProtocolMessage(
            'Invalid message type (data["type"] = {})'.format(data['type'])
        ) from None
    return klass.from_dict(data)


def message_from_sendevent(send_event, our_address):
    if type(send_event) == SendLockedTransfer:
        message = LockedTransfer.from_event(send_event)
    elif type(send_event) == SendDirectTransfer:
        message = DirectTransfer.from_event(send_event)
    elif type(send_event) == SendRevealSecret:
        message = RevealSecret.from_event(send_event)
    elif type(send_event) == SendBalanceProof:
        message = Secret.from_event(send_event)
    elif type(send_event) == SendSecretRequest:
        message = SecretRequest.from_event(send_event)
    elif type(send_event) == SendRefundTransfer:
        message = RefundTransfer.from_event(send_event)
    elif type(send_event) == SendProcessed:
        message = Processed.from_event(send_event, our_address)
    else:
        raise ValueError(f'Unknown event type {send_event}')

    return message


class Message:
    # Needs to be set by a subclass
    cmdid = None

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
        return '<{klass} [msghash={msghash}]>'.format(
            klass=self.__class__.__name__,
            msghash=pex(self.hash),
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

    @classmethod
    def unpack(cls, packed):
        raise NotImplementedError('Method needs to be implemented in a subclass.')

    def pack(self, packed):
        raise NotImplementedError('Method needs to be implemented in a subclass.')

    def to_dict(self):
        raise NotImplementedError('Method needs to be implemented in a subclass.')

    @classmethod
    def from_dict(cls, data):
        raise NotImplementedError('Method needs to be implemented in a subclass.')


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

        address = signing.recover_address(data_that_was_signed, message_signature)

        if address is None:
            return None

        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = address
        return message


class EnvelopeMessage(SignedMessage):
    def __init__(self):
        super().__init__()
        self.nonce = 0
        self.transferred_amount = 0
        self.locked_amount = 0
        self.locksroot = EMPTY_MERKLE_ROOT
        self.channel = b''
        self.token_network_address = b''

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
            klass.get_bytes_from(data, 'locked_amount'),
            klass.get_bytes_from(data, 'channel'),
            klass.get_bytes_from(data, 'locksroot'),
            self.message_hash,
        )
        signature = signing.sign(data_to_sign, private_key)

        packed.signature = signature

        self.sender = node_address
        self.signature = signature

    def sign2(self, private_key, node_address, chain_id):
        """ Creates the signature to the balance proof. Will be used in the SC refactoring. """
        balance_proof = raiden_libs.messages.BalanceProof(
            channel_identifier=self.channel,
            token_network_address=self.token_network_address,
            balance_hash=None,
            nonce=self.nonce,
            additional_hash=self.message_hash.decode(),
            chain_id=chain_id,
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )
        balance_proof.signature = encode_hex(
            sign_data(self.privkey, balance_proof.serialize_bin())
        )

        self.sender = node_address
        self.signature = balance_proof.signature

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
            message_type.get_bytes_from(data, 'locked_amount'),
            message_type.get_bytes_from(data, 'channel'),
            message_type.get_bytes_from(data, 'locksroot'),
            message_hash,
        )

        address = signing.recover_address(data_that_was_signed, message_signature)

        if address is None:
            return None

        message = cls.unpack(packed)  # pylint: disable=no-member
        message.sender = address
        return message


class Processed(SignedMessage):
    """ All accepted messages should be confirmed by a `Processed` message which echoes the
    orginals Message hash.

    We don't sign `Processed` messages because attack vector can be mitigated and to speed up
    things.
    """
    cmdid = messages.PROCESSED

    def __init__(self, sender, message_identifier):
        super().__init__()
        self.sender = sender
        self.message_identifier = message_identifier

    @classmethod
    def unpack(cls, packed):
        processed = cls(
            sender=packed.sender,
            message_identifier=packed.message_identifier,
        )
        processed.signature = packed.signature
        return processed

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.sender = self.sender
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event, sender):
        return cls(sender=sender, message_identifier=event.message_identifier)

    def __repr__(self):
        return '<{} [msgid:{}]>'.format(
            self.__class__.__name__,
            self.message_identifier,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'sender': to_normalized_address(self.sender),
            'message_identifier': self.message_identifier,
            'signature': data_encoder(self.signature)
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        processed = cls(
            sender=to_canonical_address(data['sender']),
            message_identifier=data['message_identifier'],
        )
        processed.signature = data_decoder(data['signature'])
        return processed


class Delivered(SignedMessage):
    """ Message used to inform the partner node that a message was received *and*
    persisted.
    """
    cmdid = messages.DELIVERED

    def __init__(self, delivered_message_identifier):
        super().__init__()
        self.delivered_message_identifier = delivered_message_identifier

    @classmethod
    def unpack(cls, packed):
        delivered = cls(
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

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'delivered_message_identifier': self.delivered_message_identifier,
            'signature': data_encoder(self.signature)
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        delivered = cls(
            delivered_message_identifier=data['delivered_message_identifier'],
        )
        delivered.signature = data_decoder(data['signature'])
        return delivered


class Pong(SignedMessage):
    """ Response to a Ping message. """
    cmdid = messages.PONG

    def __init__(self, nonce):
        super().__init__()
        self.nonce = nonce

    @staticmethod
    def unpack(packed):
        pong = Pong(nonce=packed.nonce)
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

    @classmethod
    def unpack(cls, packed):
        ping = cls(nonce=packed.nonce)
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

    @classmethod
    def unpack(cls, packed):
        secret_request = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            secrethash=packed.secrethash,
            amount=packed.amount,
        )
        secret_request.signature = packed.signature
        return secret_request

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.secrethash = self.secrethash
        packed.amount = self.amount
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            secrethash=event.secrethash,
            amount=event.amount,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secrethash': data_encoder(self.secrethash),
            'amount': self.amount,
            'signature': data_encoder(self.signature)
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        secret_request = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            secrethash=data_decoder(data['secrethash']),
            amount=data['amount'],
        )
        secret_request.signature = data_decoder(data['signature'])
        return secret_request


class Secret(EnvelopeMessage):
    """ Message used to do state changes on a partner Raiden Channel.

    Locksroot changes need to be synchronized among both participants, the
    protocol is for only the side unlocking to send the Secret message allowing
    the other party to claim the unlocked lock.
    """
    cmdid = messages.SECRET

    def __init__(
            self,
            message_identifier,
            payment_identifier,
            nonce,
            token_network_address,
            channel,
            transferred_amount,
            locked_amount,
            locksroot,
            secret,
    ):
        super().__init__()

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locked_amount,
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
        self.token_network_address = token_network_address
        self.channel = channel
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self._secrethash = None

    def __repr__(self):
        return (
            '<{} ['
            'msgid:{} paymentid:{} token_network:{} channel:{} nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} hash:{} secrethash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.token_network_address),
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.hash),
            pex(self.secrethash),
        )

    @property
    def secrethash(self):
        if self._secrethash is None:
            self._secrethash = sha3(self.secret)
        return self._secrethash

    @classmethod
    def unpack(cls, packed):
        secret = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            channel=packed.channel,
            transferred_amount=packed.transferred_amount,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            secret=packed.secret,
        )
        secret.signature = packed.signature
        return secret

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
        packed.locksroot = self.locksroot
        packed.secret = self.secret
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof
        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            channel=balance_proof.channel_address,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            secret=event.secret,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secret': data_encoder(self.secret),
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'channel': to_normalized_address(self.channel),
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'locksroot': data_encoder(self.locksroot),
            'signature': data_encoder(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        message = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            secret=data_decoder(data['secret']),
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            channel=to_canonical_address(data['channel']),
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            locksroot=data_decoder(data['locksroot']),
        )
        message.signature = data_decoder(data['signature'])
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

    @classmethod
    def unpack(cls, packed):
        reveal_secret = RevealSecret(
            message_identifier=packed.message_identifier,
            secret=packed.secret,
        )
        reveal_secret.signature = packed.signature
        return reveal_secret

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.secret = self.secret
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        return cls(
            message_identifier=event.message_identifier,
            secret=event.secret,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'secret': data_encoder(self.secret),
            'signature': data_encoder(self.signature)
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        return cls(
            message_identifier=data['message_identifier'],
            secret=data_decoder(data['secret']),
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
            token_network_address,
            token,
            channel,
            transferred_amount,
            locked_amount,
            recipient,
            locksroot,
    ):

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locked_amount,
            locksroot,
        )
        assert_transfer_values(payment_identifier, token, recipient)

        super().__init__()
        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.nonce = nonce
        self.token_network_address = token_network_address
        self.token = token
        self.channel = channel
        self.transferred_amount = transferred_amount  #: total amount of token sent to partner
        self.locked_amount = locked_amount  #: total amount of token locked in the merkle tree
        self.recipient = recipient  #: partner's address
        self.locksroot = locksroot  #: the merkle root that represent all pending locked transfers

    @classmethod
    def unpack(cls, packed):
        transfer = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel=packed.channel,
            transferred_amount=packed.transferred_amount,
            recipient=packed.recipient,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
        )
        transfer.signature = packed.signature

        return transfer

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token = self.token
        packed.token_network_address = self.token_network_address
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof

        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            token=event.token,
            channel=balance_proof.channel_address,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            recipient=event.recipient,
            locksroot=balance_proof.locksroot,
        )

    def __repr__(self):
        representation = (
            '<{} ['
            'msgid:{} paymentid:{} token_network:{} channel:{} nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} hash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.token_network_address),
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.hash),
        )

        return representation

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'token': to_normalized_address(self.token),
            'channel': to_normalized_address(self.channel),
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': data_encoder(self.locksroot),
            'signature': data_encoder(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        message = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            token=to_canonical_address(data['token']),
            channel=to_canonical_address(data['channel']),
            transferred_amount=data['transferred_amount'],
            recipient=to_canonical_address(data['recipient']),
            locked_amount=data['locked_amount'],
            locksroot=data_decoder(data['locksroot']),
        )
        message.signature = data_decoder(data['signature'])
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
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

    @classmethod
    def from_state(cls, state):
        lock = cls(
            amount=state.amount,
            expiration=state.expiration,
            secrethash=state.secrethash,
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
            'type': self.__class__.__name__,
            'amount': self.amount,
            'expiration': self.expiration,
            'secrethash': data_encoder(self.secrethash),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        return cls(
            amount=data['amount'],
            expiration=data['expiration'],
            secrethash=data_decoder(data['secrethash'])
        )


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
            token_network_address,
            token,
            channel,
            transferred_amount,
            locked_amount,
            recipient,
            locksroot,
            lock):
        super().__init__()

        assert_envelope_values(
            nonce,
            channel,
            transferred_amount,
            locked_amount,
            locksroot,
        )

        assert_transfer_values(payment_identifier, token, recipient)

        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.nonce = nonce
        self.token_network_address = token_network_address
        self.token = token
        self.channel = channel
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.recipient = recipient
        self.locksroot = locksroot
        self.lock = lock

    @classmethod
    def unpack(cls, packed):
        lock = Lock(
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

        locked_transfer = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel=packed.channel,
            transferred_amount=packed.transferred_amount,
            recipient=packed.recipient,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            lock=lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.token = self.token
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
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
            token_network_address,
            token,
            channel,
            transferred_amount,
            locked_amount,
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
            token_network_address,
            token,
            channel,
            transferred_amount,
            locked_amount,
            recipient,
            locksroot,
            lock,
        )

        self.target = target
        self.fee = fee
        self.initiator = initiator

    def __repr__(self):
        representation = (
            '<{} ['
            'msgid:{} paymentid:{} token_network:{} channel:{} nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} hash:{} secrethash:{} expiration:{} amount:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.token_network_address),
            pex(self.channel),
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.hash),
            pex(self.lock.secrethash),
            self.lock.expiration,
            self.lock.amount,
        )

        return representation

    @classmethod
    def unpack(cls, packed):
        lock = Lock(
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

        mediated_transfer = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel=packed.channel,
            transferred_amount=packed.transferred_amount,
            locked_amount=packed.locked_amount,
            recipient=packed.recipient,
            locksroot=packed.locksroot,
            lock=lock,
            target=packed.target,
            initiator=packed.initiator,
            fee=packed.fee,
        )
        mediated_transfer.signature = packed.signature
        return mediated_transfer

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.token = self.token
        packed.channel = self.channel
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
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

    @classmethod
    def from_event(cls, event: 'SendLockedTransfer') -> 'LockedTransfer':
        transfer = event.transfer
        lock = transfer.lock
        balance_proof = transfer.balance_proof
        lock = Lock(
            amount=lock.amount,
            expiration=lock.expiration,
            secrethash=lock.secrethash,
        )
        fee = 0

        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=transfer.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            token=transfer.token,
            channel=balance_proof.channel_address,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            recipient=event.recipient,
            locksroot=balance_proof.locksroot,
            lock=lock,
            target=transfer.target,
            initiator=transfer.initiator,
            fee=fee,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'token': to_normalized_address(self.token),
            'channel': to_normalized_address(self.channel),
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': data_encoder(self.locksroot),
            'lock': self.lock.to_dict(),
            'target': to_normalized_address(self.target),
            'initiator': to_normalized_address(self.initiator),
            'fee': self.fee,
            'signature': data_encoder(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        message = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            token=to_canonical_address(data['token']),
            channel=to_canonical_address(data['channel']),
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            recipient=to_canonical_address(data['recipient']),
            locksroot=data_decoder(data['locksroot']),
            lock=Lock.from_dict(data['lock']),
            target=to_canonical_address(data['target']),
            initiator=to_canonical_address(data['initiator']),
            fee=data['fee'],
        )
        message.signature = data_decoder(data['signature'])
        return message


class RefundTransfer(LockedTransfer):
    """ A special LockedTransfer sent from a payee to a payer indicating that
    no route is available, this transfer will effectively refund the payer the
    transfer amount allowing him to try a new path to complete the transfer.
    """
    cmdid = messages.REFUNDTRANSFER

    @classmethod
    def unpack(cls, packed):
        lock = Lock(
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

        locked_transfer = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel=packed.channel,
            transferred_amount=packed.transferred_amount,
            locked_amount=packed.locked_amount,
            recipient=packed.recipient,
            locksroot=packed.locksroot,
            lock=lock,
            target=packed.target,
            initiator=packed.initiator,
            fee=packed.fee,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof
        lock = Lock(
            amount=event.lock.amount,
            expiration=event.lock.expiration,
            secrethash=event.lock.secrethash,
        )
        fee = 0

        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            token=event.token,
            channel=balance_proof.channel_address,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            recipient=event.recipient,
            locksroot=balance_proof.locksroot,
            lock=lock,
            target=event.target,
            initiator=event.initiator,
            fee=fee,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'token': to_normalized_address(self.token),
            'channel': to_normalized_address(self.channel),
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': data_encoder(self.locksroot),
            'lock': self.lock.to_dict(),
            'target': to_normalized_address(self.target),
            'initiator': to_normalized_address(self.initiator),
            'fee': self.fee,
            'signature': data_encoder(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        message = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            token=to_canonical_address(data['token']),
            channel=to_canonical_address(data['channel']),
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            recipient=to_canonical_address(data['recipient']),
            locksroot=data_decoder(data['locksroot']),
            lock=Lock.from_dict(data['lock']),
            target=to_canonical_address(data['target']),
            initiator=to_canonical_address(data['initiator']),
            fee=data['fee'],
        )
        message.signature = data_decoder(data['signature'])
        return message


CMDID_TO_CLASS = {
    messages.DELIVERED: Delivered,
    messages.DIRECTTRANSFER: DirectTransfer,
    messages.LOCKEDTRANSFER: LockedTransfer,
    messages.PING: Ping,
    messages.PONG: Pong,
    messages.PROCESSED: Processed,
    messages.REFUNDTRANSFER: RefundTransfer,
    messages.REVEALSECRET: RevealSecret,
    messages.SECRET: Secret,
    messages.SECRETREQUEST: SecretRequest,
}

CLASSNAME_TO_CLASS = {klass.__name__: klass for klass in CMDID_TO_CLASS.values()}
