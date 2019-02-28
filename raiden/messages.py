from operator import attrgetter

from cachetools import LRUCache, cached
from eth_utils import (
    big_endian_to_int,
    decode_hex,
    encode_hex,
    to_canonical_address,
    to_normalized_address,
)

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.encoding import messages
from raiden.encoding.format import buffer_for
from raiden.exceptions import InvalidProtocolMessage, InvalidSignature
from raiden.transfer.architecture import SendMessageEvent
from raiden.transfer.balance_proof import (
    pack_balance_proof,
    pack_balance_proof_update,
    pack_reward_proof,
)
from raiden.transfer.events import SendProcessed
from raiden.transfer.mediated_transfer.events import (
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils import CanonicalIdentifier, ishash, pex, sha3, typing
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    ChainID,
    ChannelID,
    Locksroot,
    MessageID,
    Optional,
    PaymentID,
    Secret,
    SecretHash,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
)

__all__ = (
    'Delivered',
    'EnvelopeMessage',
    'Lock',
    'LockedTransfer',
    'LockedTransferBase',
    'LockExpired',
    'Message',
    'Ping',
    'Pong',
    'Processed',
    'RefundTransfer',
    'RequestMonitoring',
    'RevealSecret',
    'SecretRequest',
    'SignedBlindedBalanceProof',
    'SignedMessage',
    'Unlock',
    'decode',
    'from_dict',
)

_senders_cache = LRUCache(maxsize=128)
_hashes_cache = LRUCache(maxsize=128)
_lock_bytes_cache = LRUCache(maxsize=128)


def assert_envelope_values(
        nonce: int,
        channel_identifier: ChannelID,
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
):
    if nonce <= 0:
        raise ValueError('nonce cannot be zero or negative')

    if nonce > UINT64_MAX:
        raise ValueError('nonce is too large')

    if channel_identifier < 0:
        raise ValueError('channel id cannot be negative')

    if channel_identifier > UINT256_MAX:
        raise ValueError('channel id is too large')

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


def decode(data: bytes) -> 'Message':
    try:
        klass = CMDID_TO_CLASS[data[0]]
    except KeyError:
        raise InvalidProtocolMessage('Invalid message type (CMDID = {})'.format(hex(data[0])))
    return klass.decode(data)


def from_dict(data: dict) -> 'Message':
    try:
        klass = CLASSNAME_TO_CLASS[data['type']]
    except KeyError:
        if 'type' in data:
            raise InvalidProtocolMessage(
                'Invalid message type (data["type"] = {})'.format(data['type']),
            ) from None
        else:
            raise InvalidProtocolMessage(
                'Invalid message data. Can not find the data type',
            ) from None
    return klass.from_dict(data)


def message_from_sendevent(send_event: SendMessageEvent, our_address: Address) -> 'Message':
    if type(send_event) == SendLockedTransfer:
        message = LockedTransfer.from_event(send_event)
    elif type(send_event) == SendSecretReveal:
        message = RevealSecret.from_event(send_event)
    elif type(send_event) == SendBalanceProof:
        message = Unlock.from_event(send_event)
    elif type(send_event) == SendSecretRequest:
        message = SecretRequest.from_event(send_event)
    elif type(send_event) == SendRefundTransfer:
        message = RefundTransfer.from_event(send_event)
    elif type(send_event) == SendLockExpired:
        message = LockExpired.from_event(send_event)
    elif type(send_event) == SendProcessed:
        message = Processed.from_event(send_event)
    else:
        raise ValueError(f'Unknown event type {send_event}')

    return message


class Message:
    # Needs to be set by a subclass
    cmdid = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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


class AuthenticatedMessage(Message):
    """ Message, that has a sender. """

    def sender(self) -> typing.Address:
        raise NotImplementedError('Property needs to be implemented in subclass.')


class SignedMessage(AuthenticatedMessage):
    # signing is a bit problematic, we need to pack the data to sign, but the
    # current API assumes that signing is called before, this can be improved
    # by changing the order to packing then signing
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.signature = b''

    def _data_to_sign(self) -> bytes:
        """ Return the binary data to be/which was signed """
        packed = self.packed()

        field = type(packed).fields_spec[-1]
        assert field.name == 'signature', 'signature is not the last field'

        # this slice must be from the end of the buffer
        return packed.data[:-field.size_bytes]

    def sign(self, signer: Signer):
        """ Sign message using signer. """
        message_data = self._data_to_sign()
        self.signature = signer.sign(data=message_data)

    @property
    @cached(_senders_cache, key=attrgetter('signature'))
    def sender(self) -> Optional[Address]:
        if not self.signature:
            return None
        data_that_was_signed = self._data_to_sign()
        message_signature = self.signature

        try:
            address: Optional[Address] = recover(
                data=data_that_was_signed,
                signature=message_signature,
            )
        except InvalidSignature:
            address = None
        return address

    @classmethod
    def decode(cls, data):
        packed = messages.wrap(data)

        if packed is None:
            return None

        return cls.unpack(packed)


class RetrieableMessage:
    """ Message, that supports a retry-queue. """

    def __init__(self, *, message_identifier: MessageID, **kwargs):
        self.message_identifier = message_identifier


class SignedRetrieableMessage(SignedMessage, RetrieableMessage):
    """ Mixin of SignedMessage and RetrieableMessage. """

    def __init__(self, *, message_identifier: MessageID, **kwargs):
        super().__init__(message_identifier=message_identifier, **kwargs)


class EnvelopeMessage(SignedRetrieableMessage):
    def __init__(
            self,
            *,
            chain_id: ChainID,
            message_identifier: MessageID,
            nonce: typing.Nonce,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            locksroot: Locksroot,
            channel_identifier: ChannelID,
            token_network_address: TokenNetworkAddress,
            **kwargs,
    ):
        super().__init__(message_identifier=message_identifier, **kwargs)
        assert_envelope_values(
            nonce,
            channel_identifier,
            transferred_amount,
            locked_amount,
            locksroot,
        )
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.channel_identifier = channel_identifier
        self.token_network_address = token_network_address
        self.chain_id = chain_id

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

    def _data_to_sign(self) -> bytes:
        balance_hash = hash_balance_data(
            self.transferred_amount,
            self.locked_amount,
            self.locksroot,
        )
        balance_proof_packed = pack_balance_proof(
            nonce=self.nonce,
            balance_hash=balance_hash,
            additional_hash=self.message_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.chain_id,
                token_network_address=self.token_network_address,
                channel_identifier=self.channel_identifier,
            ),
        )
        return balance_proof_packed


class Processed(SignedRetrieableMessage):
    """ All accepted messages should be confirmed by a `Processed` message which echoes the
    orginals Message hash.
    """
    # FIXME: Processed should _not_ be SignedRetrieableMessage, but only SignedMessage
    cmdid = messages.PROCESSED

    def __init__(self, *, message_identifier: MessageID, **kwargs):
        super().__init__(message_identifier=message_identifier, **kwargs)

    @classmethod
    def unpack(cls, packed):
        processed = cls(
            message_identifier=packed.message_identifier,
        )
        processed.signature = packed.signature
        return processed

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        return cls(message_identifier=event.message_identifier)

    def __repr__(self):
        return '<{} [msgid:{}]>'.format(
            self.__class__.__name__,
            self.message_identifier,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        processed = cls(
            message_identifier=data['message_identifier'],
        )
        processed.signature = decode_hex(data['signature'])
        return processed


class Delivered(SignedMessage):
    """ Message used to inform the partner node that a message was received *and*
    persisted.
    """
    cmdid = messages.DELIVERED

    def __init__(self, *, delivered_message_identifier: MessageID, **kwargs):
        super().__init__(**kwargs)
        self.delivered_message_identifier = delivered_message_identifier

    @classmethod
    def unpack(cls, packed):
        delivered = cls(
            delivered_message_identifier=packed.delivered_message_identifier,
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
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        delivered = cls(
            delivered_message_identifier=data['delivered_message_identifier'],
        )
        delivered.signature = decode_hex(data['signature'])
        return delivered


class Pong(SignedMessage):
    """ Response to a Ping message. """
    cmdid = messages.PONG

    def __init__(self, *, nonce: int, **kwargs):
        super().__init__(**kwargs)
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

    def __init__(
            self,
            nonce: typing.Nonce,
            current_protocol_version: typing.RaidenProtocolVersion,
            **kwargs,
    ):
        super().__init__(**kwargs)
        self.nonce = nonce
        self.current_protocol_version = current_protocol_version

    @classmethod
    def unpack(cls, packed):
        ping = cls(
            nonce=packed.nonce,
            current_protocol_version=packed.current_protocol_version,
        )
        ping.signature = packed.signature
        return ping

    def pack(self, packed):
        packed.nonce = self.nonce
        packed.current_protocol_version = self.current_protocol_version
        packed.signature = self.signature


class SecretRequest(SignedRetrieableMessage):
    """ Requests the secret which unlocks a secrethash. """
    cmdid = messages.SECRETREQUEST

    def __init__(
            self,
            *,
            message_identifier: MessageID,
            payment_identifier: PaymentID,
            secrethash: SecretHash,
            amount: typing.PaymentAmount,
            expiration: typing.BlockExpiration,
            **kwargs,
    ):
        super().__init__(message_identifier=message_identifier, **kwargs)
        self.payment_identifier = payment_identifier
        self.secrethash = secrethash
        self.amount = amount
        self.expiration = expiration

    def __repr__(self):
        return (
            '<{} '
            '[msgid:{} paymentid:{} secrethash:{} amount:{} expiration:{} hash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.message_identifier,
            self.payment_identifier,
            pex(self.secrethash),
            self.amount,
            self.expiration,
            pex(self.hash),
        )

    @classmethod
    def unpack(cls, packed):
        secret_request = cls(
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            secrethash=packed.secrethash,
            amount=packed.amount,
            expiration=packed.expiration,
        )
        secret_request.signature = packed.signature
        return secret_request

    def pack(self, packed):
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.secrethash = self.secrethash
        packed.amount = self.amount
        packed.expiration = self.expiration
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            secrethash=event.secrethash,
            amount=event.amount,
            expiration=event.expiration,
        )

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secrethash': encode_hex(self.secrethash),
            'amount': self.amount,
            'expiration': self.expiration,
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        secret_request = cls(
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            secrethash=decode_hex(data['secrethash']),
            amount=data['amount'],
            expiration=data['expiration'],
        )
        secret_request.signature = decode_hex(data['signature'])
        return secret_request


class Unlock(EnvelopeMessage):
    """ Message used to do state changes on a partner Raiden Channel.

    Locksroot changes need to be synchronized among both participants, the
    protocol is for only the side unlocking to send the Unlock message allowing
    the other party to claim the unlocked lock.
    """
    cmdid = messages.UNLOCK

    def __init__(
            self,
            *,
            chain_id: ChainID,
            message_identifier: MessageID,
            payment_identifier: PaymentID,
            nonce: int,
            token_network_address: TokenNetworkAddress,
            channel_identifier: ChannelID,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            locksroot: Locksroot,
            secret: Secret,
            **kwargs,
    ):
        super().__init__(
            chain_id=chain_id,
            nonce=nonce,
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            channel_identifier=channel_identifier,
            token_network_address=token_network_address,
            message_identifier=message_identifier,
            **kwargs,
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

    def __repr__(self):
        return (
            '<{} ['
            'chainid:{} msgid:{} paymentid:{} token_network:{} channel_identifier:{} '
            'nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} hash:{} secrethash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.chain_id,
            self.message_identifier,
            self.payment_identifier,
            pex(self.token_network_address),
            self.channel_identifier,
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.hash),
            pex(self.secrethash),
        )

    @property
    @cached(_hashes_cache, key=attrgetter('secret'))
    def secrethash(self):
        return sha3(self.secret)

    @classmethod
    def unpack(cls, packed):
        secret = cls(
            chain_id=packed.chain_id,
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            channel_identifier=packed.channel_identifier,
            transferred_amount=packed.transferred_amount,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            secret=packed.secret,
        )
        secret.signature = packed.signature
        return secret

    def pack(self, packed):
        packed.chain_id = self.chain_id
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.channel_identifier = self.channel_identifier
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
        packed.locksroot = self.locksroot
        packed.secret = self.secret
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof
        return cls(
            chain_id=balance_proof.chain_id,
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            channel_identifier=balance_proof.channel_identifier,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            secret=event.secret,
        )

    def to_dict(self):
        return {
            'type': 'Secret',
            'chain_id': self.chain_id,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'secret': encode_hex(self.secret),
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'channel_identifier': self.channel_identifier,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'locksroot': encode_hex(self.locksroot),
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == 'Secret'
        message = cls(
            chain_id=data['chain_id'],
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            secret=decode_hex(data['secret']),
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            channel_identifier=data['channel_identifier'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            locksroot=decode_hex(data['locksroot']),
        )
        message.signature = decode_hex(data['signature'])
        return message


class RevealSecret(SignedRetrieableMessage):
    """Message used to reveal a secret to party known to have interest in it.

    This message is not sufficient for state changes in the raiden Channel, the
    reason is that a node participating in split transfer or in both mediated
    transfer for an exchange might can reveal the secret to it's partners, but
    that must not update the internal channel state.
    """
    cmdid = messages.REVEALSECRET

    def __init__(self, *, message_identifier: MessageID, secret: Secret, **kwargs):
        super().__init__(message_identifier=message_identifier, **kwargs)
        self.secret = secret

    def __repr__(self):
        return '<{} [msgid:{} secrethash:{} hash:{}]>'.format(
            self.__class__.__name__,
            self.message_identifier,
            pex(self.secrethash),
            pex(self.hash),
        )

    @property
    @cached(_hashes_cache, key=attrgetter('secret'))
    def secrethash(self):
        return sha3(self.secret)

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
            'secret': encode_hex(self.secret),
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        reveal_secret = cls(
            message_identifier=data['message_identifier'],
            secret=decode_hex(data['secret']),
        )
        reveal_secret.signature = decode_hex(data['signature'])
        return reveal_secret


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

    def __init__(
            self,
            *,
            amount: TokenAmount,
            expiration: BlockExpiration,
            secrethash: SecretHash,
            **kwargs,
    ):
        super().__init__(**kwargs)
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

    @property
    @cached(_lock_bytes_cache, key=attrgetter('amount', 'expiration', 'secrethash'))
    def as_bytes(self):
        packed = messages.Lock(buffer_for(messages.Lock))
        packed.amount = self.amount
        packed.expiration = self.expiration
        packed.secrethash = self.secrethash

        # convert bytearray to bytes
        return bytes(packed.data)

    @property
    @cached(_hashes_cache, key=attrgetter('as_bytes'))
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
            'secrethash': encode_hex(self.secrethash),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        return cls(
            amount=data['amount'],
            expiration=data['expiration'],
            secrethash=decode_hex(data['secrethash']),
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
            *,
            chain_id: ChainID,
            message_identifier: MessageID,
            payment_identifier: PaymentID,
            nonce: int,
            token_network_address: TokenNetworkAddress,
            token: TokenAddress,
            channel_identifier: ChannelID,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            recipient: Address,
            locksroot: Locksroot,
            lock: HashTimeLockState,
            **kwargs,
    ):
        super().__init__(
            chain_id=chain_id,
            nonce=nonce,
            transferred_amount=transferred_amount,
            message_identifier=message_identifier,
            locked_amount=locked_amount,
            locksroot=locksroot,
            channel_identifier=channel_identifier,
            token_network_address=token_network_address,
            **kwargs,
        )
        assert_transfer_values(payment_identifier, token, recipient)
        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.token = token
        self.recipient = recipient
        self.lock = lock

    @classmethod
    def unpack(cls, packed):
        lock = Lock(
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

        locked_transfer = cls(
            chain_id=packed.chain_id,
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel_identifier=packed.channel_identifier,
            transferred_amount=packed.transferred_amount,
            recipient=packed.recipient,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            lock=lock,
        )
        locked_transfer.signature = packed.signature
        return locked_transfer

    def pack(self, packed):
        packed.chain_id = self.chain_id
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.token = self.token
        packed.channel_identifier = self.channel_identifier
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
            *,
            chain_id: ChainID,
            message_identifier: MessageID,
            payment_identifier: PaymentID,
            nonce: int,
            token_network_address: TokenNetworkAddress,
            token: TokenAddress,
            channel_identifier: ChannelID,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            recipient: Address,
            locksroot: Locksroot,
            lock: HashTimeLockState,
            target: Address,
            initiator: Address,
            fee: int = 0,
            **kwargs,
    ):

        if len(target) != 20:
            raise ValueError('target is an invalid address')

        if len(initiator) != 20:
            raise ValueError('initiator is an invalid address')

        if fee > UINT256_MAX:
            raise ValueError('fee is too large')

        super().__init__(
            chain_id=chain_id,
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
            lock=lock,
            **kwargs,
        )

        self.target = target
        self.fee = fee
        self.initiator = initiator

    def __repr__(self):
        representation = (
            '<{} ['
            'chainid:{} msgid:{} paymentid:{} token_network:{} channel_identifier:{} '
            'nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} hash:{} secrethash:{} expiration:{} amount:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.chain_id,
            self.message_identifier,
            self.payment_identifier,
            pex(self.token_network_address),
            self.channel_identifier,
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
            chain_id=packed.chain_id,
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel_identifier=packed.channel_identifier,
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
        packed.chain_id = self.chain_id
        packed.message_identifier = self.message_identifier
        packed.payment_identifier = self.payment_identifier
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.token = self.token
        packed.channel_identifier = self.channel_identifier
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
            chain_id=balance_proof.chain_id,
            message_identifier=event.message_identifier,
            payment_identifier=transfer.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=TokenNetworkAddress(balance_proof.token_network_identifier),
            token=transfer.token,
            channel_identifier=balance_proof.channel_identifier,
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
            'chain_id': self.chain_id,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'token': to_normalized_address(self.token),
            'channel_identifier': self.channel_identifier,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': encode_hex(self.locksroot),
            'lock': self.lock.to_dict(),
            'target': to_normalized_address(self.target),
            'initiator': to_normalized_address(self.initiator),
            'fee': self.fee,
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        message = cls(
            chain_id=data['chain_id'],
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            token=to_canonical_address(data['token']),
            channel_identifier=data['channel_identifier'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            recipient=to_canonical_address(data['recipient']),
            locksroot=decode_hex(data['locksroot']),
            lock=Lock.from_dict(data['lock']),
            target=to_canonical_address(data['target']),
            initiator=to_canonical_address(data['initiator']),
            fee=data['fee'],
        )
        message.signature = decode_hex(data['signature'])
        return message


class RefundTransfer(LockedTransfer):
    """ A special LockedTransfer sent from a payee to a payer indicating that
    no route is available, this transfer will effectively refund the payer the
    transfer amount allowing him to try a new path to complete the transfer.
    """
    cmdid = messages.REFUNDTRANSFER

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def unpack(cls, packed):
        lock = Lock(
            amount=packed.amount,
            expiration=packed.expiration,
            secrethash=packed.secrethash,
        )

        locked_transfer = cls(
            chain_id=packed.chain_id,
            message_identifier=packed.message_identifier,
            payment_identifier=packed.payment_identifier,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            token=packed.token,
            channel_identifier=packed.channel_identifier,
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
        transfer = event.transfer
        balance_proof = transfer.balance_proof
        lock = Lock(
            amount=transfer.lock.amount,
            expiration=transfer.lock.expiration,
            secrethash=transfer.lock.secrethash,
        )
        fee = 0

        return cls(
            chain_id=balance_proof.chain_id,
            message_identifier=event.message_identifier,
            payment_identifier=transfer.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            token=transfer.token,
            channel_identifier=balance_proof.channel_identifier,
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
            'chain_id': self.chain_id,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'token': to_normalized_address(self.token),
            'channel_identifier': self.channel_identifier,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': encode_hex(self.locksroot),
            'lock': self.lock.to_dict(),
            'target': to_normalized_address(self.target),
            'initiator': to_normalized_address(self.initiator),
            'fee': self.fee,
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        message = cls(
            chain_id=data['chain_id'],
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            nonce=data['nonce'],
            token_network_address=to_canonical_address(data['token_network_address']),
            token=to_canonical_address(data['token']),
            channel_identifier=data['channel_identifier'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            recipient=to_canonical_address(data['recipient']),
            locksroot=decode_hex(data['locksroot']),
            lock=Lock.from_dict(data['lock']),
            target=to_canonical_address(data['target']),
            initiator=to_canonical_address(data['initiator']),
            fee=data['fee'],
        )
        message.signature = decode_hex(data['signature'])
        return message


class LockExpired(EnvelopeMessage):
    """Message used to notify opposite channel participant that a lock has
    expired.
    """
    cmdid = messages.LOCKEXPIRED

    def __init__(
            self,
            *,
            chain_id: ChainID,
            nonce: int,
            message_identifier: MessageID,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            locksroot: Locksroot,
            channel_identifier: ChannelID,
            token_network_address: TokenNetworkAddress,
            recipient: Address,
            secrethash: SecretHash,
            **kwargs,
    ):

        super().__init__(
            chain_id=chain_id,
            nonce=nonce,
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            channel_identifier=channel_identifier,
            token_network_address=token_network_address,
            message_identifier=message_identifier,
            **kwargs,
        )
        self.message_identifier = message_identifier
        self.recipient = recipient
        self.secrethash = secrethash

    @classmethod
    def unpack(cls, packed):
        transfer = cls(
            chain_id=packed.chain_id,
            nonce=packed.nonce,
            message_identifier=packed.message_identifier,
            token_network_address=packed.token_network_address,
            channel_identifier=packed.channel_identifier,
            transferred_amount=packed.transferred_amount,
            recipient=packed.recipient,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            secrethash=packed.secrethash,
        )
        transfer.signature = packed.signature

        return transfer

    def pack(self, packed):
        packed.chain_id = self.chain_id
        packed.nonce = self.nonce
        packed.message_identifier = self.message_identifier
        packed.token_network_address = self.token_network_address
        packed.channel_identifier = self.channel_identifier
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
        packed.recipient = self.recipient
        packed.locksroot = self.locksroot
        packed.secrethash = self.secrethash
        packed.signature = self.signature

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof

        return cls(
            chain_id=balance_proof.chain_id,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_identifier,
            channel_identifier=balance_proof.channel_identifier,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            message_identifier=event.message_identifier,
            recipient=event.recipient,
            secrethash=event.secrethash,
        )

    def __repr__(self):
        representation = (
            '<{} ['
            'chainid:{} token_network_address:{} msg_id:{} channel_identifier:{} nonce:{} '
            'transferred_amount:{} locked_amount:{} locksroot:{} secrethash:{}'
            ']>'
        ).format(
            self.__class__.__name__,
            self.chain_id,
            pex(self.token_network_address),
            self.message_identifier,
            self.channel_identifier,
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.secrethash),
        )

        return representation

    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'chain_id': self.chain_id,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'message_identifier': self.message_identifier,
            'channel_identifier': self.channel_identifier,
            'secrethash': encode_hex(self.secrethash),
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'recipient': to_normalized_address(self.recipient),
            'locksroot': encode_hex(self.locksroot),
            'signature': encode_hex(self.signature),
        }

    @classmethod
    def from_dict(cls, data):
        assert data['type'] == cls.__name__
        expired_lock = cls(
            chain_id=data['chain_id'],
            nonce=data['nonce'],
            message_identifier=data['message_identifier'],
            token_network_address=to_canonical_address(data['token_network_address']),
            channel_identifier=data['channel_identifier'],
            transferred_amount=data['transferred_amount'],
            secrethash=decode_hex(data['secrethash']),
            recipient=to_canonical_address(data['recipient']),
            locked_amount=data['locked_amount'],
            locksroot=decode_hex(data['locksroot']),
        )
        expired_lock.signature = decode_hex(data['signature'])
        return expired_lock


class SignedBlindedBalanceProof:
    """Message sub-field `onchain_balance_proof` for `RequestMonitoring`.
    """

    def __init__(
            self,
            *,
            channel_identifier: typing.ChannelID,
            token_network_address: typing.TokenNetworkID,
            nonce: typing.Nonce,
            additional_hash: typing.AdditionalHash,
            chain_id: typing.ChainID,
            signature: typing.Signature,
            balance_hash: typing.BalanceHash,
            **kwargs,
    ):

        super().__init__(**kwargs)
        self.channel_identifier = channel_identifier
        self.token_network_address = token_network_address
        self.nonce = nonce
        self.additional_hash = additional_hash
        self.chain_id = chain_id
        self.balance_hash = balance_hash
        self.signature = signature
        if not signature:
            raise ValueError('balance proof is not signed')
        self.non_closing_signature = None

    @classmethod
    def from_balance_proof_signed_state(
            cls,
            balance_proof: BalanceProofSignedState,
    ) -> 'SignedBlindedBalanceProof':
        assert isinstance(balance_proof, BalanceProofSignedState)
        return cls(
            channel_identifier=balance_proof.channel_identifier,
            token_network_address=typing.TokenNetworkID(balance_proof.token_network_identifier),
            nonce=balance_proof.nonce,
            additional_hash=balance_proof.message_hash,
            chain_id=balance_proof.chain_id,
            signature=balance_proof.signature,
            balance_hash=hash_balance_data(
                balance_proof.transferred_amount,
                balance_proof.locked_amount,
                balance_proof.locksroot,
            ),
        )

    def _data_to_sign(self) -> bytes:
        packed = pack_balance_proof_update(
            nonce=self.nonce,
            balance_hash=self.balance_hash,
            additional_hash=self.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.chain_id,
                token_network_address=self.token_network_address,
                channel_identifier=self.channel_identifier,
            ),
            partner_signature=self.signature,
        )
        return packed

    def _sign(self, signer: Signer) -> typing.Signature:
        """Internal function for the overall `sign` function of `RequestMonitoring`.
        """
        # Important: we don't write the signature to `.signature`
        data = self._data_to_sign()
        return signer.sign(data)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        """Message format according to monitoring service spec"""
        return {
            'type': self.__class__.__name__,
            'channel_identifier': self.channel_identifier,
            'token_network_address': to_normalized_address(self.token_network_address),
            'balance_hash': encode_hex(self.balance_hash),
            'nonce': self.nonce,
            'additional_hash': encode_hex(self.additional_hash),
            'signature': encode_hex(self.signature),
            'chain_id': self.chain_id,
        }

    @classmethod
    def from_dict(
            cls,
            data: typing.Dict,
    ) -> 'SignedBlindedBalanceProof':
        assert data['type'] == cls.__name__
        return cls(
            channel_identifier=data['channel_identifier'],
            token_network_address=decode_hex(data['token_network_address']),
            balance_hash=decode_hex(data['balance_hash']),
            nonce=typing.Nonce(int(data['nonce'])),
            additional_hash=decode_hex(data['additional_hash']),
            signature=decode_hex(data['signature']),
            chain_id=typing.ChainID(int(data['chain_id'])),
        )


class RequestMonitoring(SignedMessage):
    """Message to request channel watching from a monitoring service.
    Spec:
        https://raiden-network-specification.readthedocs.io/en/latest/monitoring_service.html\
#monitor-request
    """

    def __init__(
            self,
            *,
            onchain_balance_proof: SignedBlindedBalanceProof,
            reward_amount: typing.TokenAmount,
            non_closing_signature: typing.Signature = b'',
            reward_proof_signature: typing.Signature = b'',
            **kwargs,
    ):
        super().__init__(**kwargs)
        if onchain_balance_proof is None:
            raise ValueError('no balance proof given')
        self.balance_proof = onchain_balance_proof
        self.reward_amount = reward_amount
        if non_closing_signature:
            self.non_closing_signature = non_closing_signature
        else:
            self.non_closing_signature = None
        if reward_proof_signature:
            self.signature = reward_proof_signature
        else:
            self.signature = None

    @classmethod
    def from_balance_proof_signed_state(
            cls,
            balance_proof: BalanceProofSignedState,
            reward_amount: typing.TokenAmount,
    ) -> 'RequestMonitoring':
        assert isinstance(balance_proof, BalanceProofSignedState)
        onchain_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
            balance_proof=balance_proof,
        )
        return cls(
            onchain_balance_proof=onchain_balance_proof,
            reward_amount=reward_amount,
        )

    @property
    def reward_proof_signature(self) -> typing.Signature:
        return self.signature

    @classmethod
    def from_dict(
            cls,
            data: typing.Dict,
    ) -> 'RequestMonitoring':
        assert data['type'] == cls.__name__
        onchain_balance_proof = SignedBlindedBalanceProof.from_dict(
            data['onchain_balance_proof'],
        )
        assert isinstance(onchain_balance_proof, SignedBlindedBalanceProof)
        return cls(
            onchain_balance_proof=onchain_balance_proof,
            reward_amount=int(data['reward_amount']),
            non_closing_signature=decode_hex(data['non_closing_signature']),
            reward_proof_signature=decode_hex(data['reward_proof_signature']),
        )

    def to_dict(self) -> typing.Dict:
        """Message format according to monitoring service spec"""
        if not self.non_closing_signature:
            raise ValueError('onchain_balance_proof needs to be signed')
        if not self.reward_proof_signature:
            raise ValueError('monitoring request needs to be signed')
        return {
            'type': self.__class__.__name__,
            'onchain_balance_proof': self.balance_proof.to_dict(),
            'reward_amount': self.reward_amount,
            'non_closing_signature': encode_hex(self.non_closing_signature),
            'reward_proof_signature': encode_hex(self.reward_proof_signature),
        }

    def _data_to_sign(self) -> bytes:
        """ Return the binary data to be/which was signed """
        packed = pack_reward_proof(
            channel_identifier=self.balance_proof.channel_identifier,
            reward_amount=self.reward_amount,
            token_network_address=self.balance_proof.token_network_address,
            chain_id=self.balance_proof.chain_id,
            nonce=self.balance_proof.nonce,
        )
        return packed

    def sign(self, signer: Signer):
        """This method signs twice:
            - the `non_closing_signature` for the balance proof update
            - the `reward_proof_signature` for the monitoring request
        """
        self.non_closing_signature = self.balance_proof._sign(signer)
        message_data = self._data_to_sign()
        self.signature = signer.sign(data=message_data)

    def packed(self) -> bytes:
        klass = messages.RequestMonitoring
        data = buffer_for(klass)
        packed = klass(data)
        self.pack(packed)
        return packed

    def pack(self, packed: bytes) -> bytes:
        if self.non_closing_signature is None:
            raise ValueError('non_closing_signature missing, did you forget to sign()?')
        if self.reward_proof_signature is None:
            raise ValueError('reward_proof_signature missing, did you forget to sign()?')
        packed.nonce = self.balance_proof.nonce
        packed.chain_id = self.balance_proof.chain_id
        packed.token_network_address = self.balance_proof.token_network_address
        packed.channel_identifier = self.balance_proof.channel_identifier
        packed.balance_hash = self.balance_proof.balance_hash
        packed.additional_hash = self.balance_proof.additional_hash
        packed.signature = self.balance_proof.signature
        packed.non_closing_signature = self.non_closing_signature
        packed.reward_amount = self.reward_amount
        packed.reward_proof_signature = self.reward_proof_signature
        return packed

    @classmethod
    def unpack(
            cls,
            packed: bytes,
    ) -> 'RequestMonitoring':
        assert packed.balance_hash
        onchain_balance_proof = SignedBlindedBalanceProof(
            nonce=packed.nonce,
            chain_id=packed.chain_id,
            token_network_address=packed.token_network_address,
            channel_identifier=packed.channel_identifier,
            balance_hash=packed.balance_hash,
            additional_hash=packed.additional_hash,
            signature=packed.signature,
        )
        monitoring_request = cls(
            onchain_balance_proof=onchain_balance_proof,
            non_closing_signature=packed.non_closing_signature,
            reward_amount=packed.reward_amount,
            reward_proof_signature=packed.reward_proof_signature,
        )
        return monitoring_request

    def verify_request_monitoring(
            self,
            partner_address: typing.Address,
            requesting_address: typing.Address,
    ) -> bool:
        """ One should only use this method to verify integrity and signatures of a
        RequestMonitoring message. """
        balance_proof_data = pack_balance_proof(
            nonce=self.balance_proof.nonce,
            balance_hash=self.balance_proof.balance_hash,
            additional_hash=self.balance_proof.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.balance_proof.chain_id,
                token_network_address=self.balance_proof.token_network_address,
                channel_identifier=self.balance_proof.channel_identifier,
            ),
        )
        blinded_data = pack_balance_proof_update(
            nonce=self.balance_proof.nonce,
            balance_hash=self.balance_proof.balance_hash,
            additional_hash=self.balance_proof.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.balance_proof.chain_id,
                token_network_address=self.balance_proof.token_network_address,
                channel_identifier=self.balance_proof.channel_identifier,
            ),
            partner_signature=self.balance_proof.signature,
        )
        reward_proof_data = pack_reward_proof(
            channel_identifier=self.balance_proof.channel_identifier,
            reward_amount=self.reward_amount,
            token_network_address=self.balance_proof.token_network_address,
            chain_id=self.balance_proof.chain_id,
            nonce=self.balance_proof.nonce,
        )
        return (
            recover(balance_proof_data, self.balance_proof.signature) == partner_address and
            recover(blinded_data, self.non_closing_signature) == requesting_address and
            recover(reward_proof_data, self.reward_proof_signature) == requesting_address
        )


class UpdatePFS(SignedMessage):
    """ Message to inform a pathfinding service about a capacity change. """

    def __init__(
            self,
            *,
            nonce: typing.Nonce,
            transferred_amount: typing.TokenAmount,
            locked_amount: typing.TokenAmount,
            locksroot: typing.Locksroot,
            token_network_address: typing.TokenNetworkAddress,
            channel_identifier: typing.ChannelID,
            chain_id: typing.ChainID,
            reveal_timeout: int,
            signature: typing.Optional[typing.Signature] = None,
            **kwargs,
    ):
        super().__init__(**kwargs)
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.token_network_address = token_network_address
        self.channel_identifier = channel_identifier
        self.chain_id = chain_id
        self.reveal_timeout = reveal_timeout
        if signature is None:
            self.signature = b''
        else:
            self.signature = signature

    @classmethod
    def from_balance_proof(
            cls,
            balance_proof: BalanceProofUnsignedState,
            reveal_timeout: int,
    ) -> 'UpdatePFS':
        assert isinstance(balance_proof, BalanceProofUnsignedState)
        return cls(
            nonce=balance_proof.nonce,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            token_network_address=TokenNetworkAddress(balance_proof.token_network_identifier),
            channel_identifier=balance_proof.channel_identifier,
            chain_id=balance_proof.chain_id,
            reveal_timeout=reveal_timeout,
        )

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'type': self.__class__.__name__,
            'chain_id': self.chain_id,
            'nonce': self.nonce,
            'token_network_address': to_normalized_address(self.token_network_address),
            'channel_identifier': self.channel_identifier,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'locksroot': encode_hex(self.locksroot),
            'signature': encode_hex(self.signature),
            'reveal_timeout': self.reveal_timeout,
        }

    @classmethod
    def from_dict(
            cls,
            data: typing.Dict[str, typing.Any],
    ) -> 'UpdatePFS':
        return cls(
            nonce=data['nonce'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            locksroot=data['locksroot'],
            token_network_address=data['token_network_address'],
            channel_identifier=data['channel_identifier'],
            chain_id=data['chain_id'],
            reveal_timeout=data['reveal_timeout'],
        )

    def packed(self) -> bytes:
        klass = messages.UpdatePFS
        data = buffer_for(klass)
        packed = klass(data)
        self.pack(packed)
        return packed

    def pack(self, packed: bytes) -> bytes:
        packed.chain_id = self.chain_id
        packed.nonce = self.nonce
        packed.token_network_address = self.token_network_address
        packed.channel_identifier = self.channel_identifier
        packed.transferred_amount = self.transferred_amount
        packed.locked_amount = self.locked_amount
        packed.locksroot = self.locksroot
        packed.reveal_timeout = self.reveal_timeout
        packed.signature = self.signature

    @classmethod
    def unpack(
            cls,
            packed: bytes,
    ) -> 'UpdatePFS':
        return cls(
            chain_id=packed.chain_id,
            nonce=packed.nonce,
            token_network_address=packed.token_network_address,
            channel_identifier=packed.channel_identifier,
            transferred_amount=packed.transferred_amount,
            locked_amount=packed.locked_amount,
            locksroot=packed.locksroot,
            reveal_timeout=packed.reveal_timeout,
            signature=packed.signature,
        )


CMDID_TO_CLASS = {
    messages.DELIVERED: Delivered,
    messages.LOCKEDTRANSFER: LockedTransfer,
    messages.PING: Ping,
    messages.PONG: Pong,
    messages.PROCESSED: Processed,
    messages.REFUNDTRANSFER: RefundTransfer,
    messages.REVEALSECRET: RevealSecret,
    messages.UNLOCK: Unlock,
    messages.SECRETREQUEST: SecretRequest,
    messages.LOCKEXPIRED: LockExpired,
}

CLASSNAME_TO_CLASS = {klass.__name__: klass for klass in CMDID_TO_CLASS.values()}
CLASSNAME_TO_CLASS['Secret'] = Unlock
