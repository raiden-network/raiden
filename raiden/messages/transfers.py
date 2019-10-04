from dataclasses import dataclass, field
from hashlib import sha256
from typing import overload

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX, UINT256_MAX
from raiden.messages.abstract import SignedRetrieableMessage
from raiden.messages.cmdid import CmdId
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendRefundTransfer
from raiden.transfer.utils import hash_balance_data
from raiden.utils import ishash, sha3
from raiden.utils.packing import pack_balance_proof
from raiden.utils.signing import pack_data
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    ChainID,
    ChannelID,
    ClassVar,
    InitiatorAddress,
    Locksroot,
    Nonce,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
)


def assert_envelope_values(
    nonce: int,
    channel_identifier: ChannelID,
    transferred_amount: TokenAmount,
    locked_amount: TokenAmount,
    locksroot: Locksroot,
):
    if nonce <= 0:
        raise ValueError("nonce cannot be zero or negative")

    if nonce > UINT64_MAX:
        raise ValueError("nonce is too large")

    if channel_identifier <= 0:
        raise ValueError("channel id cannot be zero or negative")

    if channel_identifier > UINT256_MAX:
        raise ValueError("channel id is too large")

    if transferred_amount < 0:
        raise ValueError("transferred_amount cannot be negative")

    if transferred_amount > UINT256_MAX:
        raise ValueError("transferred_amount is too large")

    if locked_amount < 0:
        raise ValueError("locked_amount cannot be negative")

    if locked_amount > UINT256_MAX:
        raise ValueError("locked_amount is too large")

    if len(locksroot) != 32:
        raise ValueError("locksroot must have length 32")


def assert_transfer_values(payment_identifier, token, recipient):
    if payment_identifier < 0:
        raise ValueError("payment_identifier cannot be negative")

    if payment_identifier > UINT64_MAX:
        raise ValueError("payment_identifier is too large")

    if len(token) != 20:
        raise ValueError("token is an invalid address")

    if len(recipient) != 20:
        raise ValueError("recipient is an invalid address")


@dataclass(repr=False, eq=False)
class Lock:
    """ The lock datastructure.

    Args:
        amount: Amount of the token being transferred.
        expiration: Highest block_number until which the transfer can be settled
        secrethash: Hashed secret `sha256(secret).digest()` used to register the transfer,
        the real `secret` is necessary to release the locked amount.
    """

    # Lock is not a message, it is a serializable structure that is reused in
    # some messages
    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash

    def __post_init__(self):
        # guarantee that `amount` can be serialized using the available bytes
        # in the fixed length format
        if self.amount < 0:
            raise ValueError(f"amount {self.amount} needs to be positive")

        if self.amount > UINT256_MAX:
            raise ValueError(f"amount {self.amount} is too large")

        if self.expiration < 0:
            raise ValueError(f"expiration {self.expiration} needs to be positive")

        if self.expiration > UINT256_MAX:
            raise ValueError(f"expiration {self.expiration} is too large")

        if not ishash(self.secrethash):
            raise ValueError("secrethash {self.secrethash} is not a valid hash")

    @property
    def as_bytes(self):
        return pack_data(
            (self.expiration, "uint256"), (self.amount, "uint256"), (self.secrethash, "bytes32")
        )

    @property
    def lockhash(self):
        return sha3(self.as_bytes)

    @classmethod
    def from_bytes(cls, serialized):
        return cls(
            expiration=int.from_bytes(serialized[:32], byteorder="big"),
            amount=int.from_bytes(serialized[32:64], byteorder="big"),
            secrethash=serialized[64:],
        )


@dataclass(repr=False, eq=False)
class EnvelopeMessage(SignedRetrieableMessage):
    """ Contains an on-chain message and shares its signature.

    For performance reasons envelope messages share the signature with the
    blockchain message. The same signature is used for authenticating for both
    the client and the smart contract.
    """

    chain_id: ChainID
    nonce: Nonce
    transferred_amount: TokenAmount
    locked_amount: TokenAmount
    locksroot: Locksroot
    channel_identifier: ChannelID
    token_network_address: TokenNetworkAddress

    def __post_init__(self):
        assert_envelope_values(
            self.nonce,
            self.channel_identifier,
            self.transferred_amount,
            self.locked_amount,
            self.locksroot,
        )

    @property
    def message_hash(self):
        raise NotImplementedError

    def _data_to_sign(self) -> bytes:
        balance_hash = hash_balance_data(
            self.transferred_amount, self.locked_amount, self.locksroot
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


@dataclass(repr=False, eq=False)
class SecretRequest(SignedRetrieableMessage):
    """ Requests the secret/preimage which unlocks a lock. """

    cmdid: ClassVar[CmdId] = CmdId.SECRETREQUEST

    payment_identifier: PaymentID
    secrethash: SecretHash
    amount: PaymentAmount
    expiration: BlockExpiration

    @classmethod
    def from_event(cls, event):
        # pylint: disable=unexpected-keyword-arg
        return cls(
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            secrethash=event.secrethash,
            amount=event.amount,
            expiration=event.expiration,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.message_identifier, "uint64"),
            (self.payment_identifier, "uint64"),
            (self.secrethash, "bytes32"),
            (self.amount, "uint256"),
            (self.expiration, "uint256"),
        )


@dataclass(repr=False, eq=False)
class Unlock(EnvelopeMessage):
    """ Message used to successfully unlock a lock.

    For this message to be valid the balance proof has to be updated to:

    - Remove the successful lock from the pending locks and decrement the
      locked_amount by the lock's amount, otherwise the sender will pay twice.
    - Increase the transferred_amount, otherwise the recipient will reject it
      because it is not being paid.

    This message is needed to unlock off-chain transfers for channels that used
    less frequently then the pending locks' expiration, otherwise the receiving
    end would have to go on-chain to register the secret.

    This message is needed in addition to the RevealSecret to fix
    synchronization problems. The recipient can not preemptively update its
    channel state because there may other messages in-flight. Consider the
    following case:

    1. Node A sends a LockedTransfer to B.
    2. Node B forwards and eventually receives the secret
    3. Node A sends a second LockedTransfer to B.

    At point 3, node A had no knowledge about the first payment having its
    secret revealed, therefore the pending locks from message at step 3 will
    include both locks. If B were to preemptively remove the lock it would
    reject the message.
    """

    cmdid: ClassVar[CmdId] = CmdId.UNLOCK

    payment_identifier: PaymentID
    secret: Secret = field(repr=False)

    def __post_init__(self):
        super().__post_init__()
        if self.payment_identifier < 0:
            raise ValueError("payment_identifier cannot be negative")

        if self.payment_identifier > UINT64_MAX:
            raise ValueError("payment_identifier is too large")

        if len(self.secret) != 32:
            raise ValueError("secret must have 32 bytes")

    @property
    def secrethash(self):
        return sha256(self.secret).digest()

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof
        # pylint: disable=unexpected-keyword-arg
        return cls(
            chain_id=balance_proof.chain_id,
            message_identifier=event.message_identifier,
            payment_identifier=event.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_address,
            channel_identifier=balance_proof.channel_identifier,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            secret=event.secret,
            signature=EMPTY_SIGNATURE,
        )

    @property
    def message_hash(self) -> bytes:
        return sha3(
            pack_data(
                (self.cmdid.value, "uint8"),
                (self.message_identifier, "uint64"),
                (self.payment_identifier, "uint64"),
                (self.secret, "bytes32"),
            )
        )


@dataclass(repr=False, eq=False)
class RevealSecret(SignedRetrieableMessage):
    """Reveal the lock's secret.

    This message is not sufficient to unlock a lock, refer to the Unlock.
    """

    cmdid: ClassVar[CmdId] = CmdId.REVEALSECRET

    secret: Secret = field(repr=False)

    @property
    def secrethash(self):
        return sha256(self.secret).digest()

    @classmethod
    def from_event(cls, event):
        # pylint: disable=unexpected-keyword-arg
        return cls(
            message_identifier=event.message_identifier,
            secret=event.secret,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.message_identifier, "uint64"),
            (self.secret, "bytes32"),
        )


@dataclass(repr=False, eq=False)
class LockedTransferBase(EnvelopeMessage):
    """ A transfer which signs that the partner can claim `locked_amount` if
    she knows the secret to `secrethash`.
    """

    payment_identifier: PaymentID
    token: TokenAddress
    recipient: Address
    lock: Lock
    target: TargetAddress
    initiator: InitiatorAddress
    fee: int
    metadata: Metadata

    def __post_init__(self):
        super().__post_init__()
        assert_transfer_values(self.payment_identifier, self.token, self.recipient)

        if len(self.target) != 20:
            raise ValueError("target is an invalid address")

        if len(self.initiator) != 20:
            raise ValueError("initiator is an invalid address")

        if self.fee > UINT256_MAX:
            raise ValueError("fee is too large")

    @overload
    @classmethod
    def from_event(cls, event: SendLockedTransfer) -> "LockedTransfer":
        # pylint: disable=unused-argument
        ...

    @overload  # noqa: F811
    @classmethod
    def from_event(cls, event: SendRefundTransfer) -> "RefundTransfer":
        # pylint: disable=unused-argument
        ...

    @classmethod  # noqa: F811
    def from_event(cls, event):
        transfer = event.transfer
        balance_proof = transfer.balance_proof
        lock = Lock(
            amount=transfer.lock.amount,
            expiration=transfer.lock.expiration,
            secrethash=transfer.lock.secrethash,
        )
        fee = 0

        # pylint: disable=unexpected-keyword-arg
        return cls(
            chain_id=balance_proof.chain_id,
            message_identifier=event.message_identifier,
            payment_identifier=transfer.payment_identifier,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_address,
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
            signature=EMPTY_SIGNATURE,
            metadata=Metadata(
                routes=[RouteMetadata(route=r.route) for r in transfer.route_states]
            ),
        )

    def _packed_data(self):
        return pack_data(
            (self.cmdid.value, "uint8"),
            (self.message_identifier, "uint64"),
            (self.payment_identifier, "uint64"),
            (self.lock.expiration, "uint256"),
            (self.token, "address"),
            (self.recipient, "address"),
            (self.target, "address"),
            (self.initiator, "address"),
            (self.lock.secrethash, "bytes32"),
            (self.lock.amount, "uint256"),
            (self.fee, "uint256"),
        )


@dataclass(repr=False, eq=False)
class LockedTransfer(LockedTransferBase):
    """ Message used to reserve tokens for a new mediated transfer.

    For this message to be valid, the sender must:

    - Use a lock.amount smaller then its current capacity. If the amount is
      higher, then the recipient will reject it, as it means spending money it
      does not own.
    - Have the new lock represented in locksroot.
    - Increase the locked_amount by exactly `lock.amount` otherwise the message
      would be rejected by the recipient. If the locked_amount is increased by
      more, then funds may get locked in the channel. If the locked_amount is
      increased by less, then the recipient will reject the message as it may
      mean it received the funds with an on-chain unlock.

    The initiator will estimate the fees based on the available routes and
    incorporate it in the lock's amount. Note that with permissive routing it
    is not possible to predetermine the exact fee amount, as the initiator does
    not know which nodes are available, thus an estimated value is used.
    """

    cmdid: ClassVar[CmdId] = CmdId.LOCKEDTRANSFER

    @property
    def message_hash(self) -> bytes:
        metadata_hash = (self.metadata and self.metadata.hash) or b""
        return sha3(self._packed_data() + metadata_hash)


@dataclass(repr=False, eq=False)
class RefundTransfer(LockedTransferBase):
    """ A message used when a payee does not have any available routes to
    forward the transfer.

    This message is used by the payee to refund the payer when no route is
    available. This transfer refunds the payer, allowing him to try a new path
    to complete the transfer.
    """

    cmdid: ClassVar[CmdId] = CmdId.REFUNDTRANSFER

    @property
    def message_hash(self) -> bytes:
        return sha3(self._packed_data())


@dataclass(repr=False, eq=False)
class LockExpired(EnvelopeMessage):
    """ Message used when a lock expires.

    This will complete an unsuccessful transfer off-chain.

    For this message to be valid the balance proof has to be updated to:

    - Remove the expired lock from the pending locks and reflect it in the
      locksroot.
    - Decrease the locked_amount by exactly by lock.amount. If less tokens are
      decreased the sender may get tokens locked. If more tokens are decreased
      the recipient will reject the message as on-chain unlocks may fail.

    This message is necessary for synchronization since other messages may be
    in-flight, vide Unlock for examples.
    """

    cmdid: ClassVar[CmdId] = CmdId.LOCKEXPIRED

    recipient: Address
    secrethash: SecretHash

    @classmethod
    def from_event(cls, event):
        balance_proof = event.balance_proof

        # pylint: disable=unexpected-keyword-arg
        return cls(
            chain_id=balance_proof.chain_id,
            nonce=balance_proof.nonce,
            token_network_address=balance_proof.token_network_address,
            channel_identifier=balance_proof.channel_identifier,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=balance_proof.locked_amount,
            locksroot=balance_proof.locksroot,
            message_identifier=event.message_identifier,
            recipient=event.recipient,
            secrethash=event.secrethash,
            signature=EMPTY_SIGNATURE,
        )

    @property
    def message_hash(self) -> bytes:
        return sha3(
            pack_data(
                (self.cmdid.value, "uint8"),
                (self.message_identifier, "uint64"),
                (self.recipient, "address"),
                (self.secrethash, "bytes32"),
            )
        )
