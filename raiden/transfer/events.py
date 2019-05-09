from typing import TYPE_CHECKING

from eth_utils import to_bytes, to_canonical_address, to_checksum_address, to_hex

from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    ContractSendEvent,
    ContractSendExpirableEvent,
    Event,
    SendMessageEvent,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils import pex, serialization, sha3
from raiden.utils.serialization import deserialize_bytes, serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BlockExpiration,
    BlockHash,
    ChannelID,
    Dict,
    InitiatorAddress,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    T_Secret,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.state import BalanceProofSignedState

# pylint: disable=too-many-arguments,too-few-public-methods


class ContractSendChannelClose(ContractSendEvent):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    def __init__(
        self,
        canonical_identifier: CanonicalIdentifier,
        balance_proof: Optional["BalanceProofSignedState"],
        triggered_by_block_hash: BlockHash,
    ) -> None:
        super().__init__(triggered_by_block_hash)
        self.canonical_identifier = canonical_identifier
        self.balance_proof = balance_proof

    def __repr__(self) -> str:
        return (
            "<ContractSendChannelClose channel:{} token:{} token_network:{} "
            "balance_proof:{} triggered_by_block_hash:{}>"
        ).format(
            self.canonical_identifier.channel_identifier,
            pex(self.canonical_identifier.token_network_address),
            self.balance_proof,
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other)
            and isinstance(other, ContractSendChannelClose)
            and self.canonical_identifier == other.canonical_identifier
            and self.balance_proof == other.balance_proof
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "balance_proof": self.balance_proof,
            "triggered_by_block_hash": serialize_bytes(self.triggered_by_block_hash),
        }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSendChannelClose":
        restored = cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            balance_proof=data["balance_proof"],
            triggered_by_block_hash=BlockHash(deserialize_bytes(data["triggered_by_block_hash"])),
        )

        return restored


class ContractSendChannelSettle(ContractSendEvent):
    """ Event emitted if the netting channel must be settled. """

    def __init__(
        self, canonical_identifier: CanonicalIdentifier, triggered_by_block_hash: BlockHash
    ):
        super().__init__(triggered_by_block_hash)
        canonical_identifier.validate()

        self.canonical_identifier = canonical_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def __repr__(self) -> str:
        return (
            "<ContractSendChannelSettle channel:{} token_network:{} "
            "triggered_by_block_hash:{}>".format(
                self.channel_identifier,
                pex(self.token_network_identifier),
                pex(self.triggered_by_block_hash),
            )
        )

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other)
            and isinstance(other, ContractSendChannelSettle)
            and self.canonical_identifier == other.canonical_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "triggered_by_block_hash": serialize_bytes(self.triggered_by_block_hash),
        }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSendChannelSettle":
        restored = cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data["triggered_by_block_hash"])),
        )
        return restored


class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """ Event emitted if the netting channel balance proof must be updated. """

    def __init__(
        self,
        expiration: BlockExpiration,
        balance_proof: "BalanceProofSignedState",
        triggered_by_block_hash: BlockHash,
    ) -> None:
        super().__init__(triggered_by_block_hash, expiration)
        self.balance_proof = balance_proof

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.balance_proof.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.balance_proof.channel_identifier

    def __repr__(self) -> str:
        return (
            "<ContractSendChannelUpdateTransfer channel:{} token_network:{} "
            "balance_proof:{} triggered_by_block_hash:{}>"
        ).format(
            self.channel_identifier,
            pex(self.token_network_identifier),
            self.balance_proof,
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractSendChannelUpdateTransfer)
            and self.balance_proof == other.balance_proof
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "expiration": str(self.expiration),
            "balance_proof": self.balance_proof,
            "triggered_by_block_hash": serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSendChannelUpdateTransfer":
        restored = cls(
            expiration=BlockExpiration(int(data["expiration"])),
            balance_proof=data["balance_proof"],
            triggered_by_block_hash=BlockHash(deserialize_bytes(data["triggered_by_block_hash"])),
        )

        return restored


class ContractSendChannelBatchUnlock(ContractSendEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(
        self,
        canonical_identifier: CanonicalIdentifier,
        participant: Address,
        triggered_by_block_hash: BlockHash,
    ) -> None:
        super().__init__(triggered_by_block_hash)
        self.canonical_identifier = canonical_identifier
        self.participant = participant

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def __repr__(self) -> str:
        return (
            "<ContractSendChannelBatchUnlock token_network_id:{} "
            "channel:{} participant:{} triggered_by_block_hash:{}"
            ">"
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.participant),
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other)
            and isinstance(other, ContractSendChannelBatchUnlock)
            and self.canonical_identifier == other.canonical_identifier
            and self.participant == other.participant
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "participant": to_checksum_address(self.participant),
            "triggered_by_block_hash": serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSendChannelBatchUnlock":
        restored = cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            participant=to_canonical_address(data["participant"]),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data["triggered_by_block_hash"])),
        )

        return restored


class ContractSendSecretReveal(ContractSendExpirableEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(
        self, expiration: BlockExpiration, secret: Secret, triggered_by_block_hash: BlockHash
    ) -> None:
        if not isinstance(secret, T_Secret):
            raise ValueError("secret must be a Secret instance")

        super().__init__(triggered_by_block_hash, expiration)
        self.secret = secret

    def __repr__(self) -> str:
        secrethash: SecretHash = SecretHash(sha3(self.secret))
        return ("<ContractSendSecretReveal secrethash:{} triggered_by_block_hash:{}>").format(
            secrethash, pex(self.triggered_by_block_hash)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractSendSecretReveal)
            and self.secret == other.secret
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "expiration": str(self.expiration),
            "secret": serialization.serialize_bytes(self.secret),
            "triggered_by_block_hash": serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSendSecretReveal":
        restored = cls(
            expiration=BlockExpiration(int(data["expiration"])),
            secret=Secret(serialization.deserialize_bytes(data["secret"])),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data["triggered_by_block_hash"])),
        )

        return restored


class EventPaymentSentSuccess(Event):
    """ Event emitted by the initiator when a transfer is considered successful.

    A transfer is considered successful when the initiator's payee hop sends the
    reveal secret message, assuming that each hop in the mediator chain has
    also learned the secret and unlocked its token off-chain or on-chain.

    This definition of successful is used to avoid the following corner case:

    - The reveal secret message is sent, since the network is unreliable and we
      assume byzantine behavior the message is considered delivered without an
      acknowledgement.
    - The transfer is considered successful because of the above.
    - The reveal secret message was not delivered because of actual network
      problems.
    - The lock expires and an EventUnlockFailed follows, contradicting the
      EventPaymentSentSuccess.

    Note:
        Mediators cannot use this event, since an off-chain unlock may be locally
        successful but there is no knowledge about the global transfer.
    """

    def __init__(
        self,
        payment_network_identifier: PaymentNetworkID,
        token_network_identifier: TokenNetworkID,
        identifier: PaymentID,
        amount: PaymentAmount,
        target: TargetAddress,
        secret: Secret = None,
    ) -> None:
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.identifier = identifier
        self.amount = amount
        self.target = target
        self.secret = secret

    def __repr__(self) -> str:
        return (
            "<"
            "EventPaymentSentSuccess payment_network_identifier:{} "
            "token_network_identifier:{} "
            "identifier:{} amount:{} "
            "target:{} secret:{} "
            ">"
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            self.amount,
            pex(self.target),
            to_hex(self.secret),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventPaymentSentSuccess)
            and self.identifier == other.identifier
            and self.amount == other.amount
            and self.target == other.target
            and self.payment_network_identifier == other.payment_network_identifier
            and self.token_network_identifier == other.token_network_identifier
            and self.secret == other.secret
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "token_network_identifier": to_checksum_address(self.token_network_identifier),
            "identifier": str(self.identifier),
            "amount": str(self.amount),
            "target": to_checksum_address(self.target),
        }
        if self.secret is not None:
            result["secret"] = to_hex(self.secret)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventPaymentSentSuccess":
        if "secret" in data:
            secret = to_bytes(hexstr=data["secret"])
        else:
            secret = None

        restored = cls(
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            token_network_identifier=to_canonical_address(data["token_network_identifier"]),
            identifier=PaymentID(int(data["identifier"])),
            amount=PaymentAmount(int(data["amount"])),
            target=to_canonical_address(data["target"]),
            secret=secret,
        )

        return restored


class EventPaymentSentFailed(Event):
    """ Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    def __init__(
        self,
        payment_network_identifier: PaymentNetworkID,
        token_network_identifier: TokenNetworkID,
        identifier: PaymentID,
        target: TargetAddress,
        reason: str,
    ) -> None:
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.identifier = identifier
        self.target = target
        self.reason = reason

    def __repr__(self) -> str:
        return (
            "<"
            "EventPaymentSentFailed payment_network_identifier:{} "
            "token_network_identifier:{} "
            "id:{} target:{} reason:{} "
            ">"
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            pex(self.target),
            self.reason,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventPaymentSentFailed)
            and self.payment_network_identifier == other.payment_network_identifier
            and self.token_network_identifier == other.token_network_identifier
            and self.identifier == other.identifier
            and self.target == other.target
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "token_network_identifier": to_checksum_address(self.token_network_identifier),
            "identifier": str(self.identifier),
            "target": to_checksum_address(self.target),
            "reason": self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventPaymentSentFailed":
        restored = cls(
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            token_network_identifier=to_canonical_address(data["token_network_identifier"]),
            identifier=PaymentID(int(data["identifier"])),
            target=to_canonical_address(data["target"]),
            reason=data["reason"],
        )

        return restored


class EventPaymentReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    def __init__(
        self,
        payment_network_identifier: PaymentNetworkID,
        token_network_identifier: TokenNetworkID,
        identifier: PaymentID,
        amount: TokenAmount,
        initiator: InitiatorAddress,
    ) -> None:
        if amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

        self.identifier = identifier
        self.amount = amount
        self.initiator = initiator
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier

    def __repr__(self) -> str:
        return (
            "<"
            "EventPaymentReceivedSuccess payment_network_identifier:{} "
            "token_network_identifier:{} identifier:{} "
            "amount:{} initiator:{} "
            ">"
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            self.amount,
            pex(self.initiator),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventPaymentReceivedSuccess)
            and self.identifier == other.identifier
            and self.amount == other.amount
            and self.initiator == other.initiator
            and self.payment_network_identifier == other.payment_network_identifier
            and self.token_network_identifier == other.token_network_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "token_network_identifier": to_checksum_address(self.token_network_identifier),
            "identifier": str(self.identifier),
            "amount": str(self.amount),
            "initiator": to_checksum_address(self.initiator),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventPaymentReceivedSuccess":
        restored = cls(
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            token_network_identifier=to_canonical_address(data["token_network_identifier"]),
            identifier=PaymentID(int(data["identifier"])),
            amount=TokenAmount(int(data["amount"])),
            initiator=to_canonical_address(data["initiator"]),
        )

        return restored


class EventInvalidReceivedTransferRefund(Event):
    """ Event emitted when an invalid refund transfer is received. """

    def __init__(self, payment_identifier: PaymentID, reason: str) -> None:
        self.payment_identifier = payment_identifier
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"<"
            f"EventInvalidReceivedTransferRefund "
            f"payment_identifier:{self.payment_identifier} "
            f"reason:{self.reason}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventInvalidReceivedTransferRefund)
            and self.payment_identifier == other.payment_identifier
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {"payment_identifier": str(self.payment_identifier), "reason": self.reason}

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventInvalidReceivedTransferRefund":
        restored = cls(
            payment_identifier=PaymentID(int(data["payment_identifier"])), reason=data["reason"]
        )

        return restored


class EventInvalidReceivedLockExpired(Event):
    """ Event emitted when an invalid lock expired message is received. """

    def __init__(self, secrethash: SecretHash, reason: str) -> None:
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"<"
            f"EventInvalidReceivedLockExpired "
            f"secrethash:{pex(self.secrethash)} "
            f"reason:{self.reason}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventInvalidReceivedLockExpired)
            and self.secrethash == other.secrethash
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "secrethash": serialization.serialize_bytes(self.secrethash),
            "reason": self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventInvalidReceivedLockExpired":
        restored = cls(
            secrethash=serialization.deserialize_secret_hash(data["secrethash"]),
            reason=data["reason"],
        )

        return restored


class EventInvalidReceivedLockedTransfer(Event):
    """ Event emitted when an invalid locked transfer is received. """

    def __init__(self, payment_identifier: PaymentID, reason: str) -> None:
        self.payment_identifier = payment_identifier
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"<"
            f"EventInvalidReceivedLockedTransfer "
            f"payment_identifier:{self.payment_identifier} "
            f"reason:{self.reason}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventInvalidReceivedLockedTransfer)
            and self.payment_identifier == other.payment_identifier
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {"payment_identifier": str(self.payment_identifier), "reason": self.reason}

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventInvalidReceivedLockedTransfer":
        restored = cls(
            payment_identifier=PaymentID(int(data["payment_identifier"])), reason=data["reason"]
        )

        return restored


class EventInvalidReceivedUnlock(Event):
    """ Event emitted when an invalid unlock message is received. """

    def __init__(self, secrethash: SecretHash, reason: str) -> None:
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"<"
            f"EventInvalidReceivedUnlock "
            f"secrethash:{pex(self.secrethash)} "
            f"reason:{self.reason}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventInvalidReceivedUnlock)
            and self.secrethash == other.secrethash
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "secrethash": serialization.serialize_bytes(self.secrethash),
            "reason": self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventInvalidReceivedUnlock":
        restored = cls(
            secrethash=serialization.deserialize_secret_hash(data["secrethash"]),
            reason=data["reason"],
        )

        return restored


class SendProcessed(SendMessageEvent):
    def __repr__(self) -> str:
        return ("<SendProcessed confirmed_msgid:{} recipient:{}>").format(
            self.message_identifier, pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, SendProcessed) and super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendProcessed":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
        )

        return restored
