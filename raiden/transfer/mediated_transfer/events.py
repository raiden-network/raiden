# pylint: disable=too-many-arguments,too-few-public-methods
from eth_utils import to_canonical_address, to_checksum_address

from raiden.transfer.architecture import Event, SendMessageEvent
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.utils import pex, sha3
from raiden.utils.serialization import deserialize_secret, deserialize_secret_hash, serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BlockExpiration,
    ChannelID,
    Dict,
    MessageID,
    PaymentID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    TokenAddress,
)

# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
CHANNEL_IDENTIFIER_GLOBAL_QUEUE = ChannelID(0)


def refund_from_sendmediated(
    send_lockedtransfer_event: "SendLockedTransfer",
) -> "SendRefundTransfer":
    return SendRefundTransfer(
        recipient=send_lockedtransfer_event.recipient,
        channel_identifier=send_lockedtransfer_event.queue_identifier.channel_identifier,
        message_identifier=send_lockedtransfer_event.message_identifier,
        transfer=send_lockedtransfer_event.transfer,
    )


class SendLockExpired(SendMessageEvent):
    def __init__(
        self,
        recipient: Address,
        message_identifier: MessageID,
        balance_proof: BalanceProofUnsignedState,
        secrethash: SecretHash,
    ) -> None:
        super().__init__(recipient, balance_proof.channel_identifier, message_identifier)

        self.balance_proof = balance_proof
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<SendLockExpired msgid:{} balance_proof:{} secrethash:{} recipient:{}>".format(
            self.message_identifier, self.balance_proof, pex(self.secrethash), pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendLockExpired)
            and self.message_identifier == other.message_identifier
            and self.balance_proof == other.balance_proof
            and self.secrethash == other.secrethash
            and self.recipient == other.recipient
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "message_identifier": str(self.message_identifier),
            "balance_proof": self.balance_proof,
            "secrethash": serialize_bytes(self.secrethash),
            "recipient": to_checksum_address(self.recipient),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendLockExpired":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            message_identifier=MessageID(int(data["message_identifier"])),
            balance_proof=data["balance_proof"],
            secrethash=deserialize_secret_hash(data["secrethash"]),
        )

        return restored


class SendLockedTransfer(SendMessageEvent):
    """ A locked transfer that must be sent to `recipient`. """

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        transfer: LockedTransferUnsignedState,
    ) -> None:
        if not isinstance(transfer, LockedTransferUnsignedState):
            raise ValueError("transfer must be a LockedTransferUnsignedState instance")

        super().__init__(recipient, channel_identifier, message_identifier)

        self.transfer = transfer

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof

    def __repr__(self) -> str:
        return "<SendLockedTransfer msgid:{} transfer:{} recipient:{}>".format(
            self.message_identifier, self.transfer, pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendLockedTransfer)
            and self.transfer == other.transfer
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
            "transfer": self.transfer,
            "balance_proof": self.transfer.balance_proof,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendLockedTransfer":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            transfer=data["transfer"],
        )

        return restored


class SendSecretReveal(SendMessageEvent):
    """ Sends a SecretReveal to another node.

    This event is used once the secret is known locally and an action must be
    performed on the recipient:

        - For receivers in the payee role, it informs the node that the lock has
            been released and the token can be claimed, either on-chain or
            off-chain.
        - For receivers in the payer role, it tells the payer that the payee
            knows the secret and wants to claim the lock off-chain, so the payer
            may unlock the lock and send an up-to-date balance proof to the payee,
            avoiding on-chain payments which would require the channel to be
            closed.

    For any mediated transfer:
        - The initiator will only perform the payer role.
        - The target will only perform the payee role.
        - The mediators will have `n` channels at the payee role and `n` at the
          payer role, where `n` is equal to `1 + number_of_refunds`.

    Note:
        The payee must only update its local balance once the payer sends an
        up-to-date balance-proof message. This is a requirement for keeping the
        nodes synchronized. The reveal secret message flows from the recipient
        to the sender, so when the secret is learned it is not yet time to
        update the balance.
    """

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        secret: Secret,
    ) -> None:
        secrethash = sha3(secret)

        super().__init__(recipient, channel_identifier, message_identifier)

        self.secret = secret
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<SendSecretReveal msgid:{} secrethash:{} recipient:{}>".format(
            self.message_identifier, pex(self.secrethash), pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendSecretReveal)
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
            "secret": serialize_bytes(self.secret),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendSecretReveal":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            secret=deserialize_secret(data["secret"]),
        )

        return restored


class SendBalanceProof(SendMessageEvent):
    """ Event to send a balance-proof to the counter-party, used after a lock
    is unlocked locally allowing the counter-party to claim it.

    Used by payers: The initiator and mediator nodes.

    Note:
        This event has a dual role, it serves as a synchronization and as
        balance-proof for the netting channel smart contract.

        Nodes need to keep the last known merkle root synchronized. This is
        required by the receiving end of a transfer in order to properly
        validate. The rule is "only the party that owns the current payment
        channel may change it" (remember that a netting channel is composed of
        two uni-directional channels), as a consequence the merkle root is only
        updated by the recipient once a balance proof message is received.
    """

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        payment_identifier: PaymentID,
        token_address: TokenAddress,
        secret: Secret,
        balance_proof: BalanceProofUnsignedState,
    ) -> None:
        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.token = token_address
        self.secret = secret
        self.secrethash = sha3(secret)
        self.balance_proof = balance_proof

    def __repr__(self) -> str:
        return (
            "<"
            "SendBalanceProof msgid:{} paymentid:{} token:{} secrethash:{} recipient:{} "
            "balance_proof:{}"
            ">"
        ).format(
            self.message_identifier,
            self.payment_identifier,
            pex(self.token),
            pex(self.secrethash),
            pex(self.recipient),
            self.balance_proof,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendBalanceProof)
            and self.payment_identifier == other.payment_identifier
            and self.token == other.token
            and self.recipient == other.recipient
            and self.secret == other.secret
            and self.balance_proof == other.balance_proof
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
            "payment_identifier": str(self.payment_identifier),
            "token_address": to_checksum_address(self.token),
            "secret": serialize_bytes(self.secret),
            "balance_proof": self.balance_proof,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendBalanceProof":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            payment_identifier=PaymentID(int(data["payment_identifier"])),
            token_address=to_canonical_address(data["token_address"]),
            secret=deserialize_secret(data["secret"]),
            balance_proof=data["balance_proof"],
        )

        return restored


class SendSecretRequest(SendMessageEvent):
    """ Event used by a target node to request the secret from the initiator
    (`recipient`).
    """

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        payment_identifier: PaymentID,
        amount: PaymentWithFeeAmount,
        expiration: BlockExpiration,
        secrethash: SecretHash,
    ) -> None:

        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return (
            "<SendSecretRequest "
            "msgid:{} paymentid:{} amount:{} expiration:{} secrethash:{} recipient:{}"
            ">"
        ).format(
            self.message_identifier,
            self.payment_identifier,
            self.amount,
            self.expiration,
            pex(self.secrethash),
            pex(self.recipient),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendSecretRequest)
            and self.payment_identifier == other.payment_identifier
            and self.amount == other.amount
            and self.expiration == other.expiration
            and self.secrethash == other.secrethash
            and self.recipient == other.recipient
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
            "payment_identifier": str(self.payment_identifier),
            "amount": str(self.amount),
            "expiration": str(self.expiration),
            "secrethash": serialize_bytes(self.secrethash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendSecretRequest":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            payment_identifier=PaymentID(int(data["payment_identifier"])),
            amount=PaymentWithFeeAmount(int(data["amount"])),
            expiration=BlockExpiration(int(data["expiration"])),
            secrethash=deserialize_secret_hash(data["secrethash"]),
        )

        return restored


class SendRefundTransfer(SendMessageEvent):
    """ Event used to cleanly backtrack the current node in the route.
    This message will pay back the same amount of token from the recipient to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        transfer: LockedTransferUnsignedState,
    ) -> None:

        super().__init__(recipient, channel_identifier, message_identifier)

        self.transfer = transfer

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof

    def __repr__(self) -> str:
        return (
            f"<"
            f"SendRefundTransfer msgid:{self.message_identifier} transfer:{self.transfer} "
            f"recipient:{pex(self.recipient)} "
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SendRefundTransfer)
            and self.transfer == other.transfer
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": str(self.queue_identifier.channel_identifier),
            "message_identifier": str(self.message_identifier),
            "transfer": self.transfer,
            "balance_proof": self.transfer.balance_proof,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SendRefundTransfer":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            transfer=data["transfer"],
        )

        return restored


class EventUnlockSuccess(Event):
    """ Event emitted when a lock unlock succeded. """

    def __init__(self, identifier: PaymentID, secrethash: SecretHash) -> None:
        self.identifier = identifier
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<EventUnlockSuccess id:{} secrethash:{}>".format(
            self.identifier, pex(self.secrethash)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnlockSuccess)
            and self.identifier == other.identifier
            and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "identifier": str(self.identifier),
            "secrethash": serialize_bytes(self.secrethash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventUnlockSuccess":
        restored = cls(
            identifier=PaymentID(int(data["identifier"])),
            secrethash=deserialize_secret_hash(data["secrethash"]),
        )

        return restored


class EventUnlockFailed(Event):
    """ Event emitted when a lock unlock failed. """

    def __init__(self, identifier: PaymentID, secrethash: SecretHash, reason: str) -> None:
        self.identifier = identifier
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self) -> str:
        return "<EventUnlockFailed id:{} secrethash:{} reason:{}>".format(
            self.identifier, pex(self.secrethash), self.reason
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnlockFailed)
            and self.identifier == other.identifier
            and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "identifier": str(self.identifier),
            "secrethash": serialize_bytes(self.secrethash),
            "reason": self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventUnlockFailed":
        restored = cls(
            identifier=PaymentID(int(data["identifier"])),
            secrethash=deserialize_secret_hash(data["secrethash"]),
            reason=data["reason"],
        )

        return restored


class EventUnlockClaimSuccess(Event):
    """ Event emitted when a lock claim succeded. """

    def __init__(self, identifier: PaymentID, secrethash: SecretHash) -> None:
        self.identifier = identifier
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<EventUnlockClaimSuccess id:{} secrethash:{}>".format(
            self.identifier, pex(self.secrethash)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnlockClaimSuccess)
            and self.identifier == other.identifier
            and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "identifier": str(self.identifier),
            "secrethash": serialize_bytes(self.secrethash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventUnlockClaimSuccess":
        restored = cls(
            identifier=PaymentID(int(data["identifier"])),
            secrethash=deserialize_secret_hash(data["secrethash"]),
        )

        return restored


class EventUnlockClaimFailed(Event):
    """ Event emitted when a lock claim failed. """

    def __init__(self, identifier: PaymentID, secrethash: SecretHash, reason: str) -> None:
        self.identifier = identifier
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self) -> str:
        return "<EventUnlockClaimFailed id:{} secrethash:{} reason:{}>".format(
            self.identifier, pex(self.secrethash), self.reason
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnlockClaimFailed)
            and self.identifier == other.identifier
            and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "identifier": str(self.identifier),
            "secrethash": serialize_bytes(self.secrethash),
            "reason": self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventUnlockClaimFailed":
        restored = cls(
            identifier=PaymentID(int(data["identifier"])),
            secrethash=deserialize_secret_hash(data["secrethash"]),
            reason=data["reason"],
        )

        return restored


class EventUnexpectedSecretReveal(Event):
    """ Event emitted when an unexpected secret reveal message is received. """

    def __init__(self, secrethash: SecretHash, reason: str):
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"<"
            f"EventUnexpectedSecretReveal "
            f"secrethash:{pex(self.secrethash)} "
            f"reason:{self.reason}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnexpectedSecretReveal)
            and self.secrethash == other.secrethash
            and self.reason == other.reason
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {"secrethash": serialize_bytes(self.secrethash), "reason": self.reason}

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventUnexpectedSecretReveal":
        restored = cls(
            secrethash=deserialize_secret_hash(data["secrethash"]), reason=data["reason"]
        )

        return restored


class EventRouteFailed(Event):
    """ Event emitted when a route failed.

    As a payment can try different routes to reach the intended target
    some of the routes can fail. This event is emitted when a route failed.

    This means that multiple EventRouteFailed for a given payment and it's
    therefore different to EventPaymentSentFailed.

    A route can fail for two reasons:
    - A refund transfer reaches the initiator (it's not important if this
        refund transfer is unlocked or not)
    - A lock expires
    """

    def __init__(self, secrethash: SecretHash):
        self.secrethash = secrethash

    def __repr__(self):
        return f"<EventRouteFailed secrethash:{pex(self.secrethash)}>"

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, EventUnexpectedSecretReveal) and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"secrethash": serialize_bytes(self.secrethash)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventRouteFailed":
        return cls(secrethash=deserialize_secret_hash(data["secrethash"]))
