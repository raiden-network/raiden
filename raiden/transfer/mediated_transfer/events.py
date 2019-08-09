# pylint: disable=too-many-arguments,too-few-public-methods
from dataclasses import dataclass, field

from raiden.constants import EMPTY_SECRETHASH
from raiden.transfer.architecture import Event, SendMessageEvent
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    List,
    PaymentID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    TokenAddress,
    TokenNetworkAddress,
    typecheck,
)


def refund_from_sendmediated(
    send_lockedtransfer_event: "SendLockedTransfer",
) -> "SendRefundTransfer":
    return SendRefundTransfer(
        recipient=send_lockedtransfer_event.recipient,
        message_identifier=send_lockedtransfer_event.message_identifier,
        transfer=send_lockedtransfer_event.transfer,
        canonical_identifier=send_lockedtransfer_event.queue_identifier.canonical_identifier,
    )


@dataclass(frozen=True)
class SendLockExpired(SendMessageEvent):
    balance_proof: BalanceProofUnsignedState
    secrethash: SecretHash


@dataclass(frozen=True)
class SendLockedTransfer(SendMessageEvent):
    """ A locked transfer that must be sent to `recipient`. """

    transfer: LockedTransferUnsignedState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.transfer, LockedTransferUnsignedState)

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof


@dataclass(frozen=True)
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

    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(self, "secrethash", sha256_secrethash(self.secret))


@dataclass(frozen=True)
class SendBalanceProof(SendMessageEvent):
    """ Event to send a balance-proof to the counter-party, used after a lock
    is unlocked locally allowing the counter-party to claim it.

    Used by payers: The initiator and mediator nodes.

    Note:
        This event has a dual role, it serves as a synchronization and as
        balance-proof for the netting channel smart contract.

        Nodes need to keep the last known locksroot synchronized. This is
        required by the receiving end of a transfer in order to properly
        validate. The rule is "only the party that owns the current payment
        channel may change it" (remember that a netting channel is composed of
        two uni-directional channels), as a consequence the locksroot is only
        updated by the recipient once a balance proof message is received.
    """

    payment_identifier: PaymentID
    token_address: TokenAddress
    balance_proof: BalanceProofUnsignedState = field(repr=False)
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(self, "secrethash", sha256_secrethash(self.secret))


@dataclass(frozen=True)
class SendSecretRequest(SendMessageEvent):
    """ Event used by a target node to request the secret from the initiator
    (`recipient`).
    """

    payment_identifier: PaymentID
    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash


@dataclass(frozen=True)
class SendRefundTransfer(SendMessageEvent):
    """ Event used to cleanly backtrack the current node in the route.
    This message will pay back the same amount of token from the recipient to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """

    transfer: LockedTransferUnsignedState

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof


@dataclass(frozen=True)
class EventUnlockSuccess(Event):
    """ Event emitted when a lock unlock succeded. """

    identifier: PaymentID
    secrethash: SecretHash


@dataclass(frozen=True)
class EventUnlockFailed(Event):
    """ Event emitted when a lock unlock failed. """

    identifier: PaymentID
    secrethash: SecretHash
    reason: str


@dataclass(frozen=True)
class EventUnlockClaimSuccess(Event):
    """ Event emitted when a lock claim succeded. """

    identifier: PaymentID
    secrethash: SecretHash


@dataclass(frozen=True)
class EventUnlockClaimFailed(Event):
    """ Event emitted when a lock claim failed. """

    identifier: PaymentID
    secrethash: SecretHash
    reason: str


@dataclass(frozen=True)
class EventUnexpectedSecretReveal(Event):
    """ Event emitted when an unexpected secret reveal message is received. """

    secrethash: SecretHash
    reason: str


@dataclass(frozen=True)
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

    secrethash: SecretHash
    route: List[Address]
    token_network_address: TokenNetworkAddress
