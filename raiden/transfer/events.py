from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    ContractSendEvent,
    ContractSendExpirableEvent,
    Event,
    SendMessageEvent,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import BalanceProofSignedState
from raiden.utils import pex, sha3
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    ChannelID,
    InitiatorAddress,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
)

if TYPE_CHECKING:
    from dataclasses import dataclass, field
else:
    from raiden.storage.serialization import dataclass, field

# pylint: disable=too-many-arguments,too-few-public-methods


@dataclass
class ContractSendChannelClose(ContractSendEvent):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    canonical_identifier: CanonicalIdentifier
    balance_proof: Optional[BalanceProofSignedState]

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class ContractSendChannelSettle(ContractSendEvent):
    """ Event emitted if the netting channel must be settled. """

    canonical_identifier: CanonicalIdentifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """ Event emitted if the netting channel balance proof must be updated. """

    balance_proof: BalanceProofSignedState

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.balance_proof.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.balance_proof.channel_identifier


@dataclass
class ContractSendChannelBatchUnlock(ContractSendEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    canonical_identifier: CanonicalIdentifier
    participant: Address

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(repr=False)
class ContractSendSecretReveal(ContractSendExpirableEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    secret: Secret = field(repr=False)

    def __repr__(self):
        secrethash: SecretHash = SecretHash(sha3(self.secret))
        return ("ContractSendSecretReveal(secrethash={} triggered_by_block_hash={})").format(
            secrethash, pex(self.triggered_by_block_hash)
        )


@dataclass
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

    payment_network_identifier: PaymentNetworkID
    token_network_identifier: TokenNetworkID
    identifier: PaymentID
    amount: PaymentAmount
    target: TargetAddress
    secret: Optional[Secret] = None


@dataclass
class EventPaymentSentFailed(Event):
    """ Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    payment_network_identifier: PaymentNetworkID
    token_network_identifier: TokenNetworkID
    identifier: PaymentID
    target: TargetAddress
    reason: str


@dataclass
class EventPaymentReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    payment_network_identifier: PaymentNetworkID
    token_network_identifier: TokenNetworkID
    identifier: PaymentID
    amount: TokenAmount
    initiator: InitiatorAddress

    def __post_init__(self):
        if self.amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if self.amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")


@dataclass
class EventInvalidReceivedTransferRefund(Event):
    """ Event emitted when an invalid refund transfer is received. """

    payment_identifier: PaymentID
    reason: str


@dataclass
class EventInvalidReceivedLockExpired(Event):
    """ Event emitted when an invalid lock expired message is received. """

    secrethash: SecretHash
    reason: str


@dataclass
class EventInvalidReceivedLockedTransfer(Event):
    """ Event emitted when an invalid locked transfer is received. """

    payment_identifier: PaymentID
    reason: str


@dataclass
class EventInvalidReceivedUnlock(Event):
    """ Event emitted when an invalid unlock message is received. """

    secrethash: SecretHash
    reason: str


@dataclass
class SendProcessed(SendMessageEvent):
    pass
