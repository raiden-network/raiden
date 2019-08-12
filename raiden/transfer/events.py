from dataclasses import dataclass, field

from eth_utils import to_hex

from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    ContractSendEvent,
    ContractSendExpirableEvent,
    Event,
    SendMessageEvent,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import BalanceProofSignedState
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    ChannelID,
    InitiatorAddress,
    List,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    Signature,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    WithdrawAmount,
)

# pylint: disable=too-many-arguments,too-few-public-methods


@dataclass(frozen=True)
class SendWithdrawRequest(SendMessageEvent):
    """ Event used by node to request a withdraw from channel partner."""

    total_withdraw: WithdrawAmount
    participant: Address
    expiration: BlockExpiration
    nonce: Nonce


@dataclass(frozen=True)
class SendWithdrawConfirmation(SendMessageEvent):
    """ Event used by node to confirm a withdraw for a channel's partner."""

    total_withdraw: WithdrawAmount
    participant: Address
    expiration: BlockExpiration
    nonce: Nonce


@dataclass(frozen=True)
class SendWithdrawExpired(SendMessageEvent):
    """ Event used by node to expire a withdraw request."""

    total_withdraw: WithdrawAmount
    participant: Address
    nonce: Nonce
    expiration: BlockExpiration


@dataclass(frozen=True)
class ContractSendChannelWithdraw(ContractSendEvent):
    """ Event emitted if node wants to withdraw from current channel balance. """

    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    partner_signature: Signature


@dataclass(frozen=True)
class ContractSendChannelClose(ContractSendEvent):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    canonical_identifier: CanonicalIdentifier
    balance_proof: Optional[BalanceProofSignedState]

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ContractSendChannelSettle(ContractSendEvent):
    """ Event emitted if the netting channel must be settled. """

    canonical_identifier: CanonicalIdentifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """ Event emitted if the netting channel balance proof must be updated. """

    balance_proof: BalanceProofSignedState

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.balance_proof.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.balance_proof.channel_identifier


@dataclass(frozen=True)
class ContractSendChannelBatchUnlock(ContractSendEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    canonical_identifier: CanonicalIdentifier
    sender: Address  # sender of the lock

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(repr=False, frozen=True)
class ContractSendSecretReveal(ContractSendExpirableEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    secret: Secret = field(repr=False)

    def __repr__(self) -> str:
        secrethash = sha256_secrethash(self.secret)
        return "ContractSendSecretReveal(secrethash={} triggered_by_block_hash={})".format(
            secrethash, to_hex(self.triggered_by_block_hash)
        )


@dataclass(frozen=True)
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

    payment_network_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    amount: PaymentAmount
    target: TargetAddress
    secret: Secret
    route: List[Address]


@dataclass(frozen=True)
class EventPaymentSentFailed(Event):
    """ Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    payment_network_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    target: TargetAddress
    reason: str


@dataclass(frozen=True)
class EventPaymentReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    payment_network_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    amount: TokenAmount
    initiator: InitiatorAddress

    def __post_init__(self) -> None:
        if self.amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if self.amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")


@dataclass(frozen=True)
class EventInvalidReceivedTransferRefund(Event):
    """ Event emitted when an invalid refund transfer is received. """

    payment_identifier: PaymentID
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedLockExpired(Event):
    """ Event emitted when an invalid lock expired message is received. """

    secrethash: SecretHash
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedLockedTransfer(Event):
    """ Event emitted when an invalid locked transfer is received. """

    payment_identifier: PaymentID
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedUnlock(Event):
    """ Event emitted when an invalid unlock message is received. """

    secrethash: SecretHash
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedWithdrawRequest(Event):
    """ Event emitted when an invalid withdraw request is received. """

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedWithdraw(Event):
    """ Event emitted when an invalid withdraw confirmation is received. """

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedWithdrawExpired(Event):
    """ Event emitted when an invalid withdraw expired event is received. """

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidActionWithdraw(Event):
    """ Event emitted when an invalid withdraw is initiated. """

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class SendProcessed(SendMessageEvent):
    pass
