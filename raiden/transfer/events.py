from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

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
from raiden.utils.formatting import to_checksum_address
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    BlockTimeout,
    Callable,
    ChannelID,
    Dict,
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
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    WithdrawAmount,
)

if TYPE_CHECKING:
    from raiden.transfer.state_change import UpdateServicesAddressesStateChange

# pylint: disable=too-many-arguments,too-few-public-methods


@dataclass(frozen=True)
class SendWithdrawRequest(SendMessageEvent):
    """Event used by node to request a withdraw from channel partner."""

    total_withdraw: WithdrawAmount
    participant: Address
    expiration: BlockExpiration
    nonce: Nonce
    coop_settle: bool = False

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"total_withdraw: {self.total_withdraw} expiration: {self.expiration} "
            f"participant: {to_checksum_address(self.participant)} nonce: {self.nonce} "
            f"coop_settle: {self.coop_settle}"
            f">"
        )


@dataclass(frozen=True)
class SendWithdrawConfirmation(SendMessageEvent):
    """Event used by node to confirm a withdraw for a channel's partner."""

    total_withdraw: WithdrawAmount
    participant: Address
    expiration: BlockExpiration
    nonce: Nonce

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"total_withdraw: {self.total_withdraw} expiration: {self.expiration} "
            f"participant: {to_checksum_address(self.participant)} nonce: {self.nonce} "
            f">"
        )


@dataclass(frozen=True)
class SendWithdrawExpired(SendMessageEvent):
    """Event used by node to expire a withdraw request."""

    total_withdraw: WithdrawAmount
    participant: Address
    nonce: Nonce
    expiration: BlockExpiration

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"total_withdraw: {self.total_withdraw} expiration: {self.expiration} "
            f"participant: {to_checksum_address(self.participant)} nonce: {self.nonce} "
            f">"
        )


@dataclass(frozen=True)
class ContractSendChannelWithdraw(ContractSendEvent):
    """Event emitted if node wants to withdraw from current channel balance."""

    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    partner_signature: Signature

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"canonical_identifier: {self.canonical_identifier} "
            f"total_withdraw: {self.total_withdraw} expiration: {self.expiration} "
            f"partner_signature: {to_hex(self.partner_signature)} "
            f">"
        )


@dataclass(frozen=True)
class ContractSendChannelCoopSettle(ContractSendEvent):
    """Event emitted if node wants to withdraw from current channel balance."""

    canonical_identifier: CanonicalIdentifier
    our_total_withdraw: WithdrawAmount
    partner_total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    # These are the partner's signatures of the two withdraws.
    # Our signature of that data will be constructed again in the event-handler
    signature_our_withdraw: Signature
    signature_partner_withdraw: Signature

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"canonical_identifier: {self.canonical_identifier} "
            f"our_total_withdraw: {self.our_total_withdraw} "
            f"partner_total_withdraw: {self.partner_total_withdraw} "
            f"expiration: {self.expiration} "
            f"signature_partner_withdraw: {to_hex(self.signature_partner_withdraw)} "
            f"signature_our_withdraw: {to_hex(self.signature_our_withdraw)} "
            f">"
        )


@dataclass(frozen=True)
class ContractSendChannelClose(ContractSendEvent):
    """Event emitted to close the netting channel.
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
    """Event emitted if the netting channel must be settled."""

    canonical_identifier: CanonicalIdentifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """Event emitted if the netting channel balance proof must be updated."""

    balance_proof: BalanceProofSignedState

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.balance_proof.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.balance_proof.channel_identifier


@dataclass(frozen=True)
class ContractSendChannelBatchUnlock(ContractSendEvent):
    """Look for unlocks that we should do after settlement

    This will only lead to an on-chain unlock if there are locks that can be
    unlocked to our benefit.

    Usually, we would check if this is the case in the state machine and skip
    the creation of this event if no profitable locks are found. But if a
    channel was closed with another BP than the latest one, we need to look in
    the database for the locks that correspond to the on-chain data. Searching
    the database is not possible in the state machine, so we create this event
    in every case and do the check in the event handler.
    Since locks for both receiving and sending transfers can potentially return
    tokens to use, this event leads to 0-2 on-chain transactions.
    """

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
    """Event emitted when the lock must be claimed on-chain."""

    secret: Secret = field(repr=False)

    def __repr__(self) -> str:
        secrethash = sha256_secrethash(self.secret)
        return "ContractSendSecretReveal(secrethash={} triggered_by_block_hash={})".format(
            to_hex(secrethash), to_hex(self.triggered_by_block_hash)
        )


@dataclass(frozen=True)
class UpdateServicesAddresses(Event):
    """Transition used when adding a new service address."""

    service_address: Address
    validity: int

    @staticmethod
    def from_state_change(
        state_change: "UpdateServicesAddressesStateChange",
    ) -> "UpdateServicesAddresses":
        return UpdateServicesAddresses(
            service_address=state_change.service,
            validity=state_change.valid_till,
        )


@dataclass(frozen=True)
class EventPaymentSentSuccess(Event):
    """Event emitted by the initiator when a transfer is considered successful.

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

    token_network_registry_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    amount: PaymentAmount
    target: TargetAddress
    secret: Secret
    route: List[Address]

    def __repr__(self) -> str:
        route_str = ",".join(to_checksum_address(x) for x in self.route)
        return (
            f"{self.__class__.__name__}< "
            f"token_network_address: {to_checksum_address(self.token_network_address)} "
            f"identifier: {self.identifier} amount: {self.amount} "
            f"target: {to_checksum_address(self.target)} "
            f"secret: {to_hex(self.secret)} "
            f"route: [{route_str}] "
            f">"
        )


@dataclass(frozen=True)
class EventPaymentSentFailed(Event):
    """Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    token_network_registry_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    target: TargetAddress
    reason: str

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"token_network_address: {to_checksum_address(self.token_network_address)} "
            f"identifier: {self.identifier} "
            f"target: {to_checksum_address(self.target)} "
            f"reason: {self.reason} "
            f">"
        )


@dataclass(frozen=True)
class EventPaymentReceivedSuccess(Event):
    """Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    token_network_registry_address: TokenNetworkRegistryAddress
    token_network_address: TokenNetworkAddress
    identifier: PaymentID
    amount: PaymentAmount
    initiator: InitiatorAddress

    def __post_init__(self) -> None:
        if self.amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if self.amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"token_network_address: {to_checksum_address(self.token_network_address)} "
            f"identifier: {self.identifier} amount: {self.amount} "
            f"initiator: {to_checksum_address(self.initiator)} "
            f">"
        )


@dataclass(frozen=True)
class EventInvalidReceivedTransferRefund(Event):
    """Event emitted when an invalid refund transfer is received."""

    payment_identifier: PaymentID
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedLockExpired(Event):
    """Event emitted when an invalid lock expired message is received."""

    secrethash: SecretHash
    reason: str

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"secrethash: {to_hex(self.secrethash)} "
            f"reason: {self.reason} "
            f">"
        )


@dataclass(frozen=True)
class EventInvalidReceivedLockedTransfer(Event):
    """Event emitted when an invalid locked transfer is received."""

    payment_identifier: PaymentID
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedUnlock(Event):
    """Event emitted when an invalid unlock message is received."""

    secrethash: SecretHash
    reason: str

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}< "
            f"secrethash: {to_hex(self.secrethash)} "
            f"reason: {self.reason} "
            f">"
        )


@dataclass(frozen=True)
class EventInvalidReceivedWithdrawRequest(Event):
    """Event emitted when an invalid withdraw request is received."""

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedWithdraw(Event):
    """Event emitted when an invalid withdraw confirmation is received."""

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidReceivedWithdrawExpired(Event):
    """Event emitted when an invalid withdraw expired event is received."""

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidActionWithdraw(Event):
    """Event emitted when an invalid withdraw is initiated."""

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidActionCoopSettle(Event):
    """Event emitted when an invalid coop-settle is initiated."""

    attempted_withdraw: WithdrawAmount
    reason: str


@dataclass(frozen=True)
class EventInvalidActionSetRevealTimeout(Event):
    """Event emitted when an invalid withdraw is initiated."""

    reveal_timeout: BlockTimeout
    reason: str


@dataclass(frozen=True)
class SendProcessed(SendMessageEvent):
    pass


@dataclass(frozen=True)
class EventInvalidSecretRequest(Event):
    """Event emitted when an invalid SecretRequest is received."""

    payment_identifier: PaymentID
    intended_amount: PaymentAmount
    actual_amount: PaymentAmount


@dataclass(frozen=True)
class RequestMetadata(Event):
    dependant_events: List[SendMessageEvent]


@dataclass
class EventWrapper:
    """
    Some events have missing data and need to be encapsulated inside wrapping events that will
    fetch this data before they can be processed.
    """

    events: List[Event]
    _wrapping_map: Dict[object, Callable] = field(init=False)

    def __post_init__(self) -> None:
        self._wrapping_map: Dict[object, Callable] = defaultdict(lambda: lambda x: x)
        self._wrapping_map.update({SendMessageEvent: self._wrap_send_message_event})

    @staticmethod
    def _wrap_send_message_event(event: SendMessageEvent) -> Event:
        return RequestMetadata([event]) if not event.recipient_metadata else event

    def wrap_events(self) -> List[Event]:
        wrapped_events = []
        for event in self.events:
            t_event = type(event)
            method = self._wrapping_map[t_event]
            wrapped_events.append(method(event))
        return wrapped_events
