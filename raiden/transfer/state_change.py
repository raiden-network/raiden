# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field

from raiden.constants import EMPTY_SECRETHASH
from raiden.settings import MediationFeeConfig
from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    ContractReceiveStateChange,
    StateChange,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    TokenNetworkRegistryState,
    TokenNetworkState,
    TransactionChannelDeposit,
)
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    BlockExpiration,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    PaymentID,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    Signature,
    T_Address,
    T_BlockNumber,
    T_Secret,
    T_SecretHash,
    T_SecretRegistryAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    WithdrawAmount,
    typecheck,
)


@dataclass(frozen=True)
class BalanceProofStateChange(AuthenticatedSenderStateChange):
    """Marker used for state changes which contain a balance proof."""

    balance_proof: BalanceProofSignedState

    def __post_init__(self) -> None:
        typecheck(self.balance_proof, BalanceProofSignedState)


@dataclass(frozen=True)
class Block(StateChange):
    """Transition used when a new block is mined.
    Args:
        block_number: The current block_number.
    """

    block_number: BlockNumber
    gas_limit: BlockGasLimit
    block_hash: BlockHash

    def __post_init__(self) -> None:
        typecheck(self.block_number, T_BlockNumber)


@dataclass(frozen=True)
class ActionCancelPayment(StateChange):
    """The user requests the transfer to be cancelled.
    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    payment_identifier: PaymentID


@dataclass(frozen=True)
class ActionChannelClose(StateChange):
    """User is closing an existing channel."""

    canonical_identifier: CanonicalIdentifier

    @property
    def chain_identifier(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ActionChannelWithdraw(StateChange):
    """Withdraw funds from channel."""

    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    recipient_metadata: Optional[AddressMetadata] = None

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ActionChannelCoopSettle(StateChange):
    """Cooperatively withdraw funds from channel back to both parties
    and close the channel in a single operation."""

    canonical_identifier: CanonicalIdentifier
    recipient_metadata: Optional[AddressMetadata] = None

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ContractReceiveChannelNew(ContractReceiveStateChange):
    """A new channel was created and this node IS a participant."""

    channel_state: NettingChannelState

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.channel_state.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.channel_state.canonical_identifier.channel_identifier


@dataclass(frozen=True)
class ContractReceiveChannelClosed(ContractReceiveStateChange):
    """A channel to which this node IS a participant was closed."""

    transaction_from: Address
    canonical_identifier: CanonicalIdentifier

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ContractReceiveChannelDeposit(ContractReceiveStateChange):
    """A channel to which this node IS a participant had a deposit."""

    canonical_identifier: CanonicalIdentifier
    deposit_transaction: TransactionChannelDeposit
    fee_config: MediationFeeConfig

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ContractReceiveChannelWithdraw(ContractReceiveStateChange):
    """A channel to which this node IS a participant had a withdraw."""

    canonical_identifier: CanonicalIdentifier
    participant: Address
    total_withdraw: WithdrawAmount
    fee_config: MediationFeeConfig

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ContractReceiveChannelSettled(ContractReceiveStateChange):
    """A channel to which this node IS a participant was settled."""

    canonical_identifier: CanonicalIdentifier
    our_onchain_locksroot: Locksroot
    our_transferred_amount: TokenAmount
    partner_onchain_locksroot: Locksroot
    partner_transferred_amount: TokenAmount

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ActionChannelSetRevealTimeout(StateChange):
    """Change the reveal timeout value of a given channel."""

    canonical_identifier: CanonicalIdentifier
    reveal_timeout: BlockTimeout

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ContractReceiveNewTokenNetworkRegistry(ContractReceiveStateChange):
    """Registers a new token network registry.
    A token network registry corresponds to a registry smart contract.
    """

    token_network_registry: TokenNetworkRegistryState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.token_network_registry, TokenNetworkRegistryState)


@dataclass(frozen=True)
class ContractReceiveNewTokenNetwork(ContractReceiveStateChange):
    """A new token was registered with the token network registry."""

    token_network_registry_address: TokenNetworkRegistryAddress
    token_network: TokenNetworkState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.token_network, TokenNetworkState)


@dataclass(frozen=True)
class ContractReceiveSecretReveal(ContractReceiveStateChange):
    """A new secret was registered with the SecretRegistry contract."""

    secret_registry_address: SecretRegistryAddress
    secrethash: SecretHash
    secret: Secret

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.secret_registry_address, T_SecretRegistryAddress)
        typecheck(self.secrethash, T_SecretHash)
        typecheck(self.secret, T_Secret)


@dataclass(frozen=True)
class ContractReceiveChannelBatchUnlock(ContractReceiveStateChange):
    """All the locks were claimed via the blockchain.

    Used when all the hash time locks were unlocked and a log ChannelUnlocked is emitted
    by the token network contract.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `receiver` is the address to which the `unlocked_amount`
        was transferred. `returned_tokens` was transferred to the channel partner.
    """

    canonical_identifier: CanonicalIdentifier
    receiver: Address
    sender: Address
    locksroot: Locksroot
    unlocked_amount: TokenAmount
    returned_tokens: TokenAmount

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.receiver, T_Address)
        typecheck(self.sender, T_Address)

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ContractReceiveRouteNew(ContractReceiveStateChange):
    """New channel was created and this node is NOT a participant."""

    canonical_identifier: CanonicalIdentifier
    participant1: Address
    participant2: Address

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.participant1, T_Address)
        typecheck(self.participant2, T_Address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


# FIXME: remove on next breaking release
# This needs to be kept, so that the state changes that are already in the DB
# continue to be decodable.
@dataclass(frozen=True)
class ContractReceiveUpdateTransfer(ContractReceiveStateChange):
    canonical_identifier: CanonicalIdentifier
    nonce: Nonce

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ReceiveUnlock(BalanceProofStateChange):
    message_identifier: MessageID
    secret: Secret
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(self, "secrethash", sha256_secrethash(self.secret))


@dataclass(frozen=True)
class ReceiveDelivered(AuthenticatedSenderStateChange):
    sender: Address
    message_identifier: MessageID


@dataclass(frozen=True)
class ReceiveProcessed(AuthenticatedSenderStateChange):
    sender: Address
    message_identifier: MessageID


@dataclass(frozen=True)
class ReceiveWithdrawRequest(AuthenticatedSenderStateChange):
    """A Withdraw message received."""

    message_identifier: MessageID
    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    nonce: Nonce
    expiration: BlockExpiration
    signature: Signature
    participant: Address
    coop_settle: Optional[bool] = False
    sender_metadata: Optional[AddressMetadata] = None

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ReceiveWithdrawConfirmation(AuthenticatedSenderStateChange):
    """A Withdraw message was received."""

    message_identifier: MessageID
    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    nonce: Nonce
    expiration: BlockExpiration
    signature: Signature
    participant: Address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class ReceiveWithdrawExpired(AuthenticatedSenderStateChange):
    """A WithdrawExpired message was received."""

    message_identifier: MessageID
    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce
    participant: Address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass(frozen=True)
class UpdateServicesAddressesStateChange(StateChange):
    """A `RegisteredService` contract event was received."""

    service: Address
    valid_till: int
