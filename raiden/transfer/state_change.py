# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field
from hashlib import sha256
from random import Random

from raiden.constants import EMPTY_SECRETHASH
from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    ContractReceiveStateChange,
    StateChange,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    PaymentNetworkState,
    TokenNetworkState,
    TransactionChannelDeposit,
)
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    Locksroot,
    MessageID,
    Nonce,
    PaymentID,
    PaymentNetworkAddress,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    Signature,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_Secret,
    T_SecretHash,
    T_SecretRegistryAddress,
    TokenAmount,
    TokenNetworkAddress,
    WithdrawAmount,
    typecheck,
)


@dataclass
class BalanceProofStateChange(AuthenticatedSenderStateChange):
    """ Marker used for state changes which contain a balance proof. """

    balance_proof: BalanceProofSignedState

    def __post_init__(self):
        typecheck(self.balance_proof, BalanceProofSignedState)


@dataclass
class Block(StateChange):
    """ Transition used when a new block is mined.
    Args:
        block_number: The current block_number.
    """

    block_number: BlockNumber
    gas_limit: BlockGasLimit
    block_hash: BlockHash

    def __post_init__(self) -> None:
        typecheck(self.block_number, T_BlockNumber)


@dataclass
class ActionUpdateTransportAuthData(StateChange):
    """ Holds the last "timestamp" at which we synced
    with the transport. The timestamp could be a date/time value
    or any other value provided by the transport backend.
    Can be used later to filter the messages which have not been processed.
    """

    auth_data: str


@dataclass
class ActionCancelPayment(StateChange):
    """ The user requests the transfer to be cancelled.
    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    payment_identifier: PaymentID


@dataclass
class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

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


@dataclass
class ActionChannelWithdraw(StateChange):
    """ Withdraw funds from channel. """

    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class ActionChannelUpdateFee(StateChange):
    canonical_identifier: CanonicalIdentifier
    fee_schedule: FeeScheduleState

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class ContractReceiveChannelNew(ContractReceiveStateChange):
    """ A new channel was created and this node IS a participant. """

    channel_state: NettingChannelState

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.channel_state.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.channel_state.canonical_identifier.channel_identifier


@dataclass
class ContractReceiveChannelClosed(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was closed. """

    transaction_from: Address
    canonical_identifier: CanonicalIdentifier

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ActionInitChain(StateChange):
    pseudo_random_generator: Random = field(compare=False)
    block_number: BlockNumber
    block_hash: BlockHash
    our_address: Address
    chain_id: ChainID

    def __post_init__(self) -> None:
        typecheck(self.block_number, T_BlockNumber)
        typecheck(self.block_hash, T_BlockHash)
        typecheck(self.chain_id, int)


@dataclass
class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    payment_network_address: PaymentNetworkAddress
    token_network: TokenNetworkState

    def __post_init__(self) -> None:
        typecheck(self.token_network, TokenNetworkState)


@dataclass
class ContractReceiveChannelDeposit(ContractReceiveStateChange):
    """ A channel to which this node IS a participant had a deposit. """

    canonical_identifier: CanonicalIdentifier
    deposit_transaction: TransactionChannelDeposit

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ContractReceiveChannelWithdraw(ContractReceiveStateChange):
    """ A channel to which this node IS a participant had a withdraw. """

    canonical_identifier: CanonicalIdentifier
    participant: Address
    total_withdraw: WithdrawAmount

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ContractReceiveChannelSettled(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was settled. """

    canonical_identifier: CanonicalIdentifier
    our_onchain_locksroot: Locksroot
    partner_onchain_locksroot: Locksroot

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ActionChangeNodeNetworkState(StateChange):
    """ The network state of `node_address` changed. """

    node_address: Address
    network_state: str

    def __post_init__(self) -> None:
        typecheck(self.node_address, T_Address)


@dataclass
class ContractReceiveNewPaymentNetwork(ContractReceiveStateChange):
    """ Registers a new payment network.
    A payment network corresponds to a registry smart contract.
    """

    payment_network: PaymentNetworkState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.payment_network, PaymentNetworkState)


@dataclass
class ContractReceiveNewTokenNetwork(ContractReceiveStateChange):
    """ A new token was registered with the payment network. """

    payment_network_address: PaymentNetworkAddress
    token_network: TokenNetworkState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.token_network, TokenNetworkState)


@dataclass
class ContractReceiveSecretReveal(ContractReceiveStateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    secret_registry_address: SecretRegistryAddress
    secrethash: SecretHash
    secret: Secret

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.secret_registry_address, T_SecretRegistryAddress)
        typecheck(self.secrethash, T_SecretHash)
        typecheck(self.secret, T_Secret)


@dataclass
class ContractReceiveChannelBatchUnlock(ContractReceiveStateChange):
    """ All the locks were claimed via the blockchain.

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


@dataclass
class ContractReceiveRouteNew(ContractReceiveStateChange):
    """ New channel was created and this node is NOT a participant. """

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


@dataclass
class ContractReceiveRouteClosed(ContractReceiveStateChange):
    """ A channel was closed and this node is NOT a participant. """

    canonical_identifier: CanonicalIdentifier

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ContractReceiveUpdateTransfer(ContractReceiveStateChange):
    canonical_identifier: CanonicalIdentifier
    nonce: Nonce

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address


@dataclass
class ReceiveUnlock(BalanceProofStateChange):
    message_identifier: MessageID
    secret: Secret
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.secrethash = SecretHash(sha256(self.secret).digest())


@dataclass
class ReceiveDelivered(AuthenticatedSenderStateChange):
    sender: Address
    message_identifier: MessageID


@dataclass
class ReceiveProcessed(AuthenticatedSenderStateChange):
    sender: Address
    message_identifier: MessageID


@dataclass
class ReceiveWithdrawRequest(AuthenticatedSenderStateChange):
    """ A Withdraw message received. """

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


@dataclass
class ReceiveWithdrawConfirmation(AuthenticatedSenderStateChange):
    """ A Withdraw message was received. """

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


@dataclass
class ReceiveWithdrawExpired(AuthenticatedSenderStateChange):
    """ A WithdrawExpired message was received. """

    message_identifier: MessageID
    canonical_identifier: CanonicalIdentifier
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce
    signature: Signature
    participant: Address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address
