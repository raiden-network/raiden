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
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    PaymentNetworkState,
    TokenNetworkState,
    TransactionChannelNewBalance,
)
from raiden.utils.typing import (
    Address,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    FeeAmount,
    Locksroot,
    MessageID,
    Nonce,
    PaymentID,
    PaymentNetworkAddress,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_Secret,
    T_SecretHash,
    T_SecretRegistryAddress,
    TokenAmount,
    TokenNetworkAddress,
    TransferID,
)


@dataclass
class BalanceProofStateChange(AuthenticatedSenderStateChange):
    """ Marker used for state changes which contain a balance proof. """

    balance_proof: BalanceProofSignedState

    def __post_init__(self):
        if not isinstance(self.balance_proof, BalanceProofSignedState):
            raise ValueError("balance_proof must be an instance of BalanceProofSignedState")


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
        if not isinstance(self.block_number, T_BlockNumber):
            raise ValueError("block_number must be of type block_number")


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
class ActionChannelSetFee(StateChange):
    canonical_identifier: CanonicalIdentifier
    mediation_fee: FeeAmount

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    transfer_identifier: TransferID


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
        if not isinstance(self.block_number, T_BlockNumber):
            raise ValueError("block_number must be of type BlockNumber")

        if not isinstance(self.block_hash, T_BlockHash):
            raise ValueError("block_hash must be of type BlockHash")

        if not isinstance(self.chain_id, int):
            raise ValueError("chain_id must be int")


@dataclass
class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    payment_network_address: PaymentNetworkAddress
    token_network: TokenNetworkState

    def __post_init__(self) -> None:
        if not isinstance(self.token_network, TokenNetworkState):
            raise ValueError("token_network must be a TokenNetworkState instance.")


@dataclass
class ContractReceiveChannelNewBalance(ContractReceiveStateChange):
    """ A channel to which this node IS a participant had a deposit. """

    canonical_identifier: CanonicalIdentifier
    deposit_transaction: TransactionChannelNewBalance

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
class ActionLeaveAllNetworks(StateChange):
    """ User is quitting all payment networks. """

    pass


@dataclass
class ActionChangeNodeNetworkState(StateChange):
    """ The network state of `node_address` changed. """

    node_address: Address
    network_state: str

    def __post_init__(self) -> None:
        if not isinstance(self.node_address, T_Address):
            raise ValueError("node_address must be an address instance")


@dataclass
class ContractReceiveNewPaymentNetwork(ContractReceiveStateChange):
    """ Registers a new payment network.
    A payment network corresponds to a registry smart contract.
    """

    payment_network: PaymentNetworkState

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.payment_network, PaymentNetworkState):
            raise ValueError("payment_network must be a PaymentNetworkState instance")


@dataclass
class ContractReceiveNewTokenNetwork(ContractReceiveStateChange):
    """ A new token was registered with the payment network. """

    payment_network_address: PaymentNetworkAddress
    token_network: TokenNetworkState

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.token_network, TokenNetworkState):
            raise ValueError("token_network must be a TokenNetworkState instance")


@dataclass
class ContractReceiveSecretReveal(ContractReceiveStateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    secret_registry_address: SecretRegistryAddress
    secrethash: SecretHash
    secret: Secret

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.secret_registry_address, T_SecretRegistryAddress):
            raise ValueError("secret_registry_address must be of type SecretRegistryAddress")
        if not isinstance(self.secrethash, T_SecretHash):
            raise ValueError("secrethash must be of type SecretHash")
        if not isinstance(self.secret, T_Secret):
            raise ValueError("secret must be of type Secret")


@dataclass
class ContractReceiveChannelBatchUnlock(ContractReceiveStateChange):
    """ All the locks were claimed via the blockchain.

    Used when all the hash time locks were unlocked and a log ChannelUnlocked is emitted
    by the token network contract.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `participant` is the address to which the `unlocked_amount`
        was transferred. `returned_tokens` was transferred to the channel partner.
    """

    canonical_identifier: CanonicalIdentifier
    participant: Address
    partner: Address
    locksroot: Locksroot
    unlocked_amount: TokenAmount
    returned_tokens: TokenAmount

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.participant, T_Address):
            raise ValueError("participant must be of type address")

        if not isinstance(self.partner, T_Address):
            raise ValueError("partner must be of type address")

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
        if not isinstance(self.participant1, T_Address):
            raise ValueError("participant1 must be of type address")

        if not isinstance(self.participant2, T_Address):
            raise ValueError("participant2 must be of type address")

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
