# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from dataclasses import dataclass, field
from random import Random
from typing import TYPE_CHECKING, Tuple

import networkx

from raiden.constants import (
    EMPTY_LOCK_HASH,
    EMPTY_MERKLE_ROOT,
    EMPTY_SECRETHASH,
    UINT64_MAX,
    UINT256_MAX,
)
from raiden.encoding import messages
from raiden.encoding.format import buffer_for
from raiden.transfer.architecture import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ContractSendEvent,
    SendMessageEvent,
    State,
    TransferTask,
)
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.utils import lpex, pex, sha3
from raiden.utils.typing import (
    Address,
    Any,
    Balance,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    Dict,
    EncodedData,
    FeeAmount,
    Keccak256,
    List,
    LockHash,
    Locksroot,
    MessageID,
    Optional,
    PaymentNetworkID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_ChainID,
    T_ChannelID,
    T_Keccak256,
    T_PaymentWithFeeAmount,
    T_Secret,
    T_TokenAmount,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
    Union,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from messages import EnvelopeMessage


QueueIdsToQueues = Dict[QueueIdentifier, List[SendMessageEvent]]

CHANNEL_STATE_CLOSED = "closed"
CHANNEL_STATE_CLOSING = "waiting_for_close"
CHANNEL_STATE_OPENED = "opened"
CHANNEL_STATE_SETTLED = "settled"
CHANNEL_STATE_SETTLING = "waiting_for_settle"
CHANNEL_STATE_UNUSABLE = "channel_unusable"

CHANNEL_ALL_VALID_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
)

CHANNEL_STATES_PRIOR_TO_CLOSED = (CHANNEL_STATE_OPENED, CHANNEL_STATE_CLOSING)

CHANNEL_AFTER_CLOSE_STATES = (CHANNEL_STATE_CLOSED, CHANNEL_STATE_SETTLING, CHANNEL_STATE_SETTLED)

NODE_NETWORK_UNKNOWN = "unknown"
NODE_NETWORK_UNREACHABLE = "unreachable"
NODE_NETWORK_REACHABLE = "reachable"


def balanceproof_from_envelope(envelope_message: "EnvelopeMessage",) -> "BalanceProofSignedState":
    return BalanceProofSignedState(
        nonce=envelope_message.nonce,
        transferred_amount=envelope_message.transferred_amount,
        locked_amount=envelope_message.locked_amount,
        locksroot=envelope_message.locksroot,
        message_hash=envelope_message.message_hash,
        signature=envelope_message.signature,
        sender=envelope_message.sender,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=envelope_message.chain_id,
            token_network_address=envelope_message.token_network_address,
            channel_identifier=envelope_message.channel_identifier,
        ),
    )


def make_empty_merkle_tree() -> "MerkleTreeState":
    return MerkleTreeState(
        [[], [Keccak256(EMPTY_MERKLE_ROOT)]]  # the leaves are empty  # the root is the constant 0
    )


def message_identifier_from_prng(prng: Random) -> MessageID:
    return MessageID(prng.randint(0, UINT64_MAX))


def to_comparable_graph(network: networkx.Graph) -> List[List[Any]]:
    return sorted(sorted(edge) for edge in network.edges())


@dataclass
class PaymentMappingState(State):
    """ Global map from secrethash to a transfer task.
    This mapping is used to quickly dispatch state changes by secrethash, for
    those that dont have a balance proof, e.g. SecretReveal.
    This mapping forces one task per secrethash, assuming that secrethash collision
    is unlikely. Features like token swaps, that span multiple networks, must
    be encapsulated in a single task to work with this structure.
    """

    # Because of retries, there may be multiple transfers for the same payment,
    # IOW there may be more than one task for the same transfer identifier. For
    # this reason the mapping uses the secrethash as key.
    #
    # Because token swaps span multiple token networks, the state of the
    # payment task is kept in this mapping, instead of inside an arbitrary
    # token network.
    secrethashes_to_task: Dict[SecretHash, TransferTask] = field(repr=False, default_factory=dict)


# This is necessary for the routing only, maybe it should be transient state
# outside of the state tree.
@dataclass(repr=False)
class TokenNetworkGraphState(State):
    """ Stores the existing channels in the channel manager contract, used for
    route finding.
    """

    token_network_id: TokenNetworkID
    network: networkx.Graph = field(repr=False, default_factory=networkx.Graph)
    channel_identifier_to_participants: Dict[ChannelID, Tuple[Address, Address]] = field(
        repr=False, default_factory=dict
    )

    def __repr__(self):
        # pylint: disable=no-member
        return "TokenNetworkGraphState(num_edges:{})".format(len(self.network.edges))


@dataclass
class RouteState(State):
    """ A possible route provided by a routing service.

    Args:
        node_address: The address of the next_hop.
        channel_identifier: The channel identifier.
    """

    node_address: Address
    channel_identifier: ChannelID

    def __post_init__(self) -> None:
        if not isinstance(self.node_address, T_Address):
            raise ValueError("node_address must be an address instance")


@dataclass
class HashTimeLockState(State):
    """ Represents a hash time lock. """

    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash
    encoded: EncodedData = field(init=False, repr=False)
    lockhash: LockHash = field(repr=False, default=EMPTY_LOCK_HASH)

    def __post_init__(self) -> None:
        if not isinstance(self.amount, T_PaymentWithFeeAmount):
            raise ValueError("amount must be a PaymentWithFeeAmount instance")

        if not isinstance(self.expiration, T_BlockNumber):
            raise ValueError("expiration must be a BlockNumber instance")

        if not isinstance(self.secrethash, T_Keccak256):
            raise ValueError("secrethash must be a Keccak256 instance")

        packed = messages.Lock(buffer_for(messages.Lock))
        # pylint: disable=assigning-non-slot
        packed.amount = self.amount
        packed.expiration = self.expiration
        packed.secrethash = self.secrethash

        self.encoded = EncodedData(packed.data)

        self.lockhash = LockHash(sha3(self.encoded))


@dataclass
class UnlockPartialProofState(State):
    """ Stores the lock along with its unlocking secret. """

    lock: HashTimeLockState
    secret: Secret = field(repr=False)
    amount: PaymentWithFeeAmount = field(repr=False, default=PaymentWithFeeAmount(0))
    expiration: BlockExpiration = field(repr=False, default=BlockExpiration(0))
    secrethash: SecretHash = field(repr=False, default=EMPTY_SECRETHASH)
    encoded: EncodedData = field(init=False, repr=False)
    lockhash: LockHash = field(repr=False, default=EMPTY_LOCK_HASH)

    def __post_init__(self) -> None:
        if not isinstance(self.lock, HashTimeLockState):
            raise ValueError("lock must be a HashTimeLockState instance")

        if not isinstance(self.secret, T_Secret):
            raise ValueError("secret must be a secret instance")

        self.amount = self.lock.amount
        self.expiration = self.lock.expiration
        self.secrethash = self.lock.secrethash
        self.encoded = self.lock.encoded
        self.lockhash = self.lock.lockhash


@dataclass
class UnlockProofState(State):
    """ An unlock proof for a given lock. """

    merkle_proof: List[Keccak256]
    lock_encoded: bytes
    secret: Secret = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.secret, T_Secret):
            raise ValueError("secret must be a secret instance")


@dataclass
class TransactionExecutionStatus(State):
    """ Represents the status of a transaction. """

    SUCCESS = "success"
    FAILURE = "failure"
    VALID_RESULT_VALUES = (SUCCESS, FAILURE)

    started_block_number: Optional[BlockNumber] = None
    finished_block_number: Optional[BlockNumber] = None
    result: Optional[str] = None

    def __post_init__(self) -> None:
        is_valid_start = self.started_block_number is None or isinstance(
            self.started_block_number, T_BlockNumber
        )
        is_valid_finish = self.finished_block_number is None or isinstance(
            self.finished_block_number, T_BlockNumber
        )
        is_valid_result = self.result is None or self.result in self.VALID_RESULT_VALUES
        is_valid_result = self.result is None or self.result in self.VALID_RESULT_VALUES

        if not is_valid_start:
            raise ValueError("started_block_number must be None or a block_number")

        if not is_valid_finish:
            raise ValueError("finished_block_number must be None or a block_number")

        if not is_valid_result:
            raise ValueError(f"result must be one of '{self.SUCCESS}', '{self.FAILURE}' or 'None'")


@dataclass
class MerkleTreeState(State):
    layers: List[List[Keccak256]]


@dataclass(order=True)
class TransactionChannelNewBalance(State):
    participant_address: Address
    contract_balance: TokenAmount
    deposit_block_number: BlockNumber

    def __post_init__(self) -> None:
        if not isinstance(self.participant_address, T_Address):
            raise ValueError("participant_address must be of type address")

        if not isinstance(self.contract_balance, T_TokenAmount):
            raise ValueError("contract_balance must be of type token_amount")

        if not isinstance(self.deposit_block_number, T_BlockNumber):
            raise ValueError("deposit_block_number must be of type block_number")


@dataclass(order=True)
class TransactionOrder(State):
    block_number: BlockNumber
    transaction: TransactionChannelNewBalance


@dataclass
class NettingChannelEndState(State):
    """ The state of one of the nodes in a two party netting channel. """

    address: Address
    contract_balance: Balance

    #: Locks which have been introduced with a locked transfer, however the
    #: secret is not known yet
    secrethashes_to_lockedlocks: Dict[SecretHash, HashTimeLockState] = field(
        repr=False, default_factory=dict
    )
    #: Locks for which the secret is known, but the partner has not sent an
    #: unlock off chain yet.
    secrethashes_to_unlockedlocks: Dict[SecretHash, UnlockPartialProofState] = field(
        repr=False, default_factory=dict
    )
    #: Locks for which the secret is known, the partner has not sent an
    #: unlocked off chain yet, and the secret has been registered onchain
    #: before the lock has expired.
    secrethashes_to_onchain_unlockedlocks: Dict[SecretHash, UnlockPartialProofState] = field(
        repr=False, default_factory=dict
    )
    merkletree: MerkleTreeState = field(repr=False, default_factory=make_empty_merkle_tree)
    balance_proof: Optional[Union[BalanceProofSignedState, BalanceProofUnsignedState]] = None
    onchain_locksroot: Locksroot = EMPTY_MERKLE_ROOT

    def __post_init__(self) -> None:
        if not isinstance(self.address, T_Address):
            raise ValueError("address must be an address instance")

        if not isinstance(self.contract_balance, T_TokenAmount):
            raise ValueError("balance must be a token_amount isinstance")


@dataclass
class NettingChannelState(State):
    """ The state of a netting channel. """

    canonical_identifier: CanonicalIdentifier
    token_address: TokenAddress = field(repr=False)
    payment_network_identifier: PaymentNetworkID = field(repr=False)
    reveal_timeout: BlockTimeout = field(repr=False)
    settle_timeout: BlockTimeout = field(repr=False)
    mediation_fee: FeeAmount = field(repr=False)
    our_state: NettingChannelEndState = field(repr=False)
    partner_state: NettingChannelEndState = field(repr=False)
    open_transaction: TransactionExecutionStatus
    close_transaction: Optional[TransactionExecutionStatus] = None
    settle_transaction: Optional[TransactionExecutionStatus] = None
    update_transaction: Optional[TransactionExecutionStatus] = None
    deposit_transaction_queue: List[TransactionOrder] = field(repr=False, default_factory=list)

    def __post_init__(self) -> None:
        if self.reveal_timeout >= self.settle_timeout:
            raise ValueError("reveal_timeout must be smaller than settle_timeout")

        if not isinstance(self.reveal_timeout, int) or self.reveal_timeout <= 0:
            raise ValueError("reveal_timeout must be a positive integer")

        if not isinstance(self.settle_timeout, int) or self.settle_timeout <= 0:
            raise ValueError("settle_timeout must be a positive integer")

        if not isinstance(self.open_transaction, TransactionExecutionStatus):
            raise ValueError("open_transaction must be a TransactionExecutionStatus instance")

        if self.open_transaction.result != TransactionExecutionStatus.SUCCESS:
            raise ValueError(
                "Cannot create a NettingChannelState with a non successfull open_transaction"
            )

        if not isinstance(self.canonical_identifier.channel_identifier, T_ChannelID):
            raise ValueError("channel identifier must be of type T_ChannelID")

        if (
            self.canonical_identifier.channel_identifier < 0
            or self.canonical_identifier.channel_identifier > UINT256_MAX
        ):
            raise ValueError("channel identifier should be a uint256")

        valid_close_transaction = self.close_transaction is None or isinstance(
            self.close_transaction, TransactionExecutionStatus
        )
        if not valid_close_transaction:
            raise ValueError("close_transaction must be a TransactionExecutionStatus instance")

        valid_settle_transaction = self.settle_transaction is None or isinstance(
            self.settle_transaction, TransactionExecutionStatus
        )
        if not valid_settle_transaction:
            raise ValueError(
                "settle_transaction must be a TransactionExecutionStatus instance or None"
            )

    @property
    def identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def our_total_deposit(self) -> Balance:
        # pylint: disable=E1101
        return self.our_state.contract_balance

    @property
    def partner_total_deposit(self) -> Balance:
        # pylint: disable=E1101
        return self.partner_state.contract_balance


@dataclass
class TokenNetworkState(State):
    """ Corresponds to a token network smart contract. """

    address: TokenNetworkID
    token_address: TokenAddress
    network_graph: TokenNetworkGraphState = field(repr=False)
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState] = field(
        repr=False, default_factory=dict
    )
    partneraddresses_to_channelidentifiers: Dict[Address, List[ChannelID]] = field(
        repr=False, default_factory=lambda: defaultdict(list)
    )

    def __post_init__(self) -> None:
        if not isinstance(self.address, T_Address):
            raise ValueError("address must be an address instance")

        if not isinstance(self.token_address, T_Address):
            raise ValueError("token_address must be an address instance")


@dataclass
class PaymentNetworkState(State):
    """ Corresponds to a registry smart contract. """

    address: PaymentNetworkID
    token_network_list: List[TokenNetworkState]
    tokenidentifiers_to_tokennetworks: Dict[TokenNetworkID, TokenNetworkState] = field(
        repr=False, default_factory=dict
    )
    tokenaddresses_to_tokenidentifiers: Dict[TokenAddress, TokenNetworkID] = field(
        repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        if not isinstance(self.address, T_Address):
            raise ValueError("address must be an address instance")

        self.tokenidentifiers_to_tokennetworks: Dict[TokenNetworkID, TokenNetworkState] = {
            token_network.address: token_network for token_network in self.token_network_list
        }
        self.tokenaddresses_to_tokenidentifiers: Dict[TokenAddress, TokenNetworkID] = {
            token_network.token_address: token_network.address
            for token_network in self.token_network_list
        }


@dataclass(repr=False)
class ChainState(State):
    """ Umbrella object that stores the per blockchain state.
    For each registry smart contract there must be a payment network. Within the
    payment network the existing token networks and channels are registered.

    TODO: Split the node specific attributes to a "NodeState" class
    """

    pseudo_random_generator: random.Random = field(compare=False)
    block_number: BlockNumber
    block_hash: BlockHash
    our_address: Address
    chain_id: ChainID
    identifiers_to_paymentnetworks: Dict[PaymentNetworkID, PaymentNetworkState] = field(
        repr=False, default_factory=dict
    )
    nodeaddresses_to_networkstates: Dict[Address, str] = field(repr=False, default_factory=dict)
    payment_mapping: PaymentMappingState = field(repr=False, default_factory=PaymentMappingState)
    pending_transactions: List[ContractSendEvent] = field(repr=False, default_factory=list)
    queueids_to_queues: QueueIdsToQueues = field(repr=False, default_factory=dict)
    last_transport_authdata: Optional[str] = field(repr=False, default=None)
    tokennetworkaddresses_to_paymentnetworkaddresses: Dict[
        TokenNetworkAddress, PaymentNetworkID
    ] = field(repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.block_number, T_BlockNumber):
            raise ValueError("block_number must be of BlockNumber type")

        if not isinstance(self.block_hash, T_BlockHash):
            raise ValueError("block_hash must be of BlockHash type")

        if not isinstance(self.chain_id, T_ChainID):
            raise ValueError("chain_id must be of ChainID type")

    def __repr__(self):
        return (
            "ChainState(block_number={} block_hash={} networks={} " "qty_transfers={} chain_id={})"
        ).format(
            self.block_number,
            pex(self.block_hash),
            # pylint: disable=E1101
            lpex(self.identifiers_to_paymentnetworks.keys()),
            # pylint: disable=E1101
            len(self.payment_mapping.secrethashes_to_task),
            self.chain_id,
        )
