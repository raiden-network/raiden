# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from random import Random

import networkx
from eth_utils import to_checksum_address, to_hex

from raiden.constants import (
    EMPTY_SECRETHASH,
    LOCKSROOT_OF_NO_LOCKS,
    NULL_ADDRESS_BYTES,
    UINT64_MAX,
    UINT256_MAX,
)
from raiden.transfer.architecture import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ContractSendEvent,
    SendMessageEvent,
    State,
    TransferTask,
)
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.utils import lpex
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
    List,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_ChainID,
    T_ChannelID,
    T_PaymentWithFeeAmount,
    T_Secret,
    T_TokenAmount,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    Union,
    WithdrawAmount,
    typecheck,
)

QueueIdsToQueues = Dict[QueueIdentifier, List[SendMessageEvent]]


class ChannelState(Enum):
    STATE_CLOSED = "closed"
    STATE_CLOSING = "waiting_for_close"
    STATE_OPENED = "opened"
    STATE_SETTLED = "settled"
    STATE_SETTLING = "waiting_for_settle"
    STATE_UNUSABLE = "channel_unusable"


CHANNEL_STATES_PRIOR_TO_CLOSED = (ChannelState.STATE_OPENED, ChannelState.STATE_CLOSING)
CHANNEL_STATES_UP_TO_CLOSED = CHANNEL_STATES_PRIOR_TO_CLOSED + (ChannelState.STATE_CLOSED,)
CHANNEL_AFTER_CLOSE_STATES = (
    ChannelState.STATE_CLOSED,
    ChannelState.STATE_SETTLING,
    ChannelState.STATE_SETTLED,
)

NODE_NETWORK_UNKNOWN = "unknown"
NODE_NETWORK_UNREACHABLE = "unreachable"
NODE_NETWORK_REACHABLE = "reachable"


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
@dataclass(repr=False, eq=False)
class TokenNetworkGraphState(State):
    """ Stores the existing channels in the channel manager contract, used for
    route finding.
    """

    token_network_address: TokenNetworkAddress
    network: networkx.Graph = field(repr=False, default_factory=networkx.Graph)
    channel_identifier_to_participants: Dict[ChannelID, Tuple[Address, Address]] = field(
        repr=False, default_factory=dict
    )

    def __repr__(self) -> str:
        # pylint: disable=no-member
        return "TokenNetworkGraphState(num_edges:{})".format(len(self.network.edges))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TokenNetworkGraphState)
            and self.token_network_address == other.token_network_address
            and to_comparable_graph(self.network) == to_comparable_graph(other.network)
            and self.channel_identifier_to_participants == other.channel_identifier_to_participants
        )


@dataclass
class HopState(State):
    """ Information about the next hop. """

    node_address: Address
    channel_identifier: ChannelID

    def __post_init__(self) -> None:
        typecheck(self.node_address, T_Address)


@dataclass
class RouteState(State):
    """ A possible route for a payment to a given target. """

    # TODO: Add timestamp
    route: List[Address]
    forward_channel_id: ChannelID

    @property
    def next_hop_address(self) -> Address:
        assert len(self.route) >= 1
        return self.route[1]

    def __repr__(self) -> str:
        return "RouteState ({}), channel_id: {}".format(
            " -> ".join(to_checksum_address(addr) for addr in self.route), self.forward_channel_id
        )


@dataclass
class HashTimeLockState(State):
    """ Represents a hash time lock. """

    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash
    encoded: EncodedData = field(init=False, repr=False)

    def __post_init__(self) -> None:
        typecheck(self.amount, T_PaymentWithFeeAmount)
        typecheck(self.expiration, T_BlockNumber)
        typecheck(self.secrethash, T_Secret)

        from raiden.messages.transfers import Lock  # put here to avoid cyclic depenendcies

        lock = Lock(amount=self.amount, expiration=self.expiration, secrethash=self.secrethash)
        self.encoded = EncodedData(lock.as_bytes)


@dataclass
class UnlockPartialProofState(State):
    """ Stores the lock along with its unlocking secret. """

    lock: HashTimeLockState
    secret: Secret = field(repr=False)
    amount: PaymentWithFeeAmount = field(repr=False, default=PaymentWithFeeAmount(0))
    expiration: BlockExpiration = field(repr=False, default=BlockExpiration(0))
    secrethash: SecretHash = field(repr=False, default=EMPTY_SECRETHASH)
    encoded: EncodedData = field(init=False, repr=False)

    def __post_init__(self) -> None:
        typecheck(self.lock, HashTimeLockState)
        typecheck(self.secret, T_Secret)

        self.amount = self.lock.amount
        self.expiration = self.lock.expiration
        self.secrethash = self.lock.secrethash
        self.encoded = self.lock.encoded


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
class PendingLocksState(State):
    locks: List[EncodedData]


def make_empty_pending_locks_state() -> PendingLocksState:
    return PendingLocksState(list())


@dataclass(order=True)
class TransactionChannelDeposit(State):
    participant_address: Address
    contract_balance: TokenAmount
    deposit_block_number: BlockNumber

    def __post_init__(self) -> None:
        typecheck(self.participant_address, T_Address)
        typecheck(self.contract_balance, T_TokenAmount)
        typecheck(self.deposit_block_number, T_BlockNumber)


@dataclass
class ExpiredWithdrawState:
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce


@dataclass
class PendingWithdrawState:
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce


@dataclass
class NettingChannelEndState(State):
    """ The state of one of the nodes in a two party netting channel. """

    address: Address
    contract_balance: Balance
    onchain_total_withdraw: WithdrawAmount = field(default=WithdrawAmount(0))
    withdraws_pending: Dict[WithdrawAmount, PendingWithdrawState] = field(
        repr=False, default_factory=dict
    )
    withdraws_expired: List[ExpiredWithdrawState] = field(repr=False, default_factory=list)
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
    balance_proof: Optional[Union[BalanceProofSignedState, BalanceProofUnsignedState]] = None
    #: A list of the pending locks, in order of insertion. Used for calculating
    #: the locksroot.
    pending_locks: PendingLocksState = field(
        repr=False, default_factory=make_empty_pending_locks_state
    )
    onchain_locksroot: Locksroot = LOCKSROOT_OF_NO_LOCKS
    nonce: Nonce = field(default=Nonce(0))

    def __post_init__(self) -> None:
        typecheck(self.address, T_Address)
        typecheck(self.contract_balance, T_TokenAmount)

        if self.address == NULL_ADDRESS_BYTES:
            raise ValueError("address cannot be null.")

        if self.contract_balance < 0:
            raise ValueError("contract_balance cannot be negative.")

    @property
    def offchain_total_withdraw(self) -> WithdrawAmount:
        return max(self.withdraws_pending, default=WithdrawAmount(0))

    @property
    def total_withdraw(self) -> WithdrawAmount:
        return max(self.offchain_total_withdraw, self.onchain_total_withdraw)

    @property
    def transferred_amount(self) -> TokenAmount:
        if self.balance_proof:
            return self.balance_proof.transferred_amount
        return TokenAmount(0)


@dataclass
class NettingChannelState(State):
    """ The state of a netting channel. """

    canonical_identifier: CanonicalIdentifier
    token_address: TokenAddress = field(repr=False)
    token_network_registry_address: TokenNetworkRegistryAddress = field(repr=False)
    reveal_timeout: BlockTimeout = field(repr=False)
    settle_timeout: BlockTimeout = field(repr=False)
    fee_schedule: FeeScheduleState = field(repr=False)
    our_state: NettingChannelEndState
    partner_state: NettingChannelEndState
    open_transaction: TransactionExecutionStatus
    close_transaction: Optional[TransactionExecutionStatus] = None
    settle_transaction: Optional[TransactionExecutionStatus] = None
    update_transaction: Optional[TransactionExecutionStatus] = None

    def __post_init__(self) -> None:
        typecheck(self.reveal_timeout, int)
        typecheck(self.settle_timeout, int)
        typecheck(self.open_transaction, TransactionExecutionStatus)
        typecheck(self.canonical_identifier.channel_identifier, T_ChannelID)

        if self.reveal_timeout >= self.settle_timeout:
            raise ValueError("reveal_timeout must be smaller than settle_timeout")

        if self.our_state.address == self.partner_state.address:
            raise ValueError("it is illegal to open a channel with itself")

        if self.reveal_timeout <= 0:
            raise ValueError("reveal_timeout must be a positive integer")

        if self.settle_timeout <= 0:
            raise ValueError("settle_timeout must be a positive integer")

        if self.open_transaction.result != TransactionExecutionStatus.SUCCESS:
            raise ValueError(
                "Cannot create a NettingChannelState with a non successfull open_transaction"
            )

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
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def our_total_deposit(self) -> Balance:
        # pylint: disable=E1101
        return self.our_state.contract_balance

    @property
    def our_total_withdraw(self) -> WithdrawAmount:
        """The current total withdraw.

        If we only take offchain_total_withdraw, this means that it might go back to zero
        as there aren't pending withdraws. Taking onchain_total_withdraw means that we might
        be checking against a value that has been already increased by a pending offchain total
        withdraw. Therefore, we take the bigger value of both.
        """
        # pylint: disable=E1101
        return self.our_state.total_withdraw

    @property
    def partner_total_deposit(self) -> Balance:
        # pylint: disable=E1101
        return self.partner_state.contract_balance

    @property
    def partner_total_withdraw(self) -> WithdrawAmount:
        # pylint: disable=E1101
        return self.partner_state.total_withdraw


@dataclass
class TokenNetworkState(State):
    """ Corresponds to a token network smart contract. """

    address: TokenNetworkAddress
    token_address: TokenAddress
    network_graph: TokenNetworkGraphState = field(repr=False)
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState] = field(
        repr=False, default_factory=dict
    )
    partneraddresses_to_channelidentifiers: Dict[Address, List[ChannelID]] = field(
        repr=False, default_factory=lambda: defaultdict(list)
    )

    def __post_init__(self) -> None:
        typecheck(self.address, T_Address)
        typecheck(self.token_address, T_Address)

        self.partneraddresses_to_channelidentifiers = defaultdict(
            list, self.partneraddresses_to_channelidentifiers
        )


@dataclass
class TokenNetworkRegistryState(State):
    """ Corresponds to a registry smart contract. """

    address: TokenNetworkRegistryAddress
    token_network_list: List[TokenNetworkState]
    tokennetworkaddresses_to_tokennetworks: Dict[TokenNetworkAddress, TokenNetworkState] = field(
        repr=False, default_factory=dict
    )
    tokenaddresses_to_tokennetworkaddresses: Dict[TokenAddress, TokenNetworkAddress] = field(
        repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        typecheck(self.address, T_Address)

        if not self.tokennetworkaddresses_to_tokennetworks:
            self.tokennetworkaddresses_to_tokennetworks: Dict[
                TokenNetworkAddress, TokenNetworkState
            ] = {token_network.address: token_network for token_network in self.token_network_list}
        if not self.tokenaddresses_to_tokennetworkaddresses:
            self.tokenaddresses_to_tokennetworkaddresses: Dict[
                TokenAddress, TokenNetworkAddress
            ] = {
                token_network.token_address: token_network.address
                for token_network in self.token_network_list
            }


@dataclass(repr=False)
class ChainState(State):
    """ Umbrella object that stores the per blockchain state.
    For each registry smart contract there must be a token network registry. Within the
    token network registry the existing token networks and channels are registered.

    TODO: Split the node specific attributes to a "NodeState" class
    """

    pseudo_random_generator: random.Random = field(compare=False)
    block_number: BlockNumber
    block_hash: BlockHash
    our_address: Address
    chain_id: ChainID
    identifiers_to_tokennetworkregistries: Dict[
        TokenNetworkRegistryAddress, TokenNetworkRegistryState
    ] = field(repr=False, default_factory=dict)
    nodeaddresses_to_networkstates: Dict[Address, str] = field(repr=False, default_factory=dict)
    payment_mapping: PaymentMappingState = field(repr=False, default_factory=PaymentMappingState)
    pending_transactions: List[ContractSendEvent] = field(repr=False, default_factory=list)
    queueids_to_queues: QueueIdsToQueues = field(repr=False, default_factory=dict)
    last_transport_authdata: Optional[str] = field(repr=False, default=None)
    tokennetworkaddresses_to_tokennetworkregistryaddresses: Dict[
        TokenNetworkAddress, TokenNetworkRegistryAddress
    ] = field(repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        typecheck(self.block_number, T_BlockNumber)
        typecheck(self.block_hash, T_BlockHash)
        typecheck(self.chain_id, T_ChainID)

    def __repr__(self) -> str:
        return (
            "ChainState(block_number={} block_hash={} networks={} qty_transfers={} chain_id={})"
        ).format(
            self.block_number,
            to_hex(self.block_hash),
            # pylint: disable=E1101
            lpex(self.identifiers_to_tokennetworkregistries.keys()),
            # pylint: disable=E1101
            len(self.payment_mapping.secrethashes_to_task),
            self.chain_id,
        )
