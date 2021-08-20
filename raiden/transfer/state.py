# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from random import Random

import marshmallow
from eth_utils import to_hex

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
from raiden.utils.formatting import lpex, to_checksum_address
from raiden.utils.typing import (
    Address,
    AddressMetadata,
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
    List,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    Signature,
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
from raiden.utils.validation import MetadataValidation

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


class NetworkState(Enum):
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"
    REACHABLE = "reachable"


def message_identifier_from_prng(prng: Random) -> MessageID:
    return MessageID(prng.randint(0, UINT64_MAX))


@dataclass
class PaymentMappingState(State):
    """Global map from secrethash to a transfer task.
    This mapping is used to quickly dispatch state changes by secrethash, for
    those that don't have a balance proof, e.g. SecretReveal.
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


@dataclass
class HopState(State):
    """Information about the next hop."""

    node_address: Address
    channel_identifier: ChannelID

    def __post_init__(self) -> None:
        typecheck(self.node_address, T_Address)


@dataclass
class RouteState(MetadataValidation, State):
    """A possible route for a payment to a given target."""

    # TODO: Add timestamp
    route: List[Address]
    address_to_metadata: Dict[Address, AddressMetadata] = field(default_factory=dict)
    swaps: Dict[Address, TokenNetworkAddress] = field(default_factory=dict)
    estimated_fee: FeeAmount = FeeAmount(0)

    def __post_init__(self) -> None:
        """Validate address_to_metadata.

        Currently any validation error will cause a :class:``ValueError`` to be raised.
        This needs to be caught in higher layers.

        In the future a more granular validation may be introduced.
        """
        validation_errors = self.validate_address_metadata()
        if validation_errors:
            addresses_with_errors = ", ".join(
                f"{to_checksum_address(address)}: {errors}"
                for address, errors in validation_errors.items()
            )
            raise ValueError(f"Could not validate metadata {addresses_with_errors}.")

    def get_metadata(self) -> Optional[Dict[Address, AddressMetadata]]:
        return self.address_to_metadata

    def hop_after(self, address: Address) -> Optional[Address]:
        try:
            idx = self.route.index(address)
            return self.route[idx + 1]
        except (ValueError, IndexError):
            # The queried address was not in the route
            # or the queried address was the last hop
            return None

    def __repr__(self) -> str:
        return "RouteState ({}), fee: {}".format(
            " -> ".join(to_checksum_address(addr) for addr in self.route),
            self.estimated_fee,
        )


@dataclass
class HashTimeLockState(State):
    """Represents a hash time lock."""

    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash
    encoded: EncodedData = field(init=False, repr=False)

    def __post_init__(self) -> None:
        typecheck(self.amount, T_PaymentWithFeeAmount)
        typecheck(self.expiration, T_BlockNumber)
        typecheck(self.secrethash, T_Secret)

        from raiden.messages.transfers import Lock  # put here to avoid cyclic dependencies

        lock = Lock(amount=self.amount, expiration=self.expiration, secrethash=self.secrethash)
        self.encoded = EncodedData(lock.as_bytes)


@dataclass
class UnlockPartialProofState(State):
    """Stores the lock along with its unlocking secret."""

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
    """Represents the status of a transaction."""

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
class SuccessfulTransactionState(State):
    """Represents the status of a transaction."""

    finished_block_number: BlockNumber
    started_block_number: Optional[BlockNumber] = None

    def __post_init__(self) -> None:
        is_valid_start = self.started_block_number is None or isinstance(
            self.started_block_number, T_BlockNumber
        )
        is_valid_finish = isinstance(self.finished_block_number, T_BlockNumber)

        if not is_valid_start:
            raise ValueError("started_block_number must be None or a block_number")

        if not is_valid_finish:
            raise ValueError("finished_block_number must be None or a block_number")


@dataclass
class PendingLocksState(State):
    locks: List[EncodedData]


def make_empty_pending_locks_state() -> PendingLocksState:
    return PendingLocksState([])


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
    recipient_metadata: Optional[AddressMetadata] = None


@dataclass
class PendingWithdrawState:
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce
    recipient_metadata: Optional[AddressMetadata] = None


@dataclass
class CoopSettleState:
    total_withdraw_initiator: WithdrawAmount
    total_withdraw_partner: WithdrawAmount
    expiration: BlockExpiration
    partner_signature_request: Optional[Signature] = None
    partner_signature_confirmation: Optional[Signature] = None
    transaction: Optional[TransactionExecutionStatus] = None


@dataclass
class NettingChannelEndState(State):
    """The state of one of the nodes in a two party netting channel."""

    address: Address
    contract_balance: Balance
    onchain_total_withdraw: WithdrawAmount = field(default=WithdrawAmount(0))
    withdraws_pending: Dict[WithdrawAmount, PendingWithdrawState] = field(
        repr=False, default_factory=dict
    )
    initiated_coop_settle: Optional[CoopSettleState] = field(default=None)
    expired_coop_settles: List[CoopSettleState] = field(repr=False, default_factory=list)
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
    """The state of a netting channel."""

    canonical_identifier: CanonicalIdentifier
    token_address: TokenAddress = field(repr=False)
    token_network_registry_address: TokenNetworkRegistryAddress = field(repr=False)
    reveal_timeout: BlockTimeout = field(repr=False)
    settle_timeout: BlockTimeout = field(repr=False)
    fee_schedule: FeeScheduleState = field(repr=False)
    our_state: NettingChannelEndState
    partner_state: NettingChannelEndState
    open_transaction: SuccessfulTransactionState
    close_transaction: Optional[TransactionExecutionStatus] = None
    settle_transaction: Optional[TransactionExecutionStatus] = None
    update_transaction: Optional[TransactionExecutionStatus] = None

    def __post_init__(self) -> None:
        typecheck(self.reveal_timeout, int)
        typecheck(self.settle_timeout, int)
        typecheck(self.open_transaction, SuccessfulTransactionState)
        typecheck(self.canonical_identifier.channel_identifier, T_ChannelID)

        if self.our_state.address == self.partner_state.address:
            raise ValueError("it is illegal to open a channel with itself")

        if self.reveal_timeout <= 0:
            raise ValueError("reveal_timeout must be a positive integer")

        if self.settle_timeout <= 0:
            raise ValueError("settle_timeout must be a positive integer")

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
    """Corresponds to a token network smart contract."""

    address: TokenNetworkAddress
    token_address: TokenAddress
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


@dataclass(init=False)
class TokenNetworkRegistryState(State):
    """Corresponds to a registry smart contract."""

    class Meta:
        unknown = marshmallow.EXCLUDE
        fields = [
            "address",
            "token_network_list",
            "tokennetworkaddresses_to_tokennetworks",
        ]  # only serialize attributes needed for init
        load_only = ["tokennetworkaddresses_to_tokennetworks"]

    address: TokenNetworkRegistryAddress
    token_network_list: List[TokenNetworkState]
    tokenaddresses_to_tokennetworkaddresses: Dict[TokenAddress, TokenNetworkAddress] = field(
        repr=False
    )
    tokennetworkaddresses_to_tokennetworks: Dict[TokenNetworkAddress, TokenNetworkState] = field(
        repr=False, default_factory=dict
    )

    def __init__(
        self,
        address: TokenNetworkRegistryAddress,
        token_network_list: List[TokenNetworkState],
        tokennetworkaddresses_to_tokennetworks: Dict[Any, TokenNetworkState] = None,
    ) -> None:
        # Fix inconsistent state from Alderaan releases. Can be removed when
        # only reading state from Bespin or later is acceptable. Those releases
        # could leave the token_network_list empty, even after TNs have been
        # added.  The TNs were only available in the other attributes. See
        # https://github.com/raiden-network/raiden/commit/922e4fdf0d54c150c1bada0d101f8085e04b68bd
        if not token_network_list and tokennetworkaddresses_to_tokennetworks:
            token_network_list = list(tokennetworkaddresses_to_tokennetworks.values())

        self.address = address
        self.token_network_list = []
        self.tokennetworkaddresses_to_tokennetworks = {}
        self.tokenaddresses_to_tokennetworkaddresses = {}
        for tn in token_network_list:
            self.add_token_network(tn)

    def add_token_network(self, token_network: TokenNetworkState) -> None:
        self.token_network_list.append(token_network)
        self.tokennetworkaddresses_to_tokennetworks[token_network.address] = token_network
        self.tokenaddresses_to_tokennetworkaddresses[
            token_network.token_address
        ] = token_network.address


@dataclass(repr=False)
class ChainState(State):
    """Umbrella object that stores the per blockchain state.
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
    payment_mapping: PaymentMappingState = field(repr=False, default_factory=PaymentMappingState)
    pending_transactions: List[ContractSendEvent] = field(repr=False, default_factory=list)
    queueids_to_queues: QueueIdsToQueues = field(repr=False, default_factory=dict)
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

    @property
    def addresses_to_channel(
        self,
    ) -> Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState]:
        """Find the channel for a partner by his address and token network"""
        return {
            (token_network.address, channel.partner_state.address): channel
            for token_network_registry in self.identifiers_to_tokennetworkregistries.values()
            for token_network in token_network_registry.token_network_list
            for channel in token_network.channelidentifiers_to_channels.values()
        }


def get_address_metadata(
    address: Address, route_states: List[RouteState]
) -> Optional[AddressMetadata]:

    for route_state in route_states:
        recipient_metadata = route_state.address_to_metadata.get(address, None)
        if recipient_metadata is not None:
            return recipient_metadata
    return None
