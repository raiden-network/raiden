# pylint: disable=too-few-public-methods
from copy import deepcopy
from dataclasses import dataclass, field

from raiden.constants import EMPTY_BALANCE_HASH, UINT64_MAX, UINT256_MAX
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.transfer.utils import hash_balance_data
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    Any,
    BalanceHash,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    Callable,
    ChainID,
    ChannelID,
    Generic,
    List,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    Signature,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_Keccak256,
    T_Signature,
    T_TokenAmount,
    TokenAmount,
    TokenNetworkAddress,
    TransactionHash,
    Tuple,
    TypeVar,
    typecheck,
)

# Quick overview
# --------------
#
# Goals:
# - Reliable failure recovery.
#
# Approach:
# - Use a write-ahead-log for state changes. Under a node restart the
# latest state snapshot can be recovered and the pending state changes
# reaplied.
#
# Requirements:
# - The function call `state_transition(curr_state, state_change)` must be
# deterministic, the recovery depends on the re-execution of the state changes
# from the WAL and must produce the same result.
# - StateChange must be idempotent because the partner node might be recovering
# from a failure and a Event might be produced more than once.
#
# Requirements that are enforced:
# - A state_transition function must not produce a result that must be further
# processed, i.e. the state change must be self contained and the result state
# tree must be serializable to produce a snapshot. To enforce this inputs and
# outputs are separated under different class hierarquies (StateChange and Event).


@dataclass
class State:
    """ An isolated state, modified by StateChange messages.

    Notes:
    - Don't duplicate the same state data in two different States, instead use
    identifiers.
    - State objects may be nested.
    - State classes don't have logic by design.
    - Each iteration must operate on fresh copy of the state, treating the old
          objects as immutable.
    - This class is used as a marker for states.
    """

    pass


@dataclass
class StateChange:
    """ Declare the transition to be applied in a state object.

    StateChanges are incoming events that change this node state (eg. a
    blockchain event, a new packet, an error). It is not used for the node to
    communicate with the outer world.

    Nomenclature convention:
    - 'Receive' prefix for protocol messages.
    - 'ContractReceive' prefix for smart contract logs.
    - 'Action' prefix for other interactions.

    Notes:
    - These objects don't have logic by design.
    - This class is used as a marker for state changes.
    """

    pass


@dataclass
class Event:
    """ Events produced by the execution of a state change.

    Nomenclature convention:
    - 'Send' prefix for protocol messages.
    - 'ContractSend' prefix for smart contract function calls.
    - 'Event' for node events.

    Notes:
    - This class is used as a marker for events.
    - These objects don't have logic by design.
    - Separate events are preferred because there is a decoupling of what the
      upper layer will use the events for.
    """

    pass


@dataclass
class TransferTask(State):
    # TODO: When we turn these into dataclasses it would be a good time to move common attributes
    # of all transfer tasks like the `token_network_address` into the common subclass
    pass


@dataclass
class SendMessageEvent(Event):
    """ Marker used for events which represent off-chain protocol messages tied
    to a channel.

    Messages are sent only once, delivery is guaranteed by the transport and
    not by the state machine
    """

    recipient: Address
    canonical_identifier: CanonicalIdentifier
    message_identifier: MessageID
    queue_identifier: QueueIdentifier = field(init=False)

    def __post_init__(self) -> None:
        self.queue_identifier = QueueIdentifier(
            recipient=self.recipient, canonical_identifier=self.canonical_identifier
        )


@dataclass
class AuthenticatedSenderStateChange(StateChange):
    """ Marker used for state changes for which the sender has been verified. """

    sender: Address


@dataclass
class ContractSendEvent(Event):
    """ Marker used for events which represent on-chain transactions. """

    triggered_by_block_hash: BlockHash

    def __post_init__(self) -> None:
        typecheck(self.triggered_by_block_hash, T_BlockHash)


@dataclass
class ContractSendExpirableEvent(ContractSendEvent):
    """ Marker used for events which represent on-chain transactions which are
    time dependent.
    """

    expiration: BlockExpiration


@dataclass
class ContractReceiveStateChange(StateChange):
    """ Marker used for state changes which represent on-chain logs. """

    transaction_hash: TransactionHash
    block_number: BlockNumber
    block_hash: BlockHash

    def __post_init__(self) -> None:
        typecheck(self.block_number, T_BlockNumber)
        typecheck(self.block_hash, T_BlockHash)


T = TypeVar("T", covariant=True)
ST = TypeVar("ST", bound=State)


class TransitionResult(Generic[T]):  # pylint: disable=unsubscriptable-object
    """ Representes the result of applying a single state change.

    When a task is completed the new_state is set to None, allowing the parent
    task to cleanup after the child.
    """

    def __init__(self, new_state: T, events: List[Event]) -> None:
        self.new_state = new_state
        self.events = events

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TransitionResult)
            and self.new_state == other.new_state
            and self.events == other.events
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class StateManager(Generic[ST]):
    """ The mutable storage for the application state, this storage can do
    state transitions by applying the StateChanges to the current State.
    """

    __slots__ = ("state_transition", "current_state")

    def __init__(
        self,
        state_transition: Callable[[Optional[ST], StateChange], TransitionResult[ST]],
        current_state: Optional[ST],
    ) -> None:
        """ Initialize the state manager.

        Args:
            state_transition: function that can apply a StateChange message.
            current_state: current application state.
        """
        if not callable(state_transition):  # pragma: no unittest
            raise ValueError("state_transition must be a callable")

        self.state_transition = state_transition
        self.current_state = current_state

    def dispatch(self, state_changes: List[StateChange]) -> Tuple[ST, List[List[Event]]]:
        """ Apply the `state_change` in the current machine and return the
        resulting events.

        Args:
            state_change: An object representation of a state
            change.

        Return:
            A list of events produced by the state transition.
            It's the upper layer's responsibility to decided how to handle
            these events.
        """
        if not state_changes:
            raise ValueError("dispatch called with an empty state_changes list")

        # The state objects must be treated as immutable, so make a copy of the
        # current state and pass the copy to the state machine to be modified.
        next_state = deepcopy(self.current_state)

        # Update the current state by applying the state changes
        events: List[List[Event]] = list()
        for state_change in state_changes:
            iteration = self.state_transition(next_state, state_change)

            assert isinstance(iteration, TransitionResult)
            assert all(isinstance(e, Event) for e in iteration.events)
            assert isinstance(iteration.new_state, State)

            # Skipping the copy because this value is internal
            events.append(iteration.events)
            next_state = iteration.new_state

        self.current_state = next_state
        assert next_state is not None

        return iteration.new_state, events

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, StateManager)
            and self.state_transition == other.state_transition
            and self.current_state == other.current_state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


@dataclass
class BalanceProofUnsignedState(State):
    """ Balance proof from the local node without the signature. """

    nonce: Nonce
    transferred_amount: TokenAmount
    locked_amount: TokenAmount
    locksroot: Locksroot
    canonical_identifier: CanonicalIdentifier
    balance_hash: BalanceHash = field(default=EMPTY_BALANCE_HASH)

    def __post_init__(self) -> None:
        typecheck(self.nonce, int)
        typecheck(self.transferred_amount, T_TokenAmount)
        typecheck(self.locked_amount, T_TokenAmount)
        typecheck(self.locksroot, T_Keccak256)

        if self.nonce <= 0:
            raise ValueError("nonce cannot be zero or negative")

        if self.nonce > UINT64_MAX:
            raise ValueError("nonce is too large")

        if self.transferred_amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if self.transferred_amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

        if len(self.locksroot) != 32:
            raise ValueError("locksroot must have length 32")

        self.canonical_identifier.validate()

        self.balance_hash = hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


@dataclass
class BalanceProofSignedState(State):
    """ Proof of a channel balance that can be used on-chain to resolve
    disputes.
    """

    nonce: Nonce
    transferred_amount: TokenAmount
    locked_amount: TokenAmount
    locksroot: Locksroot
    message_hash: AdditionalHash
    signature: Signature
    sender: Address
    canonical_identifier: CanonicalIdentifier
    balance_hash: BalanceHash = field(default=EMPTY_BALANCE_HASH)

    def __post_init__(self) -> None:
        typecheck(self.nonce, int)
        typecheck(self.transferred_amount, T_TokenAmount)
        typecheck(self.locked_amount, T_TokenAmount)
        typecheck(self.locksroot, T_Keccak256)
        typecheck(self.message_hash, T_Keccak256)
        typecheck(self.signature, T_Signature)
        typecheck(self.sender, T_Address)

        if self.nonce <= 0:
            raise ValueError("nonce cannot be zero or negative")

        if self.nonce > UINT64_MAX:
            raise ValueError("nonce is too large")

        if self.transferred_amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if self.transferred_amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

        if len(self.locksroot) != 32:
            raise ValueError("locksroot must have length 32")

        if len(self.message_hash) != 32:
            raise ValueError("message_hash is an invalid hash")

        if len(self.signature) != 65:
            raise ValueError("signature is an invalid signature")

        self.canonical_identifier.validate()

        self.balance_hash = hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_address(self) -> TokenNetworkAddress:
        return self.canonical_identifier.token_network_address

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier
