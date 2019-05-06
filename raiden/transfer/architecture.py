# pylint: disable=too-few-public-methods
from copy import deepcopy
from dataclasses import field

from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    Callable,
    ChannelID,
    Generic,
    List,
    MessageID,
    Optional,
    T_BlockHash,
    T_BlockNumber,
    T_ChannelID,
    TransactionHash,
    Tuple,
    TypeVar,
)

if TYPE_CHECKING:
    from dataclasses import dataclass
else:
    from raiden.storage.serialization import dataclass

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
class SendMessageEvent(Event):
    """ Marker used for events which represent off-chain protocol messages tied
    to a channel.

    Messages are sent only once, delivery is guaranteed by the transport and
    not by the state machine
    """

    recipient: Address
    channel_identifier: ChannelID
    message_identifier: MessageID
    queue_identifier: QueueIdentifier = field(init=False)

    def __post_init__(self) -> None:
        # Note that here and only here channel identifier can also be 0 which stands
        # for the identifier of no channel (i.e. the global queue)
        if not isinstance(channel_identifier, T_ChannelID):
            raise ValueError("channel identifier must be of type T_ChannelIdentifier")

        self.queue_identifier = QueueIdentifier(
            recipient=recipient, channel_identifier=channel_identifier
        )
        self.message_identifier = self.message_identifier


@dataclass
class AuthenticatedSenderStateChange(StateChange):
    """ Marker used for state changes for which the sender has been verified. """

    sender: Address


@dataclass
class ContractSendEvent(Event):
    """ Marker used for events which represent on-chain transactions. """

    triggered_by_block_hash: BlockHash

    def __post_init__(self) -> None:
        if not isinstance(self.triggered_by_block_hash, T_BlockHash):
            raise ValueError("triggered_by_block_hash must be of type block_hash")


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
        if not isinstance(self.block_number, T_BlockNumber):
            raise ValueError("block_number must be of type block_number")
        if not isinstance(self.block_hash, T_BlockHash):
            raise ValueError("block_hash must be of type block_hash")


ST = TypeVar("ST", bound=State)


class StateManager(Generic[ST]):
    """ The mutable storage for the application state, this storage can do
    state transitions by applying the StateChanges to the current State.
    """

    __slots__ = ("state_transition", "current_state")

    def __init__(
        self,
        state_transition: Callable[[Optional[ST], StateChange], State],
        current_state: Optional[ST],
    ) -> None:
        """ Initialize the state manager.

        Args:
            state_transition: function that can apply a StateChange message.
            current_state: current application state.
        """
        if not callable(state_transition):
            raise ValueError("state_transition must be a callable")

        self.state_transition = state_transition
        self.current_state = current_state

    def dispatch(self, state_change: StateChange) -> Tuple[ST, List[Event]]:
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
        assert isinstance(state_change, StateChange)

        # the state objects must be treated as immutable, so make a copy of the
        # current state and pass the copy to the state machine to be modified.
        next_state = deepcopy(self.current_state)

        # update the current state by applying the change
        iteration = self.state_transition(next_state, state_change)

        assert isinstance(iteration, TransitionResult)

        self.current_state = iteration.new_state
        events = iteration.events

        assert isinstance(self.current_state, State)
        assert all(isinstance(e, Event) for e in events)

        return next_state, events

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, StateManager)
            and self.state_transition == other.state_transition
            and self.current_state == other.current_state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class TransitionResult(Generic[ST]):  # pylint: disable=unsubscriptable-object
    """ Representes the result of applying a single state change.

    When a task is completed the new_state is set to None, allowing the parent
    task to cleanup after the child.
    """

    def __init__(self, new_state: Optional[ST], events: List[Event]) -> None:
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
