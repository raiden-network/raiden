import random

from raiden.transfer import channel
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.state import TokenNetworkState
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionChannelCoopSettle,
    ActionChannelSetRevealTimeout,
    ActionChannelWithdraw,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveUpdateTransfer,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.utils.typing import MYPY_ANNOTATION, BlockHash, BlockNumber, List, Union

# TODO: The proper solution would be to introduce a marker for state changes
# that contains channel IDs and other specific channel attributes
StateChangeWithChannelID = Union[
    ActionChannelClose,
    ActionChannelCoopSettle,
    ActionChannelWithdraw,
    ActionChannelSetRevealTimeout,
    ContractReceiveChannelClosed,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelSettled,
    ContractReceiveUpdateTransfer,
    ContractReceiveChannelWithdraw,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawRequest,
    ReceiveWithdrawExpired,
]


def subdispatch_to_channel_by_id(
    token_network_state: TokenNetworkState,
    state_change: StateChangeWithChannelID,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    events = []

    ids_to_channels = token_network_state.channelidentifiers_to_channels

    channel_state = ids_to_channels.get(state_change.channel_identifier)

    if channel_state:
        result = channel.state_transition(
            channel_state=channel_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )

        partner_to_channelids = token_network_state.partneraddresses_to_channelidentifiers[
            channel_state.partner_state.address
        ]

        channel_identifier = state_change.channel_identifier
        if result.new_state is None:
            del ids_to_channels[channel_identifier]
            partner_to_channelids.remove(channel_identifier)
        else:
            ids_to_channels[channel_identifier] = result.new_state

        events.extend(result.events)

    return TransitionResult(token_network_state, events)


def handle_channel_close(
    token_network_state: TokenNetworkState,
    state_change: ActionChannelClose,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_channel_withdraw(
    token_network_state: TokenNetworkState,
    state_change: ActionChannelWithdraw,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_channel_coop_settle(
    token_network_state: TokenNetworkState,
    state_change: ActionChannelCoopSettle,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_channel_set_reveal_timeout(
    token_network_state: TokenNetworkState,
    state_change: ActionChannelSetRevealTimeout,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_channelnew(
    token_network_state: TokenNetworkState, state_change: ContractReceiveChannelNew
) -> TransitionResult:
    events: List[Event] = []

    channel_state = state_change.channel_state
    channel_identifier = channel_state.identifier
    partner_address = channel_state.partner_state.address

    # Ignore duplicated channelnew events. For this to work properly on channel
    # reopens the blockchain events ChannelSettled and ChannelOpened must be
    # processed in correct order, this should be guaranteed by the filters in
    # the ethereum node
    if channel_identifier not in token_network_state.channelidentifiers_to_channels:
        token_network_state.channelidentifiers_to_channels[channel_identifier] = channel_state
        addresses_to_ids = token_network_state.partneraddresses_to_channelidentifiers
        addresses_to_ids[partner_address].append(channel_identifier)

    return TransitionResult(token_network_state, events)


def handle_balance(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelDeposit,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_withdraw(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelWithdraw,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_closed(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelClosed,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_settled(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelSettled,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_updated_transfer(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveUpdateTransfer,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_batch_unlock(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelBatchUnlock,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    events = []
    channel_state = token_network_state.channelidentifiers_to_channels.get(
        state_change.canonical_identifier.channel_identifier
    )
    if channel_state is not None:
        sub_iteration = channel.state_transition(
            channel_state=channel_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
        events.extend(sub_iteration.events)

        if sub_iteration.new_state is None:

            token_network_state.partneraddresses_to_channelidentifiers[
                channel_state.partner_state.address
            ].remove(channel_state.identifier)

            del token_network_state.channelidentifiers_to_channels[channel_state.identifier]

    return TransitionResult(token_network_state, events)


def handle_receive_channel_withdraw_request(
    token_network_state: TokenNetworkState,
    state_change: ReceiveWithdrawRequest,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_receive_channel_withdraw(
    token_network_state: TokenNetworkState,
    state_change: ReceiveWithdrawConfirmation,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_receive_channel_withdraw_expired(
    token_network_state: TokenNetworkState,
    state_change: ReceiveWithdrawExpired,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    return subdispatch_to_channel_by_id(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )


def state_transition(
    token_network_state: TokenNetworkState,
    state_change: StateChange,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    # pylint: disable=too-many-branches,unidiomatic-typecheck
    iteration = TransitionResult(token_network_state, [])

    if type(state_change) == ActionChannelClose:
        assert isinstance(state_change, ActionChannelClose), MYPY_ANNOTATION
        iteration = handle_channel_close(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionChannelWithdraw:
        assert isinstance(state_change, ActionChannelWithdraw), MYPY_ANNOTATION
        iteration = handle_channel_withdraw(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionChannelCoopSettle:
        assert isinstance(state_change, ActionChannelCoopSettle), MYPY_ANNOTATION
        iteration = handle_channel_coop_settle(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionChannelSetRevealTimeout:
        assert isinstance(state_change, ActionChannelSetRevealTimeout), MYPY_ANNOTATION
        iteration = handle_channel_set_reveal_timeout(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelNew:
        assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
        iteration = handle_channelnew(
            token_network_state=token_network_state, state_change=state_change
        )
    elif type(state_change) == ContractReceiveChannelDeposit:
        assert isinstance(state_change, ContractReceiveChannelDeposit), MYPY_ANNOTATION
        iteration = handle_balance(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelWithdraw:
        assert isinstance(state_change, ContractReceiveChannelWithdraw), MYPY_ANNOTATION
        iteration = handle_withdraw(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelClosed:
        assert isinstance(state_change, ContractReceiveChannelClosed), MYPY_ANNOTATION
        iteration = handle_closed(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelSettled:
        assert isinstance(state_change, ContractReceiveChannelSettled), MYPY_ANNOTATION
        iteration = handle_settled(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveUpdateTransfer:
        assert isinstance(state_change, ContractReceiveUpdateTransfer), MYPY_ANNOTATION
        iteration = handle_updated_transfer(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        iteration = handle_batch_unlock(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveWithdrawRequest:
        assert isinstance(state_change, ReceiveWithdrawRequest), MYPY_ANNOTATION
        iteration = handle_receive_channel_withdraw_request(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveWithdrawConfirmation:
        assert isinstance(state_change, ReceiveWithdrawConfirmation), MYPY_ANNOTATION
        iteration = handle_receive_channel_withdraw(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveWithdrawExpired:
        assert isinstance(state_change, ReceiveWithdrawExpired), MYPY_ANNOTATION
        iteration = handle_receive_channel_withdraw_expired(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
            pseudo_random_generator=pseudo_random_generator,
        )

    return iteration
