from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import EventTransferSentFailed
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionTransferDirect,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveRouteNew,
    ReceiveTransferDirect,
)


def subdispatch_to_channel_by_id(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    events = list()

    ids_to_channels = token_network_state.channelidentifiers_to_channels
    channel_state = ids_to_channels.get(state_change.channel_identifier)

    if channel_state:
        result = channel.state_transition(
            channel_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )

        if result.new_state is None:
            del ids_to_channels[state_change.channel_identifier]
        else:
            ids_to_channels[state_change.channel_identifier] = result.new_state

        events.extend(result.events)

    return TransitionResult(token_network_state, events)


def handle_channel_close(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    return subdispatch_to_channel_by_id(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )


def handle_channelnew(token_network_state, state_change):
    events = list()

    channel_state = state_change.channel_state
    channel_id = channel_state.identifier
    our_address = channel_state.our_state.address
    partner_address = channel_state.partner_state.address

    token_network_state.network_graph.network.add_edge(
        our_address,
        partner_address,
    )

    # Ignore duplicated channelnew events. For this to work properly on channel
    # reopens the blockchain events ChannelSettled and ChannelOpened must be
    # processed in correct order, this should be guaranteed by the filters in
    # the ethereum node
    if channel_id not in token_network_state.channelidentifiers_to_channels:
        token_network_state.channelidentifiers_to_channels[channel_id] = channel_state
        token_network_state.partneraddresses_to_channels[partner_address] = channel_state

    return TransitionResult(token_network_state, events)


def handle_balance(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    return subdispatch_to_channel_by_id(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )


def handle_closed(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    return subdispatch_to_channel_by_id(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )


def handle_settled(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    return subdispatch_to_channel_by_id(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )


def handle_newroute(token_network_state, state_change):
    events = list()

    token_network_state.network_graph.network.add_edge(
        state_change.participant1,
        state_change.participant2,
    )

    return TransitionResult(token_network_state, events)


def handle_action_transfer_direct(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    receiver_address = state_change.receiver_address
    channel_state = token_network_state.partneraddresses_to_channels.get(receiver_address)

    if channel_state:
        iteration = channel.state_transition(
            channel_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
        events = iteration.events
    else:
        failure = EventTransferSentFailed(
            state_change.identifier,
            'Unknown partner channel',
        )
        events = [failure]

    return TransitionResult(token_network_state, events)


def handle_receive_transfer_direct(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    events = list()

    channel_id = state_change.balance_proof.channel_address
    channel_state = token_network_state.channelidentifiers_to_channels.get(channel_id)

    if channel_state:
        result = channel.state_transition(
            channel_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
        events.extend(result.events)

    return TransitionResult(token_network_state, events)


def handle_receive_transfer_refund(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    events = list()

    channel_id = state_change.balance_proof.channel_address
    channel_state = token_network_state.channelidentifiers_to_channels.get(channel_id)

    if channel_state:
        result = channel.state_transition(
            channel_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
        events.extend(result.events)

    return TransitionResult(token_network_state, events)


def state_transition(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    if type(state_change) == ActionChannelClose:
        iteration = handle_channel_close(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelNew:
        iteration = handle_channelnew(
            token_network_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelNewBalance:
        iteration = handle_balance(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelClosed:
        iteration = handle_closed(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelSettled:
        iteration = handle_settled(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveRouteNew:
        iteration = handle_newroute(
            token_network_state,
            state_change,
        )
    elif type(state_change) == ActionTransferDirect:
        iteration = handle_action_transfer_direct(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ReceiveTransferDirect:
        iteration = handle_receive_transfer_direct(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    else:
        raise RuntimeError(state_change)

    return iteration
