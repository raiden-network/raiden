from raiden.transfer import channel, views
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.state import CHANNEL_STATE_UNUSABLE
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionTransferDirect,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveUpdateTransfer,
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
    channel_identifier = channel_state.identifier
    our_address = channel_state.our_state.address
    partner_address = channel_state.partner_state.address

    token_network_state.network_graph.network.add_edge(
        our_address,
        partner_address,
    )
    token_network_state.network_graph.channel_identifier_to_participants[
        state_change.channel_identifier
    ] = (our_address, partner_address)

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
    network_graph_state = token_network_state.network_graph

    # it might happen that both partners close at the same time, so the channel might
    # already be deleted
    if state_change.channel_identifier in network_graph_state.channel_identifier_to_participants:
        participant1, participant2 = network_graph_state.channel_identifier_to_participants[
            state_change.channel_identifier
        ]
        token_network_state.network_graph.network.remove_edge(
            participant1,
            participant2,
        )
        del token_network_state.network_graph.channel_identifier_to_participants[
            state_change.channel_identifier
        ]

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


def handle_updated_transfer(
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


def handle_batch_unlock(
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    participant1 = state_change.participant
    participant2 = state_change.partner

    events = list()
    for channel_state in list(token_network_state.channelidentifiers_to_channels.values()):
        are_addresses_valid1 = (
            channel_state.our_state.address == participant1 and
            channel_state.partner_state.address == participant2
        )
        are_addresses_valid2 = (
            channel_state.our_state.address == participant2 and
            channel_state.partner_state.address == participant1
        )
        is_valid_locksroot = True
        is_valid_channel = (
            (are_addresses_valid1 or are_addresses_valid2) and
            is_valid_locksroot
        )

        if is_valid_channel:
            sub_iteration = channel.state_transition(
                channel_state,
                state_change,
                pseudo_random_generator,
                block_number,
            )
            events.extend(sub_iteration.events)

            if sub_iteration.new_state is None:

                token_network_state.partneraddresses_to_channelidentifiers[
                    channel_state.partner_state.address
                ].remove(channel_state.identifier)

                del token_network_state.channelidentifiers_to_channels[
                    channel_state.identifier
                ]

    return TransitionResult(token_network_state, events)


def handle_newroute(token_network_state, state_change):
    events = list()

    token_network_state.network_graph.network.add_edge(
        state_change.participant1,
        state_change.participant2,
    )
    token_network_state.network_graph.channel_identifier_to_participants[
        state_change.channel_identifier
    ] = (state_change.participant1, state_change.participant2)

    return TransitionResult(token_network_state, events)


def handle_closeroute(token_network_state, state_change):
    events = list()

    network_graph_state = token_network_state.network_graph

    # it might happen that both partners close at the same time, so the channel might
    # already be deleted
    if state_change.channel_identifier in network_graph_state.channel_identifier_to_participants:
        participant1, participant2 = network_graph_state.channel_identifier_to_participants[
            state_change.channel_identifier
        ]
        token_network_state.network_graph.network.remove_edge(
            participant1,
            participant2,
        )
        del token_network_state.network_graph.channel_identifier_to_participants[
            state_change.channel_identifier
        ]

    return TransitionResult(token_network_state, events)


def handle_action_transfer_direct(
        payment_network_identifier,
        token_network_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    receiver_address = state_change.receiver_address
    channels = [
        token_network_state.channelidentifiers_to_channels[channel_id]
        for channel_id in token_network_state.partneraddresses_to_channelidentifiers[
            receiver_address
        ]
    ]
    channel_states = views.filter_channels_by_status(
        channels,
        [CHANNEL_STATE_UNUSABLE],
    )
    if channel_states:
        iteration = channel.state_transition(
            channel_states[-1],
            state_change,
            pseudo_random_generator,
            block_number,
        )
        events = iteration.events
    else:
        failure = EventPaymentSentFailed(
            payment_network_identifier,
            state_change.token_network_identifier,
            state_change.identifier,
            receiver_address,
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

    channel_id = state_change.balance_proof.channel_identifier
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

    channel_id = state_change.balance_proof.channel_identifier
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
        payment_network_identifier,
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
    elif type(state_change) == ContractReceiveUpdateTransfer:
        iteration = handle_updated_transfer(
            token_network_state,
            state_change,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        iteration = handle_batch_unlock(
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
    elif type(state_change) == ContractReceiveRouteClosed:
        iteration = handle_closeroute(
            token_network_state,
            state_change,
        )
    elif type(state_change) == ActionTransferDirect:
        iteration = handle_action_transfer_direct(
            payment_network_identifier,
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
