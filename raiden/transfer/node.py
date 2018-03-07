# -*- coding: utf-8 -*-
from raiden.transfer import (
    channel,
    token_network,
    views,
)
from raiden.transfer.mediated_transfer import (
    initiator_manager,
    mediator,
    target,
)
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.state import (
    NodeState,
    PaymentMappingState,
    PaymentNetworkState,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionForTokenNetwork,
    ActionInitNode,
    ActionLeaveAllNetworks,
    ActionNewTokenNetwork,
    Block,
    ContractReceiveChannelWithdraw,
    ContractReceiveNewPaymentNetwork,
    ContractReceiveNewTokenNetwork,
    ReceiveUnlock,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)


def get_networks(node_state, payment_network_identifier, token_network_identifier):
    token_network_state = None
    payment_network_state = node_state.identifiers_to_paymentnetworks.get(
        payment_network_identifier
    )

    if payment_network_state:
        token_network_state = payment_network_state.tokenaddresses_to_tokennetworks.get(
            token_network_identifier
        )

    return payment_network_state, token_network_state


def get_token_network(node_state, payment_network_identifier, token_network_identifier):
    _, token_network_state = get_networks(
        node_state,
        payment_network_identifier,
        token_network_identifier,
    )

    return token_network_state


def subdispatch_to_all_channels(node_state, state_change, block_number):
    events = list()

    for payment_network in node_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network.tokenaddresses_to_tokennetworks.values():
            for channel_state in token_network_state.channelidentifiers_to_channels.values():
                result = channel.state_transition(channel_state, state_change, block_number)
                events.extend(result.events)

    return TransitionResult(node_state, events)


def subdispatch_to_all_mediatedtransfers(node_state, state_change):
    events = list()

    for hashlock in node_state.payment_mapping.hashlocks_to_task.keys():
        result = subdispatch_to_paymenttask(node_state, state_change, hashlock)
        events.extend(result.events)

    return TransitionResult(node_state, events)


def subdispatch_to_paymenttask(node_state, state_change, hashlock):
    block_number = node_state.block_number
    sub_task = node_state.payment_mapping.hashlocks_to_task.get(hashlock)
    events = list()

    if sub_task:
        if isinstance(sub_task, PaymentMappingState.InitiatorTask):
            payment_network_identifier = sub_task.payment_network_identifier
            token_network_identifier = sub_task.token_network_identifier

            token_network_state = get_token_network(
                node_state,
                payment_network_identifier,
                token_network_identifier,
            )

            if token_network_state:
                sub_iteration = initiator_manager.state_transition(
                    sub_task.manager_state,
                    state_change,
                    token_network_state.channelidentifiers_to_channels,
                    block_number,
                )
                events = sub_iteration.events

        elif isinstance(sub_task, PaymentMappingState.MediatorTask):
            payment_network_identifier = sub_task.payment_network_identifier
            token_network_identifier = sub_task.token_network_identifier

            token_network_state = get_token_network(
                node_state,
                payment_network_identifier,
                token_network_identifier,
            )

            if token_network_state:
                sub_iteration = mediator.state_transition2(
                    sub_task.mediator_state,
                    state_change,
                    token_network_state.channelidentifiers_to_channels,
                    block_number,
                )
                events = sub_iteration.events

        elif isinstance(sub_task, PaymentMappingState.TargetTask):
            payment_network_identifier = sub_task.payment_network_identifier
            token_network_identifier = sub_task.token_network_identifier
            channel_identifier = sub_task.channel_identifier

            channel_state = views.get_channelstate_by_tokenaddress(
                node_state,
                payment_network_identifier,
                token_network_identifier,
                channel_identifier,
            )

            if channel_state:
                sub_iteration = target.state_transition2(
                    sub_task.target_state,
                    state_change,
                    channel_state,
                    block_number,
                )
                events = sub_iteration.events

    return TransitionResult(node_state, events)


def subdispatch_initiatortask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        hashlock):

    block_number = node_state.block_number
    sub_task = node_state.payment_mapping.hashlocks_to_task.get(hashlock)

    if not sub_task:
        is_valid_subtask = True
        manager_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.InitiatorTask):
        is_valid_subtask = (
            payment_network_identifier == sub_task.payment_network_identifier and
            token_network_identifier == sub_task.token_network_identifier
        )
        manager_state = sub_task.manager_state
    else:
        is_valid_subtask = False

    events = list()
    if is_valid_subtask:
        token_network_state = get_token_network(
            node_state,
            payment_network_identifier,
            token_network_identifier,
        )
        iteration = initiator_manager.state_transition(
            manager_state,
            state_change,
            token_network_state.channelidentifiers_to_channels,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.InitiatorTask(
                payment_network_identifier,
                token_network_identifier,
                iteration.new_state,
            )
            node_state.payment_mapping.hashlocks_to_task[hashlock] = sub_task

    return TransitionResult(node_state, events)


def subdispatch_mediatortask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        hashlock):

    block_number = node_state.block_number
    sub_task = node_state.payment_mapping.hashlocks_to_task.get(hashlock)

    if not sub_task:
        is_valid_subtask = True
        mediator_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.MediatorTask):
        is_valid_subtask = (
            payment_network_identifier == sub_task.payment_network_identifier and
            token_network_identifier == sub_task.token_network_identifier
        )
        mediator_state = sub_task.mediator_state
    else:
        is_valid_subtask = False

    events = list()
    if is_valid_subtask:
        token_network_state = get_token_network(
            node_state,
            payment_network_identifier,
            token_network_identifier,
        )
        iteration = mediator.state_transition2(
            mediator_state,
            state_change,
            token_network_state.channelidentifiers_to_channels,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.MediatorTask(
                payment_network_identifier,
                token_network_identifier,
                iteration.new_state,
            )
            node_state.payment_mapping.hashlocks_to_task[hashlock] = sub_task

    return TransitionResult(node_state, events)


def subdispatch_targettask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        channel_identifier,
        hashlock):

    block_number = node_state.block_number
    sub_task = node_state.payment_mapping.hashlocks_to_task.get(hashlock)

    if not sub_task:
        is_valid_subtask = True
        target_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.TargetTask):
        is_valid_subtask = (
            payment_network_identifier == sub_task.payment_network_identifier and
            token_network_identifier == sub_task.token_network_identifier
        )
        target_state = sub_task.target_state
    else:
        is_valid_subtask = False

    events = list()
    channel_state = None
    if is_valid_subtask:
        channel_state = views.get_channelstate_by_tokenaddress(
            node_state,
            payment_network_identifier,
            token_network_identifier,
            channel_identifier,
        )

    if channel_state:
        iteration = target.state_transition2(
            target_state,
            state_change,
            channel_state,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.TargetTask(
                payment_network_identifier,
                token_network_identifier,
                channel_identifier,
                iteration.new_state,
            )
            node_state.payment_mapping.hashlocks_to_task[hashlock] = sub_task

    return TransitionResult(node_state, events)


def maybe_add_tokennetwork(node_state, payment_network_identifier, token_network_state):
    token_network_identifier = token_network_state.address
    token_address = token_network_state.token_address

    payment_network_state, token_network_state_previous = get_networks(
        node_state,
        payment_network_identifier,
        token_network_identifier,
    )

    if payment_network_state is None:
        payment_network_state = PaymentNetworkState(
            payment_network_identifier,
            [token_network_state],
        )

        ids_to_payments = node_state.identifiers_to_paymentnetworks
        ids_to_payments[payment_network_identifier] = payment_network_state

    elif token_network_state_previous is None:
        ids_to_tokens = payment_network_state.tokenidentifiers_to_tokennetworks
        addrs_to_tokens = payment_network_state.tokenaddresses_to_tokennetworks

        ids_to_tokens[token_network_identifier] = token_network_state
        addrs_to_tokens[token_address] = token_network_state


def sanity_check(iteration):
    assert isinstance(iteration.new_state, NodeState)


def handle_block(node_state, state_change):
    block_number = state_change.block_number
    node_state.block_number = block_number

    # Subdispatch Block state change
    channels_result = subdispatch_to_all_channels(
        node_state,
        state_change,
        block_number,
    )
    transfers_result = subdispatch_to_all_mediatedtransfers(
        node_state,
        state_change,
    )
    events = channels_result.events + transfers_result.events
    return TransitionResult(node_state, events)


def handle_node_init(node_state, state_change):
    node_state = NodeState(state_change.block_number)
    events = list()
    return TransitionResult(node_state, events)


def handle_token_network_action(node_state, state_change):
    token_network_identifier = state_change.token_network_identifier
    payment_network_state, token_network_state = get_networks(
        node_state,
        state_change.payment_network_identifier,
        token_network_identifier,
    )

    events = list()
    if token_network_state:
        iteration = token_network.state_transition(
            token_network_state,
            state_change.sub_state_change,
            node_state.block_number,
        )

        if iteration.new_state is None:
            del payment_network_state.tokenaddresses_to_tokennetworks[token_network_identifier]

        events = iteration.events

    return TransitionResult(node_state, events)


def handle_new_token_network(node_state, state_change):
    events = list()

    token_network_state = state_change.token_network
    payment_network_identifier = state_change.payment_network_identifier
    payment_network = node_state.identifiers_to_paymentnetworks.get(payment_network_identifier)

    if payment_network is not None:
        tokens_to_networks = payment_network.tokenidentifiers_to_tokennetworks
        tokens_to_networks[token_network_state.address] = token_network_state

    # TODO: add ContractSend
    return TransitionResult(node_state, events)


def handle_node_change_network_state(node_state, state_change):
    events = list()

    node_address = state_change.node_address
    network_state = state_change.network_state
    node_state.nodeaddresses_to_networkstates[node_address] = network_state

    return TransitionResult(node_state, events)


def handle_leave_all_networks(node_state):
    events = list()

    for payment_network_state in node_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network_state.tokenaddresses_to_tokennetworks.values():
            for channel_state in token_network_state.partneraddresses_to_channels.values():
                events.extend(channel.events_for_close(
                    channel_state,
                    node_state.block_number,
                ))

    return TransitionResult(node_state, events)


def handle_new_payment_network(node_state, state_change):
    events = list()

    payment_network = state_change.payment_network
    payment_network_identifier = payment_network.address
    if payment_network_identifier not in node_state.identifiers_to_paymentnetworks:
        node_state.identifiers_to_paymentnetworks[payment_network_identifier] = payment_network

    return TransitionResult(node_state, events)


def handle_tokenadded(node_state, state_change):
    events = list()
    maybe_add_tokennetwork(
        node_state,
        state_change.payment_network_identifier,
        state_change.token_network,
    )

    return TransitionResult(node_state, events)


def handle_channel_withdraw(node_state, state_change):
    token_network_identifier = state_change.token_network_identifier
    payment_network_state, token_network_state = get_networks(
        node_state,
        state_change.payment_network_identifier,
        state_change.token_network_identifier,
    )

    # first dispatch the withdraw to update the channel
    events = []
    if token_network_state:
        sub_iteration = token_network.subdispatch_to_channel_by_id(
            token_network_state,
            state_change,
            node_state.block_number,
        )
        events.extend(sub_iteration.events)

        if sub_iteration.new_state is None:
            del payment_network_state.tokenaddresses_to_tokennetworks[token_network_identifier]

    # second emulate a secret reveal, to register the secret with all the other
    # channels and proceed with the protocol
    state_change = ReceiveSecretReveal(state_change.secret, None)
    sub_iteration_secret_reveal = handle_secret_reveal(
        node_state,
        state_change,
    )
    events.extend(sub_iteration_secret_reveal.events)

    return TransitionResult(node_state, events)


def handle_secret_reveal(node_state, state_change):
    return subdispatch_to_paymenttask(
        node_state,
        state_change,
        state_change.hashlock
    )


def handle_init_initiator(node_state, state_change):
    transfer = state_change.transfer
    hashlock = transfer.hashlock
    payment_network_identifier = state_change.payment_network_identifier
    token_network_identifier = transfer.token

    return subdispatch_initiatortask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        hashlock,
    )


def handle_init_mediator(node_state, state_change):
    transfer = state_change.from_transfer
    hashlock = transfer.lock.hashlock
    payment_network_identifier = state_change.payment_network_identifier
    token_network_identifier = transfer.token

    return subdispatch_mediatortask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        hashlock,
    )


def handle_init_target(node_state, state_change):
    transfer = state_change.transfer
    hashlock = transfer.lock.hashlock
    payment_network_identifier = state_change.payment_network_identifier
    token_network_identifier = transfer.token
    channel_identifier = transfer.balance_proof.channel_address

    return subdispatch_targettask(
        node_state,
        state_change,
        payment_network_identifier,
        token_network_identifier,
        channel_identifier,
        hashlock,
    )


def handle_receive_transfer_refund(node_state, state_change):
    return subdispatch_to_paymenttask(
        node_state,
        state_change,
        state_change.transfer.lock.hashlock
    )


def handle_receive_transfer_refund_cancel_route(node_state, state_change):
    return subdispatch_to_paymenttask(
        node_state,
        state_change,
        state_change.transfer.lock.hashlock
    )


def handle_receive_secret_request(node_state, state_change):
    hashlock = state_change.hashlock
    return subdispatch_to_paymenttask(node_state, state_change, hashlock)


def handle_receive_secret_reveal(node_state, state_change):
    hashlock = state_change.hashlock
    return subdispatch_to_paymenttask(node_state, state_change, hashlock)


def handle_receive_unlock(node_state, state_change):
    hashlock = state_change.hashlock
    return subdispatch_to_paymenttask(node_state, state_change, hashlock)


def state_transition(node_state, state_change):
    # pylint: disable=too-many-branches

    if isinstance(state_change, Block):
        iteration = handle_block(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionInitNode):
        iteration = handle_node_init(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionForTokenNetwork):
        iteration = handle_token_network_action(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionNewTokenNetwork):
        iteration = handle_new_token_network(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionChangeNodeNetworkState):
        iteration = handle_node_change_network_state(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionLeaveAllNetworks):
        iteration = handle_leave_all_networks(
            node_state,
        )
    elif isinstance(state_change, ActionInitInitiator):
        iteration = handle_init_initiator(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionInitMediator):
        iteration = handle_init_mediator(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ActionInitTarget):
        iteration = handle_init_target(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ContractReceiveNewPaymentNetwork):
        iteration = handle_new_payment_network(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ContractReceiveNewTokenNetwork):
        iteration = handle_tokenadded(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ContractReceiveChannelWithdraw):
        iteration = handle_channel_withdraw(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveSecretReveal):
        iteration = handle_secret_reveal(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveTransferRefundCancelRoute):
        iteration = handle_receive_transfer_refund_cancel_route(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveTransferRefund):
        iteration = handle_receive_transfer_refund(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveSecretRequest):
        iteration = handle_receive_secret_request(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveSecretReveal):
        iteration = handle_receive_secret_reveal(
            node_state,
            state_change,
        )
    elif isinstance(state_change, ReceiveUnlock):
        iteration = handle_receive_unlock(
            node_state,
            state_change,
        )
    else:
        raise RuntimeError(state_change)

    sanity_check(iteration)

    return iteration
