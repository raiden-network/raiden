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
from raiden.transfer.architecture import (
    SendMessageEvent,
    TransitionResult,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    SendDirectTransfer,
)
from raiden.transfer.state import (
    ChainState,
    PaymentMappingState,
    PaymentNetworkState,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionChannelClose,
    ActionInitChain,
    ActionLeaveAllNetworks,
    ActionNewTokenNetwork,
    ActionTransferDirect,
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveNewPaymentNetwork,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveTransferDirect,
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


def get_networks(chain_state, payment_network_identifier, token_address):
    token_network_state = None
    payment_network_state = chain_state.identifiers_to_paymentnetworks.get(
        payment_network_identifier,
    )

    if payment_network_state:
        token_network_state = payment_network_state.tokenaddresses_to_tokennetworks.get(
            token_address,
        )

    return payment_network_state, token_network_state


def get_token_network_by_token_address(chain_state, payment_network_identifier, token_address):
    _, token_network_state = get_networks(
        chain_state,
        payment_network_identifier,
        token_address,
    )

    return token_network_state


def subdispatch_to_all_channels(chain_state, state_change, block_number):
    events = list()

    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network.tokenaddresses_to_tokennetworks.values():
            for channel_state in token_network_state.channelidentifiers_to_channels.values():
                result = channel.state_transition(
                    channel_state,
                    state_change,
                    chain_state.pseudo_random_generator,
                    block_number,
                )
                events.extend(result.events)

    return TransitionResult(chain_state, events)


def subdispatch_to_all_lockedtransfers(chain_state, state_change):
    events = list()

    for secrethash in chain_state.payment_mapping.secrethashes_to_task.keys():
        result = subdispatch_to_paymenttask(chain_state, state_change, secrethash)
        events.extend(result.events)

    return TransitionResult(chain_state, events)


def subdispatch_to_paymenttask(chain_state, state_change, secrethash):
    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)
    events = list()
    sub_iteration = None

    if sub_task:
        pseudo_random_generator = chain_state.pseudo_random_generator

        if isinstance(sub_task, PaymentMappingState.InitiatorTask):
            token_network_identifier = sub_task.token_network_identifier
            token_network_state = views.get_token_network_by_identifier(
                chain_state,
                token_network_identifier,
            )

            if token_network_state:
                sub_iteration = initiator_manager.state_transition(
                    sub_task.manager_state,
                    state_change,
                    token_network_state.channelidentifiers_to_channels,
                    pseudo_random_generator,
                    block_number,
                )
                events = sub_iteration.events

        elif isinstance(sub_task, PaymentMappingState.MediatorTask):
            token_network_identifier = sub_task.token_network_identifier
            token_network_state = views.get_token_network_by_identifier(
                chain_state,
                token_network_identifier,
            )

            if token_network_state:
                sub_iteration = mediator.state_transition(
                    sub_task.mediator_state,
                    state_change,
                    token_network_state.channelidentifiers_to_channels,
                    pseudo_random_generator,
                    block_number,
                )
                events = sub_iteration.events

        elif isinstance(sub_task, PaymentMappingState.TargetTask):
            token_network_identifier = sub_task.token_network_identifier
            channel_identifier = sub_task.channel_identifier
            token_network_state = views.get_token_network_by_identifier(
                chain_state,
                token_network_identifier,
            )

            channel_state = views.get_channelstate_by_token_network_identifier(
                chain_state,
                token_network_identifier,
                channel_identifier,
            )

            if channel_state:
                sub_iteration = target.state_transition(
                    sub_task.target_state,
                    state_change,
                    channel_state,
                    pseudo_random_generator,
                    block_number,
                )
                events = sub_iteration.events

        if sub_iteration and sub_iteration.new_state is None:
            del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_initiatortask(
        chain_state,
        state_change,
        token_network_identifier,
        secrethash,
):

    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        manager_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.InitiatorTask):
        is_valid_subtask = (
            token_network_identifier == sub_task.token_network_identifier
        )
        manager_state = sub_task.manager_state
    else:
        is_valid_subtask = False

    events = list()
    if is_valid_subtask:
        pseudo_random_generator = chain_state.pseudo_random_generator

        token_network_state = views.get_token_network_by_identifier(
            chain_state,
            token_network_identifier,
        )
        iteration = initiator_manager.state_transition(
            manager_state,
            state_change,
            token_network_state.channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.InitiatorTask(
                token_network_identifier,
                iteration.new_state,
            )
            chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
        elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
            del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_mediatortask(
        chain_state,
        state_change,
        token_network_identifier,
        secrethash,
):

    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        mediator_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.MediatorTask):
        is_valid_subtask = (
            token_network_identifier == sub_task.token_network_identifier
        )
        mediator_state = sub_task.mediator_state
    else:
        is_valid_subtask = False

    events = list()
    if is_valid_subtask:
        token_network_state = views.get_token_network_by_identifier(
            chain_state,
            token_network_identifier,
        )

        pseudo_random_generator = chain_state.pseudo_random_generator
        iteration = mediator.state_transition(
            mediator_state,
            state_change,
            token_network_state.channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.MediatorTask(
                token_network_identifier,
                iteration.new_state,
            )
            chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
        elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
            del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_targettask(
        chain_state,
        state_change,
        token_network_identifier,
        channel_identifier,
        secrethash,
):

    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        target_state = None

    elif sub_task and isinstance(sub_task, PaymentMappingState.TargetTask):
        is_valid_subtask = (
            token_network_identifier == sub_task.token_network_identifier
        )
        target_state = sub_task.target_state
    else:
        is_valid_subtask = False

    events = list()
    channel_state = None
    if is_valid_subtask:
        channel_state = views.get_channelstate_by_token_network_identifier(
            chain_state,
            token_network_identifier,
            channel_identifier,
        )

    if channel_state:
        pseudo_random_generator = chain_state.pseudo_random_generator

        iteration = target.state_transition(
            target_state,
            state_change,
            channel_state,
            pseudo_random_generator,
            block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = PaymentMappingState.TargetTask(
                token_network_identifier,
                channel_identifier,
                iteration.new_state,
            )
            chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
        elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
            del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def maybe_add_tokennetwork(chain_state, payment_network_identifier, token_network_state):
    token_network_identifier = token_network_state.address
    token_address = token_network_state.token_address

    payment_network_state, token_network_state_previous = get_networks(
        chain_state,
        payment_network_identifier,
        token_address,
    )

    if payment_network_state is None:
        payment_network_state = PaymentNetworkState(
            payment_network_identifier,
            [token_network_state],
        )

        ids_to_payments = chain_state.identifiers_to_paymentnetworks
        ids_to_payments[payment_network_identifier] = payment_network_state

    if token_network_state_previous is None:
        ids_to_tokens = payment_network_state.tokenidentifiers_to_tokennetworks
        addrs_to_tokens = payment_network_state.tokenaddresses_to_tokennetworks

        ids_to_tokens[token_network_identifier] = token_network_state
        addrs_to_tokens[token_address] = token_network_state


def sanity_check(iteration):
    assert isinstance(iteration.new_state, ChainState)


def handle_block(chain_state, state_change):
    block_number = state_change.block_number
    chain_state.block_number = block_number

    # Subdispatch Block state change
    channels_result = subdispatch_to_all_channels(
        chain_state,
        state_change,
        block_number,
    )
    transfers_result = subdispatch_to_all_lockedtransfers(
        chain_state,
        state_change,
    )
    events = channels_result.events + transfers_result.events
    return TransitionResult(chain_state, events)


def handle_chain_init(chain_state, state_change):
    chain_state = ChainState(
        state_change.pseudo_random_generator,
        state_change.block_number,
        state_change.chain_id,
    )
    events = list()
    return TransitionResult(chain_state, events)


def handle_token_network_action(chain_state, state_change):
    token_network_state = views.get_token_network_by_identifier(
        chain_state,
        state_change.token_network_identifier,
    )

    events = list()
    if token_network_state:
        pseudo_random_generator = chain_state.pseudo_random_generator
        iteration = token_network.state_transition(
            token_network_state,
            state_change,
            pseudo_random_generator,
            chain_state.block_number,
        )

        if iteration.new_state is None:
            payment_network_state = views.search_payment_network_by_token_network_id(
                chain_state,
                state_change.token_network_identifier,
            )

            del payment_network_state.tokenaddresses_to_tokennetworks[
                token_network_state.token_address
            ]
            del payment_network_state.tokenidentifiers_to_tokennetworks[
                token_network_state.address
            ]

        events = iteration.events

    return TransitionResult(chain_state, events)


def handle_delivered(chain_state, state_change):
    # TODO: improve the complexity of this algorithm
    for queueid, queue in chain_state.queueids_to_queues.items():
        if queueid[1] == 'global':
            remove = []

            for pos, message in enumerate(queue):
                if message.message_identifier == state_change.message_identifier:
                    remove.append(pos)

            for removepos in reversed(remove):
                queue.pop(removepos)

    return TransitionResult(chain_state, [])


def handle_new_token_network(chain_state, state_change):
    token_network_state = state_change.token_network
    payment_network_identifier = state_change.payment_network_identifier

    maybe_add_tokennetwork(
        chain_state,
        payment_network_identifier,
        token_network_state,
    )

    events = list()
    return TransitionResult(chain_state, events)


def handle_node_change_network_state(chain_state, state_change):
    events = list()

    node_address = state_change.node_address
    network_state = state_change.network_state
    chain_state.nodeaddresses_to_networkstates[node_address] = network_state

    return TransitionResult(chain_state, events)


def handle_leave_all_networks(chain_state):
    events = list()

    for payment_network_state in chain_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network_state.tokenaddresses_to_tokennetworks.values():
            for channel_state in token_network_state.partneraddresses_to_channels.values():
                events.extend(channel.events_for_close(
                    channel_state,
                    chain_state.block_number,
                ))

    return TransitionResult(chain_state, events)


def handle_new_payment_network(chain_state, state_change):
    events = list()

    payment_network = state_change.payment_network
    payment_network_identifier = payment_network.address
    if payment_network_identifier not in chain_state.identifiers_to_paymentnetworks:
        chain_state.identifiers_to_paymentnetworks[payment_network_identifier] = payment_network

    return TransitionResult(chain_state, events)


def handle_tokenadded(chain_state, state_change):
    events = list()
    maybe_add_tokennetwork(
        chain_state,
        state_change.payment_network_identifier,
        state_change.token_network,
    )

    return TransitionResult(chain_state, events)


def handle_channel_batch_unlock(
        chain_state: ChainState,
        state_change: ContractReceiveChannelBatchUnlock,
) -> TransitionResult:
    token_network_identifier = state_change.token_network_identifier
    token_network_state = views.get_token_network_by_identifier(
        chain_state,
        token_network_identifier,
    )

    events = []
    if token_network_state:
        payment_network_state = views.get_token_network_registry_by_token_network_identifier(
            chain_state,
            token_network_state.address,
        )

        pseudo_random_generator = chain_state.pseudo_random_generator
        participant1 = state_change.participant
        participant2 = state_change.partner

        for channel_state in token_network_state.channelidentifiers_to_channels.values():
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
                    chain_state.block_number,
                )
                events.extend(sub_iteration.events)

                if sub_iteration.new_state is None:
                    del payment_network_state.tokenaddresses_to_tokennetworks[
                        token_network_state.token_address
                    ]
                    del payment_network_state.tokenidentifiers_to_tokennetworks[
                        token_network_identifier
                    ]

    return TransitionResult(chain_state, events)


def handle_secret_reveal(chain_state, state_change):
    return subdispatch_to_paymenttask(
        chain_state,
        state_change,
        state_change.secrethash,
    )


def handle_init_initiator(chain_state, state_change):
    transfer = state_change.transfer
    secrethash = transfer.secrethash

    return subdispatch_initiatortask(
        chain_state,
        state_change,
        transfer.token_network_identifier,
        secrethash,
    )


def handle_init_mediator(chain_state, state_change):
    transfer = state_change.from_transfer
    secrethash = transfer.lock.secrethash
    token_network_identifier = transfer.balance_proof.token_network_identifier

    return subdispatch_mediatortask(
        chain_state,
        state_change,
        token_network_identifier,
        secrethash,
    )


def handle_init_target(chain_state, state_change):
    transfer = state_change.transfer
    secrethash = transfer.lock.secrethash
    channel_identifier = transfer.balance_proof.channel_address
    token_network_identifier = transfer.balance_proof.token_network_identifier

    return subdispatch_targettask(
        chain_state,
        state_change,
        token_network_identifier,
        channel_identifier,
        secrethash,
    )


def handle_receive_transfer_refund(chain_state, state_change):
    return subdispatch_to_paymenttask(
        chain_state,
        state_change,
        state_change.transfer.lock.secrethash,
    )


def handle_receive_transfer_refund_cancel_route(chain_state, state_change):
    return subdispatch_to_paymenttask(
        chain_state,
        state_change,
        state_change.transfer.lock.secrethash,
    )


def handle_receive_secret_request(chain_state, state_change):
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, secrethash)


def handle_processed(chain_state, state_change):
    # TODO: improve the complexity of this algorithm
    events = list()
    for queue in chain_state.queueids_to_queues.values():
        remove = []

        # TODO: ensure Processed message came from the correct peer
        for pos, message in enumerate(queue):
            if message.message_identifier == state_change.message_identifier:
                if type(message) == SendDirectTransfer:
                    events.append(EventTransferSentSuccess(
                        message.payment_identifier,
                        message.balance_proof.transferred_amount,
                        message.recipient,
                    ))
                remove.append(pos)

        for removepos in reversed(remove):
            queue.pop(removepos)

    return TransitionResult(chain_state, events)


def handle_receive_unlock(chain_state, state_change):
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, secrethash)


def state_transition(chain_state, state_change):
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    if type(state_change) == Block:
        iteration = handle_block(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionInitChain:
        iteration = handle_chain_init(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionNewTokenNetwork:
        iteration = handle_new_token_network(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionChannelClose:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionChangeNodeNetworkState:
        iteration = handle_node_change_network_state(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionTransferDirect:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionLeaveAllNetworks:
        iteration = handle_leave_all_networks(
            chain_state,
        )
    elif type(state_change) == ActionInitInitiator:
        iteration = handle_init_initiator(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionInitMediator:
        iteration = handle_init_mediator(
            chain_state,
            state_change,
        )
    elif type(state_change) == ActionInitTarget:
        iteration = handle_init_target(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveNewPaymentNetwork:
        iteration = handle_new_payment_network(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveNewTokenNetwork:
        iteration = handle_tokenadded(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        iteration = handle_channel_batch_unlock(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelNew:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelClosed:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelNewBalance:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveChannelSettled:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveRouteNew:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        iteration = handle_secret_reveal(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveDelivered:
        iteration = handle_delivered(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveTransferDirect:
        iteration = handle_token_network_action(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveSecretReveal:
        iteration = handle_secret_reveal(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveTransferRefundCancelRoute:
        iteration = handle_receive_transfer_refund_cancel_route(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveTransferRefund:
        iteration = handle_receive_transfer_refund(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveSecretRequest:
        iteration = handle_receive_secret_request(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveProcessed:
        iteration = handle_processed(
            chain_state,
            state_change,
        )
    elif type(state_change) == ReceiveUnlock:
        iteration = handle_receive_unlock(
            chain_state,
            state_change,
        )

    sanity_check(iteration)

    for event in iteration.events:
        if isinstance(event, SendMessageEvent):
            queueid = (event.recipient, event.queue_name)
            queue = chain_state.queueids_to_queues.setdefault(queueid, [])
            queue.append(event)

    return iteration
