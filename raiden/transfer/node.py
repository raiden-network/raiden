from raiden.transfer import channel, token_network, views
from raiden.transfer.architecture import (
    ContractReceiveStateChange,
    ContractSendEvent,
    Event,
    SendMessageEvent,
    StateChange,
    TransitionResult,
)
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import (
    CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
    CanonicalIdentifier,
    QueueIdentifier,
)
from raiden.transfer.mediated_transfer import initiator_manager, mediator, target
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    MediatorTransferState,
    TargetTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionChannelClose,
    ActionChannelUpdateFee,
    ActionChannelWithdraw,
    ActionInitChain,
    ActionNewTokenNetwork,
    ActionUpdateTransportAuthData,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveNewPaymentNetwork,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveUnlock,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    BlockHash,
    BlockNumber,
    ChannelID,
    List,
    Optional,
    PaymentNetworkAddress,
    SecretHash,
    TokenNetworkAddress,
    Union,
)

# All State changes that are subdispatched as token network actions
TokenNetworkStateChange = Union[
    ActionChannelClose,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelNew,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelSettled,
    ContractReceiveRouteNew,
    ContractReceiveRouteClosed,
    ContractReceiveUpdateTransfer,
    ContractReceiveChannelClosed,
    ContractReceiveChannelWithdraw,
]


def get_token_network_by_address(
    chain_state: ChainState, token_network_address: TokenNetworkAddress
) -> Optional[TokenNetworkState]:
    payment_network_address = chain_state.tokennetworkaddresses_to_paymentnetworkaddresses.get(
        token_network_address
    )

    payment_network_state = None
    if payment_network_address:
        payment_network_state = chain_state.identifiers_to_paymentnetworks.get(
            payment_network_address
        )

    token_network_state = None
    if payment_network_state:
        token_network_state = payment_network_state.tokennetworkaddresses_to_tokennetworks.get(
            token_network_address
        )

    return token_network_state


def subdispatch_to_all_channels(
    chain_state: ChainState,
    state_change: StateChange,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult[ChainState]:
    events = list()

    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network.tokennetworkaddresses_to_tokennetworks.values():
            for channel_state in token_network_state.channelidentifiers_to_channels.values():
                result = channel.state_transition(
                    channel_state=channel_state,
                    state_change=state_change,
                    block_number=block_number,
                    block_hash=block_hash,
                    pseudo_random_generator=chain_state.pseudo_random_generator,
                )
                events.extend(result.events)

    return TransitionResult(chain_state, events)


def subdispatch_by_canonical_id(
    chain_state: ChainState, canonical_identifier: CanonicalIdentifier, state_change: StateChange
) -> TransitionResult[ChainState]:
    token_network_state = get_token_network_by_address(
        chain_state, canonical_identifier.token_network_address
    )

    events: List[Event] = list()
    if token_network_state:
        iteration = token_network.state_transition(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=chain_state.block_number,
            block_hash=chain_state.block_hash,
            pseudo_random_generator=chain_state.pseudo_random_generator,
        )
        assert iteration.new_state, "No token network state transition can lead to None"

        events = iteration.events

    return TransitionResult(chain_state, events)


def subdispatch_to_all_lockedtransfers(
    chain_state: ChainState, state_change: StateChange
) -> TransitionResult[ChainState]:
    events = list()

    for secrethash in list(chain_state.payment_mapping.secrethashes_to_task.keys()):
        result = subdispatch_to_paymenttask(chain_state, state_change, secrethash)
        events.extend(result.events)

    return TransitionResult(chain_state, events)


def subdispatch_to_paymenttask(
    chain_state: ChainState, state_change: StateChange, secrethash: SecretHash
) -> TransitionResult[ChainState]:
    block_number = chain_state.block_number
    block_hash = chain_state.block_hash
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)
    events: List[Event] = list()

    if sub_task:
        pseudo_random_generator = chain_state.pseudo_random_generator
        sub_iteration: Union[
            TransitionResult[Optional[InitiatorPaymentState]],
            TransitionResult[Optional[MediatorTransferState]],
            TransitionResult[Optional[TargetTransferState]],
        ]

        if isinstance(sub_task, InitiatorTask):
            token_network_address = sub_task.token_network_address
            token_network_state = get_token_network_by_address(chain_state, token_network_address)

            if token_network_state:
                channel_identifier_map = token_network_state.channelidentifiers_to_channels
                sub_iteration = initiator_manager.state_transition(
                    payment_state=sub_task.manager_state,
                    state_change=state_change,
                    channelidentifiers_to_channels=channel_identifier_map,
                    nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                    pseudo_random_generator=pseudo_random_generator,
                    block_number=block_number,
                )
                events = sub_iteration.events

                if sub_iteration.new_state is None:
                    del chain_state.payment_mapping.secrethashes_to_task[secrethash]

        elif isinstance(sub_task, MediatorTask):
            token_network_address = sub_task.token_network_address
            token_network_state = get_token_network_by_address(chain_state, token_network_address)

            if token_network_state:
                channelids_to_channels = token_network_state.channelidentifiers_to_channels
                sub_iteration = mediator.state_transition(
                    mediator_state=sub_task.mediator_state,
                    state_change=state_change,
                    channelidentifiers_to_channels=channelids_to_channels,
                    nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                    pseudo_random_generator=pseudo_random_generator,
                    block_number=block_number,
                    block_hash=block_hash,
                )
                events = sub_iteration.events

                if sub_iteration.new_state is None:
                    del chain_state.payment_mapping.secrethashes_to_task[secrethash]

        elif isinstance(sub_task, TargetTask):
            token_network_address = sub_task.token_network_address
            channel_identifier = sub_task.channel_identifier

            channel_state = views.get_channelstate_by_canonical_identifier(
                chain_state=chain_state,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=chain_state.chain_id,
                    token_network_address=token_network_address,
                    channel_identifier=channel_identifier,
                ),
            )

            if channel_state:
                sub_iteration = target.state_transition(
                    target_state=sub_task.target_state,
                    state_change=state_change,
                    channel_state=channel_state,
                    pseudo_random_generator=pseudo_random_generator,
                    block_number=block_number,
                )
                events = sub_iteration.events

                if sub_iteration.new_state is None:
                    del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_initiatortask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_address: TokenNetworkAddress,
    secrethash: SecretHash,
) -> TransitionResult[ChainState]:

    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        manager_state = None

    elif sub_task and isinstance(sub_task, InitiatorTask):
        is_valid_subtask = token_network_address == sub_task.token_network_address
        manager_state = sub_task.manager_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    if is_valid_subtask:
        pseudo_random_generator = chain_state.pseudo_random_generator

        token_network_state = get_token_network_by_address(chain_state, token_network_address)

        if token_network_state:
            iteration = initiator_manager.state_transition(
                payment_state=manager_state,
                state_change=state_change,
                channelidentifiers_to_channels=token_network_state.channelidentifiers_to_channels,
                nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
            )
            events = iteration.events

            if iteration.new_state:
                sub_task = InitiatorTask(token_network_address, iteration.new_state)
                if sub_task is not None:
                    chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
            elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
                del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_mediatortask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_address: TokenNetworkAddress,
    secrethash: SecretHash,
) -> TransitionResult[ChainState]:

    block_number = chain_state.block_number
    block_hash = chain_state.block_hash
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        mediator_state = None

    elif sub_task and isinstance(sub_task, MediatorTask):
        is_valid_subtask = token_network_address == sub_task.token_network_address
        mediator_state = sub_task.mediator_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    if is_valid_subtask:
        token_network_state = get_token_network_by_address(chain_state, token_network_address)

        if token_network_state:
            pseudo_random_generator = chain_state.pseudo_random_generator
            iteration = mediator.state_transition(
                mediator_state=mediator_state,
                state_change=state_change,
                channelidentifiers_to_channels=token_network_state.channelidentifiers_to_channels,
                nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
                block_hash=block_hash,
            )
            events = iteration.events

            if iteration.new_state:
                sub_task = MediatorTask(token_network_address, iteration.new_state)
                if sub_task is not None:
                    chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
            elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
                del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def subdispatch_targettask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    secrethash: SecretHash,
) -> TransitionResult[ChainState]:

    block_number = chain_state.block_number
    sub_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)

    if not sub_task:
        is_valid_subtask = True
        target_state = None

    elif sub_task and isinstance(sub_task, TargetTask):
        is_valid_subtask = token_network_address == sub_task.token_network_address
        target_state = sub_task.target_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    channel_state = None
    if is_valid_subtask:
        channel_state = views.get_channelstate_by_canonical_identifier(
            chain_state=chain_state,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_address,
                channel_identifier=channel_identifier,
            ),
        )

    if channel_state:
        pseudo_random_generator = chain_state.pseudo_random_generator

        iteration = target.state_transition(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = TargetTask(channel_state.canonical_identifier, iteration.new_state)
            if sub_task is not None:
                chain_state.payment_mapping.secrethashes_to_task[secrethash] = sub_task
        elif secrethash in chain_state.payment_mapping.secrethashes_to_task:
            del chain_state.payment_mapping.secrethashes_to_task[secrethash]

    return TransitionResult(chain_state, events)


def maybe_add_tokennetwork(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_network_state: TokenNetworkState,
) -> None:
    token_network_address = token_network_state.address
    token_address = token_network_state.token_address

    payment_network_state, token_network_state_previous = views.get_networks(
        chain_state, payment_network_address, token_address
    )

    if payment_network_state is None:
        payment_network_state = PaymentNetworkState(payment_network_address, [token_network_state])

        ids_to_payments = chain_state.identifiers_to_paymentnetworks
        ids_to_payments[payment_network_address] = payment_network_state

    if token_network_state_previous is None:
        ids_to_tokens = payment_network_state.tokennetworkaddresses_to_tokennetworks
        addresses_to_ids = payment_network_state.tokenaddresses_to_tokennetworkaddresses

        ids_to_tokens[token_network_address] = token_network_state
        addresses_to_ids[token_address] = token_network_address

        mapping = chain_state.tokennetworkaddresses_to_paymentnetworkaddresses
        mapping[token_network_address] = payment_network_address


def sanity_check(iteration: TransitionResult[ChainState]) -> None:
    assert isinstance(iteration.new_state, ChainState)


def inplace_delete_message_queue(
    chain_state: ChainState,
    state_change: Union[ReceiveDelivered, ReceiveProcessed, ReceiveWithdrawConfirmation],
    queueid: QueueIdentifier,
) -> None:
    """ Filter messages from queue, if the queue becomes empty, cleanup the queue itself. """
    queue = chain_state.queueids_to_queues.get(queueid)
    if not queue:
        if queueid in chain_state.queueids_to_queues:
            chain_state.queueids_to_queues.pop(queueid)
        return

    inplace_delete_message(message_queue=queue, state_change=state_change)

    if len(queue) == 0:
        del chain_state.queueids_to_queues[queueid]
    else:
        chain_state.queueids_to_queues[queueid] = queue


def inplace_delete_message(
    message_queue: List[SendMessageEvent],
    state_change: Union[ReceiveDelivered, ReceiveProcessed, ReceiveWithdrawConfirmation],
) -> None:
    """ Check if the message exists in queue with ID `queueid` and exclude if found."""
    for message in list(message_queue):
        # A withdraw request is only confirmed by a withdraw confirmation.
        # This is done because Processed is not an indicator that the partner has
        # processed and **accepted** our withdraw request. Receiving
        # `Processed` here would cause the withdraw request to be removed
        # from the queue although the confirmation may have not been sent.
        # This is avoided by waiting for the confirmation before removing
        # the withdraw request.
        if isinstance(message, SendWithdrawRequest):
            if not isinstance(state_change, ReceiveWithdrawConfirmation):
                continue

        message_found = (
            message.message_identifier == state_change.message_identifier
            and message.recipient == state_change.sender
        )
        if message_found:
            message_queue.remove(message)


def handle_block(chain_state: ChainState, state_change: Block) -> TransitionResult[ChainState]:
    block_number = state_change.block_number
    chain_state.block_number = block_number
    chain_state.block_hash = state_change.block_hash

    # Subdispatch Block state change
    channels_result = subdispatch_to_all_channels(
        chain_state=chain_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=chain_state.block_hash,
    )
    transfers_result = subdispatch_to_all_lockedtransfers(chain_state, state_change)
    events = channels_result.events + transfers_result.events
    return TransitionResult(chain_state, events)


def handle_chain_init(
    chain_state: Optional[ChainState], state_change: ActionInitChain
) -> TransitionResult[ChainState]:
    if chain_state is None:
        chain_state = ChainState(
            pseudo_random_generator=state_change.pseudo_random_generator,
            block_number=state_change.block_number,
            block_hash=state_change.block_hash,
            our_address=state_change.our_address,
            chain_id=state_change.chain_id,
        )
    events: List[Event] = list()
    return TransitionResult(chain_state, events)


def handle_token_network_action(
    chain_state: ChainState, state_change: TokenNetworkStateChange
) -> TransitionResult[ChainState]:
    token_network_state = get_token_network_by_address(
        chain_state, state_change.token_network_address
    )

    events: List[Event] = list()
    if token_network_state:
        iteration = token_network.state_transition(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=chain_state.block_number,
            block_hash=chain_state.block_hash,
            pseudo_random_generator=chain_state.pseudo_random_generator,
        )
        assert iteration.new_state, "No token network state transition leads to None"

        events = iteration.events

    return TransitionResult(chain_state, events)


def handle_contract_receive_channel_closed(
    chain_state: ChainState, state_change: ContractReceiveChannelClosed
) -> TransitionResult[ChainState]:
    # cleanup queue for channel
    canonical_identifier = CanonicalIdentifier(
        chain_identifier=chain_state.chain_id,
        token_network_address=state_change.token_network_address,
        channel_identifier=state_change.channel_identifier,
    )
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )
    if channel_state:
        queue_id = QueueIdentifier(
            recipient=channel_state.partner_state.address,
            canonical_identifier=canonical_identifier,
        )
        if queue_id in chain_state.queueids_to_queues:
            chain_state.queueids_to_queues.pop(queue_id)

    return handle_token_network_action(chain_state=chain_state, state_change=state_change)


def handle_delivered(
    chain_state: ChainState, state_change: ReceiveDelivered
) -> TransitionResult[ChainState]:
    """ Check if the "Delivered" message exists in the global queue and delete if found."""
    queueid = QueueIdentifier(state_change.sender, CANONICAL_IDENTIFIER_GLOBAL_QUEUE)
    inplace_delete_message_queue(chain_state, state_change, queueid)
    return TransitionResult(chain_state, [])


def handle_new_token_network(
    chain_state: ChainState, state_change: ActionNewTokenNetwork
) -> TransitionResult[ChainState]:
    token_network_state = state_change.token_network
    payment_network_address = state_change.payment_network_address

    maybe_add_tokennetwork(chain_state, payment_network_address, token_network_state)

    events: List[Event] = list()
    return TransitionResult(chain_state, events)


def handle_node_change_network_state(
    chain_state: ChainState, state_change: ActionChangeNodeNetworkState
) -> TransitionResult[ChainState]:
    events: List[Event] = list()

    node_address = state_change.node_address
    network_state = state_change.network_state
    chain_state.nodeaddresses_to_networkstates[node_address] = network_state

    for secrethash, subtask in list(chain_state.payment_mapping.secrethashes_to_task.items()):
        # This assert would not have been needed if token_network_address, a common attribute
        # for all TransferTasks was part of the TransferTasks superclass.
        assert isinstance(subtask, (InitiatorTask, MediatorTask, TargetTask))
        result = subdispatch_mediatortask(
            chain_state=chain_state,
            state_change=state_change,
            token_network_address=subtask.token_network_address,
            secrethash=secrethash,
        )
        events.extend(result.events)

    return TransitionResult(chain_state, events)


def handle_new_payment_network(
    chain_state: ChainState, state_change: ContractReceiveNewPaymentNetwork
) -> TransitionResult[ChainState]:
    events: List[Event] = list()

    payment_network = state_change.payment_network
    payment_network_address = PaymentNetworkAddress(payment_network.address)
    if payment_network_address not in chain_state.identifiers_to_paymentnetworks:
        chain_state.identifiers_to_paymentnetworks[payment_network_address] = payment_network

    return TransitionResult(chain_state, events)


def handle_tokenadded(
    chain_state: ChainState, state_change: ContractReceiveNewTokenNetwork
) -> TransitionResult[ChainState]:
    events: List[Event] = list()
    maybe_add_tokennetwork(
        chain_state, state_change.payment_network_address, state_change.token_network
    )

    return TransitionResult(chain_state, events)


def handle_secret_reveal(
    chain_state: ChainState, state_change: ReceiveSecretReveal
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.secrethash)


def handle_contract_secret_reveal(
    chain_state: ChainState, state_change: ContractReceiveSecretReveal
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.secrethash)


def handle_init_initiator(
    chain_state: ChainState, state_change: ActionInitInitiator
) -> TransitionResult[ChainState]:
    transfer = state_change.transfer
    secrethash = transfer.secrethash

    return subdispatch_initiatortask(
        chain_state, state_change, transfer.token_network_address, secrethash
    )


def handle_init_mediator(
    chain_state: ChainState, state_change: ActionInitMediator
) -> TransitionResult[ChainState]:
    transfer = state_change.from_transfer
    secrethash = transfer.lock.secrethash
    token_network_address = transfer.balance_proof.token_network_address

    return subdispatch_mediatortask(chain_state, state_change, token_network_address, secrethash)


def handle_init_target(
    chain_state: ChainState, state_change: ActionInitTarget
) -> TransitionResult[ChainState]:
    transfer = state_change.transfer
    secrethash = transfer.lock.secrethash
    channel_identifier = transfer.balance_proof.channel_identifier
    token_network_address = transfer.balance_proof.token_network_address

    return subdispatch_targettask(
        chain_state, state_change, token_network_address, channel_identifier, secrethash
    )


def handle_receive_withdraw_request(
    chain_state: ChainState, state_change: ReceiveWithdrawRequest
) -> TransitionResult[ChainState]:
    return subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=state_change.canonical_identifier,
        state_change=state_change,
    )


def handle_receive_withdraw(
    chain_state: ChainState, state_change: ReceiveWithdrawConfirmation
) -> TransitionResult[ChainState]:
    iteration = subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=state_change.canonical_identifier,
        state_change=state_change,
    )
    # Clean up any pending SendWithdrawRequest messages
    for queueid in list(chain_state.queueids_to_queues.keys()):
        inplace_delete_message_queue(chain_state, state_change, queueid)

    return iteration


def handle_receive_withdraw_expired(
    chain_state: ChainState, state_change: ReceiveWithdrawExpired
) -> TransitionResult[ChainState]:
    return subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=state_change.canonical_identifier,
        state_change=state_change,
    )


def handle_receive_lock_expired(
    chain_state: ChainState, state_change: ReceiveLockExpired
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.secrethash)


def handle_receive_transfer_refund(
    chain_state: ChainState, state_change: ReceiveTransferRefund
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(
        chain_state, state_change, state_change.transfer.lock.secrethash
    )


def handle_receive_transfer_refund_cancel_route(
    chain_state: ChainState, state_change: ReceiveTransferRefundCancelRoute
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(
        chain_state, state_change, state_change.transfer.lock.secrethash
    )


def handle_receive_secret_request(
    chain_state: ChainState, state_change: ReceiveSecretRequest
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, secrethash)


def handle_processed(
    chain_state: ChainState, state_change: ReceiveProcessed
) -> TransitionResult[ChainState]:
    events: List[Event] = list()
    # Clean up message queue
    for queueid in list(chain_state.queueids_to_queues.keys()):
        inplace_delete_message_queue(chain_state, state_change, queueid)

    return TransitionResult(chain_state, events)


def handle_receive_unlock(
    chain_state: ChainState, state_change: ReceiveUnlock
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, secrethash)


def handle_update_transport_authdata(
    chain_state: ChainState, state_change: ActionUpdateTransportAuthData
) -> TransitionResult[ChainState]:
    assert chain_state is not None, "chain_state must be set"
    chain_state.last_transport_authdata = state_change.auth_data
    return TransitionResult(chain_state, list())


def handle_state_change(
    chain_state: Optional[ChainState], state_change: StateChange
) -> TransitionResult[ChainState]:  # pragma: no cover

    if chain_state is None:
        msg = "The first iteration must be ActionInitChain"
        assert isinstance(state_change, ActionInitChain), msg
        iteration = handle_chain_init(chain_state, state_change)
    else:
        if type(state_change) == Block:
            assert isinstance(state_change, Block), MYPY_ANNOTATION
            iteration = handle_block(chain_state, state_change)
        elif type(state_change) == ActionNewTokenNetwork:
            assert isinstance(state_change, ActionNewTokenNetwork), MYPY_ANNOTATION
            iteration = handle_new_token_network(chain_state, state_change)
        elif type(state_change) == ActionChannelClose:
            assert isinstance(state_change, ActionChannelClose), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ActionChannelUpdateFee:
            assert isinstance(state_change, ActionChannelUpdateFee), MYPY_ANNOTATION
            iteration = subdispatch_by_canonical_id(
                chain_state=chain_state,
                canonical_identifier=state_change.canonical_identifier,
                state_change=state_change,
            )
        elif type(state_change) == ActionChannelWithdraw:
            assert isinstance(state_change, ActionChannelWithdraw), MYPY_ANNOTATION
            iteration = subdispatch_by_canonical_id(
                chain_state=chain_state,
                canonical_identifier=state_change.canonical_identifier,
                state_change=state_change,
            )
        elif type(state_change) == ActionChangeNodeNetworkState:
            assert isinstance(state_change, ActionChangeNodeNetworkState), MYPY_ANNOTATION
            iteration = handle_node_change_network_state(chain_state, state_change)
        elif type(state_change) == ActionInitInitiator:
            assert isinstance(state_change, ActionInitInitiator), MYPY_ANNOTATION
            iteration = handle_init_initiator(chain_state, state_change)
        elif type(state_change) == ActionInitMediator:
            assert isinstance(state_change, ActionInitMediator), MYPY_ANNOTATION
            iteration = handle_init_mediator(chain_state, state_change)
        elif type(state_change) == ActionInitTarget:
            assert isinstance(state_change, ActionInitTarget), MYPY_ANNOTATION
            iteration = handle_init_target(chain_state, state_change)
        elif type(state_change) == ActionUpdateTransportAuthData:
            assert isinstance(state_change, ActionUpdateTransportAuthData), MYPY_ANNOTATION
            iteration = handle_update_transport_authdata(chain_state, state_change)
        elif type(state_change) == ContractReceiveNewPaymentNetwork:
            assert isinstance(state_change, ContractReceiveNewPaymentNetwork), MYPY_ANNOTATION
            iteration = handle_new_payment_network(chain_state, state_change)
        elif type(state_change) == ContractReceiveNewTokenNetwork:
            assert isinstance(state_change, ContractReceiveNewTokenNetwork), MYPY_ANNOTATION
            iteration = handle_tokenadded(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelBatchUnlock:
            assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelNew:
            assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelWithdraw:
            assert isinstance(state_change, ContractReceiveChannelWithdraw), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelClosed:
            assert isinstance(state_change, ContractReceiveChannelClosed), MYPY_ANNOTATION
            iteration = handle_contract_receive_channel_closed(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelDeposit:
            assert isinstance(state_change, ContractReceiveChannelDeposit), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveChannelSettled:
            assert isinstance(state_change, ContractReceiveChannelSettled), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveRouteNew:
            assert isinstance(state_change, ContractReceiveRouteNew), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveRouteClosed:
            assert isinstance(state_change, ContractReceiveRouteClosed), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ContractReceiveSecretReveal:
            assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
            iteration = handle_contract_secret_reveal(chain_state, state_change)
        elif type(state_change) == ContractReceiveUpdateTransfer:
            assert isinstance(state_change, ContractReceiveUpdateTransfer), MYPY_ANNOTATION
            iteration = handle_token_network_action(chain_state, state_change)
        elif type(state_change) == ReceiveDelivered:
            assert isinstance(state_change, ReceiveDelivered), MYPY_ANNOTATION
            iteration = handle_delivered(chain_state, state_change)
        elif type(state_change) == ReceiveSecretReveal:
            assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
            iteration = handle_secret_reveal(chain_state, state_change)
        elif type(state_change) == ReceiveTransferRefundCancelRoute:
            assert isinstance(state_change, ReceiveTransferRefundCancelRoute), MYPY_ANNOTATION
            iteration = handle_receive_transfer_refund_cancel_route(chain_state, state_change)
        elif type(state_change) == ReceiveTransferRefund:
            assert isinstance(state_change, ReceiveTransferRefund), MYPY_ANNOTATION
            iteration = handle_receive_transfer_refund(chain_state, state_change)
        elif type(state_change) == ReceiveSecretRequest:
            assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
            iteration = handle_receive_secret_request(chain_state, state_change)
        elif type(state_change) == ReceiveProcessed:
            assert isinstance(state_change, ReceiveProcessed), MYPY_ANNOTATION
            iteration = handle_processed(chain_state, state_change)
        elif type(state_change) == ReceiveUnlock:
            assert isinstance(state_change, ReceiveUnlock), MYPY_ANNOTATION
            iteration = handle_receive_unlock(chain_state, state_change)
        elif type(state_change) == ReceiveLockExpired:
            assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
            iteration = handle_receive_lock_expired(chain_state, state_change)
        elif type(state_change) == ReceiveWithdrawRequest:
            assert isinstance(state_change, ReceiveWithdrawRequest), MYPY_ANNOTATION
            iteration = handle_receive_withdraw_request(chain_state, state_change)
        elif type(state_change) == ReceiveWithdrawConfirmation:
            assert isinstance(state_change, ReceiveWithdrawConfirmation), MYPY_ANNOTATION
            iteration = handle_receive_withdraw(chain_state, state_change)
        elif type(state_change) == ReceiveWithdrawExpired:
            assert isinstance(state_change, ReceiveWithdrawExpired), MYPY_ANNOTATION
            iteration = handle_receive_withdraw_expired(chain_state, state_change)

    chain_state = iteration.new_state
    assert chain_state is not None, "chain_state must be set"
    return iteration


def is_transaction_effect_satisfied(
    chain_state: ChainState, transaction: ContractSendEvent, state_change: StateChange
) -> bool:
    """ True if the side-effect of `transaction` is satisfied by
    `state_change`.

    This predicate is used to clear the transaction queue. This should only be
    done once the expected side effect of a transaction is achieved. This
    doesn't necessarily mean that the transaction sent by *this* node was
    mined, but only that *some* transaction which achieves the same side-effect
    was successfully executed and mined. This distinction is important for
    restarts and to reduce the number of state changes.

    On restarts: The state of the on-chain channel could have changed while the
    node was offline. Once the node learns about the change (e.g. the channel
    was settled), new transactions can be dispatched by Raiden as a side effect for the
    on-chain *event* (e.g. do the batch unlock with the latest pending locks),
    but the dispatched transaction could have been completed by another agent (e.g.
    the partner node). For these cases, the transaction from a different
    address which achieves the same side-effect is sufficient, otherwise
    unnecessary transactions would be sent by the node.

    NOTE: The above is not important for transactions sent as a side-effect for
    a new *block*. On restart the node first synchronizes its state by querying
    for new events, only after the off-chain state is up-to-date, a Block state
    change is dispatched. At this point some transactions are not required
    anymore and therefore are not dispatched.

    On the number of state changes: Accepting a transaction from another
    address removes the need for clearing state changes, e.g. when our
    node's close transaction fails but its partner's close transaction
    succeeds.
    """
    # These transactions are not made atomic through the WAL. They are sent
    # exclusively through the external APIs.
    #
    #  - ContractReceiveChannelNew
    #  - ContractReceiveChannelDeposit
    #  - ContractReceiveNewPaymentNetwork
    #  - ContractReceiveNewTokenNetwork
    #  - ContractReceiveRouteNew
    #
    # Note: Deposits and Withdraws must consider a transaction with a higher
    # value as sufficient, because the values are monotonically increasing and
    # the transaction with a lower value will never be executed.

    # Transactions are used to change the on-chain state of a channel. It
    # doesn't matter if the sender of the transaction is the local node or
    # another node authorized to perform the operation. So, for the following
    # transactions, as long as the side-effects are the same, the local
    # transaction can be removed from the queue.
    #
    # - An update transfer can be done by a trusted third party (i.e. monitoring service)
    # - A close transaction can be sent by our partner
    # - A settle transaction can be sent by anyone
    # - A secret reveal can be done by anyone

    # - A lower nonce is not a valid replacement, since that is an older balance
    #   proof
    # - A larger raiden state change nonce is impossible.
    #   That would require the partner node to produce an invalid balance proof,
    #   and this node to accept the invalid balance proof and sign it
    is_valid_update_transfer = (
        isinstance(state_change, ContractReceiveUpdateTransfer)
        and isinstance(transaction, ContractSendChannelUpdateTransfer)
        and state_change.token_network_address == transaction.token_network_address
        and state_change.channel_identifier == transaction.channel_identifier
        and state_change.nonce == transaction.balance_proof.nonce
    )
    if is_valid_update_transfer:
        return True

    # The balance proof data cannot be verified, the local close could have
    # lost a race against a remote close, and the balance proof data would be
    # the one provided by this node's partner
    is_valid_close = (
        isinstance(state_change, ContractReceiveChannelClosed)
        and isinstance(transaction, ContractSendChannelClose)
        and state_change.token_network_address == transaction.token_network_address
        and state_change.channel_identifier == transaction.channel_identifier
    )
    if is_valid_close:
        return True

    is_valid_settle = (
        isinstance(state_change, ContractReceiveChannelSettled)
        and isinstance(transaction, ContractSendChannelSettle)
        and state_change.token_network_address == transaction.token_network_address
        and state_change.channel_identifier == transaction.channel_identifier
    )
    if is_valid_settle:
        return True

    is_valid_secret_reveal = (
        isinstance(state_change, ContractReceiveSecretReveal)
        and isinstance(transaction, ContractSendSecretReveal)
        and state_change.secret == transaction.secret
    )
    if is_valid_secret_reveal:
        return True

    is_batch_unlock = isinstance(state_change, ContractReceiveChannelBatchUnlock) and isinstance(
        transaction, ContractSendChannelBatchUnlock
    )
    if is_batch_unlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        assert isinstance(transaction, ContractSendChannelBatchUnlock), MYPY_ANNOTATION

        our_address = chain_state.our_address

        # Don't assume that because we sent the transaction, we are a
        # participant
        partner_address = None
        if state_change.receiver == our_address:
            partner_address = state_change.sender
        elif state_change.sender == our_address:
            partner_address = state_change.receiver

        # Use the second address as the partner address, but check that a
        # channel exists for our_address and partner_address
        if partner_address:
            channel_state = views.get_channelstate_by_token_network_and_partner(
                chain_state, state_change.token_network_address, partner_address
            )
            # If the channel was cleared, that means that both
            # sides of the channel were successfully unlocked.
            # In this case, we clear the batch unlock
            # transaction from the queue only in case there
            # were no more locked funds to unlock.
            if channel_state is None:
                return True

    return False


def is_transaction_invalidated(transaction: ContractSendEvent, state_change: StateChange) -> bool:
    """ True if the `transaction` is made invalid by `state_change`.

    Some transactions will fail due to race conditions. The races are:

    - Another transaction which has the same side effect is executed before.
    - Another transaction which *invalidates* the state of the smart contract
    required by the local transaction is executed before it.

    The first case is handled by the predicate `is_transaction_effect_satisfied`,
    where a transaction from a different source which does the same thing is
    considered. This predicate handles the second scenario.

    A transaction can **only** invalidate another iff both share a valid
    initial state but a different end state.

    Valid example:

        A close can invalidate a deposit, because both a close and a deposit
        can be executed from an opened state (same initial state), but a close
        transaction will transition the channel to a closed state which doesn't
        allow for deposits (different end state).

    Invalid example:

        A settle transaction cannot invalidate a deposit because a settle is
        only allowed for the closed state and deposits are only allowed for
        the open state. In such a case a deposit should never have been sent.
        The deposit transaction for an invalid state is a bug and not a
        transaction which was invalidated.
    """
    # Most transactions cannot be invalidated by others. These are:
    #
    # - close transactions
    # - settle transactions
    # - batch unlocks
    #
    # Deposits and withdraws are invalidated by the close, but these are not
    # made atomic through the WAL.

    is_our_failed_update_transfer = (
        isinstance(state_change, ContractReceiveChannelSettled)
        and isinstance(transaction, ContractSendChannelUpdateTransfer)
        and state_change.token_network_address == transaction.token_network_address
        and state_change.channel_identifier == transaction.channel_identifier
    )
    if is_our_failed_update_transfer:
        return True

    return False


def is_transaction_expired(transaction: ContractSendEvent, block_number: BlockNumber) -> bool:
    """ True if transaction cannot be mined because it has expired.

    Some transactions are time dependent, e.g. the secret registration must be
    done before the lock expiration, and the update transfer must be done
    before the settlement window is over. If the current block is higher than
    any of these expirations blocks, the transaction is expired and cannot be
    successfully executed.
    """

    is_update_expired = (
        isinstance(transaction, ContractSendChannelUpdateTransfer)
        and transaction.expiration < block_number
    )
    if is_update_expired:
        return True

    is_secret_register_expired = (
        isinstance(transaction, ContractSendSecretReveal) and transaction.expiration < block_number
    )
    if is_secret_register_expired:
        return True

    return False


def is_transaction_pending(
    chain_state: ChainState, transaction: ContractSendEvent, state_change: StateChange
) -> bool:
    return not (
        is_transaction_effect_satisfied(chain_state, transaction, state_change)
        or is_transaction_invalidated(transaction, state_change)
        or is_transaction_expired(transaction, chain_state.block_number)
    )


def update_queues(iteration: TransitionResult[ChainState], state_change: StateChange) -> None:
    chain_state = iteration.new_state
    assert chain_state is not None, "chain_state must be set"

    if isinstance(state_change, ContractReceiveStateChange):
        pending_transactions = [
            transaction
            for transaction in chain_state.pending_transactions
            if is_transaction_pending(chain_state, transaction, state_change)
        ]
        chain_state.pending_transactions = pending_transactions

    for event in iteration.events:
        if isinstance(event, SendMessageEvent):
            queue = chain_state.queueids_to_queues.setdefault(event.queue_identifier, [])
            queue.append(event)

        if isinstance(event, ContractSendEvent):
            chain_state.pending_transactions.append(event)


def state_transition(
    chain_state: Optional[ChainState], state_change: StateChange
) -> TransitionResult[ChainState]:
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    iteration = handle_state_change(chain_state, state_change)

    update_queues(iteration, state_change)
    sanity_check(iteration)

    return iteration
