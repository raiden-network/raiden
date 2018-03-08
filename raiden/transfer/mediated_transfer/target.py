# -*- coding: utf-8 -*-
from raiden.utils import sha3
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.mediated_transfer.state import (
    TargetState,
    TargetTransferState,
)
from raiden.transfer.state_change import (
    ActionRouteChange,
    Block,
    ReceiveUnlock,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ActionInitTarget2,
    ReceiveBalanceProof,
    ReceiveSecretReveal,
)
from raiden.transfer.events import (
    EventTransferReceivedSuccess,
)
from raiden.transfer.mediated_transfer.events import (
    ContractSendChannelClose,
    ContractSendWithdraw,
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendRevealSecret,
    SendRevealSecret2,
    SendSecretRequest,
)
from raiden.transfer.mediated_transfer.mediator import (
    is_safe_to_wait,
    is_safe_to_wait2,
)
from raiden.transfer.state import CHANNEL_STATE_OPENED


def events_for_close(state):
    """ Emits the event for closing the netting channel if from_transfer needs
    to be settled on-chain.
    """
    from_transfer = state.from_transfer
    from_route = state.from_route

    safe_to_wait = is_safe_to_wait(
        from_transfer,
        from_route.reveal_timeout,
        state.block_number,
    )
    secret_known = from_transfer.secret is not None

    if not safe_to_wait and secret_known:
        state.state = 'waiting_close'
        channel_close = ContractSendChannelClose(
            from_route.channel_address,
            from_transfer.token,
        )
        return [channel_close]

    return list()


def events_for_close2(target_state, channel_state, block_number):
    """ Emits the event for closing the netting channel if the transfer needs
    to be settled on-chain.
    """
    transfer = target_state.transfer

    safe_to_wait = is_safe_to_wait2(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.hashlock,
    )

    if not safe_to_wait and secret_known:
        target_state.state = 'waiting_close'
        return channel.events_for_close(channel_state, block_number)

    return list()


def events_for_withdraw(from_transfer, from_route):
    """ Withdraws from the from_channel if it is closed and the secret is known. """
    channel_open = from_route.state == CHANNEL_STATE_OPENED

    if not channel_open and from_transfer.secret is not None:
        withdraw = ContractSendWithdraw(
            from_transfer,
            from_route.channel_address,
        )
        return [withdraw]

    return list()


def handle_inittarget(state_change):
    """ Handles an ActionInitTarget state change. """
    from_transfer = state_change.from_transfer
    from_route = state_change.from_route
    block_number = state_change.block_number

    state = TargetState(
        state_change.our_address,
        from_route,
        from_transfer,
        block_number,
    )

    safe_to_wait = is_safe_to_wait(
        from_transfer,
        from_route.reveal_timeout,
        block_number,
    )

    # if there is not enough time to safely withdraw the token on-chain
    # silently let the transfer expire.
    if safe_to_wait:
        secret_request = SendSecretRequest(
            from_transfer.identifier,
            from_transfer.amount,
            from_transfer.hashlock,
            from_transfer.initiator,
        )

        iteration = TransitionResult(state, [secret_request])
    else:
        iteration = TransitionResult(state, list())

    return iteration


def handle_inittarget2(state_change, channel_state, block_number):
    """ Handles an ActionInitTarget state change. """
    transfer = state_change.transfer
    route = state_change.route

    target_state = TargetTransferState(
        route,
        transfer,
    )

    assert channel_state.identifier == transfer.balance_proof.channel_address
    is_valid, _ = channel.handle_receive_mediatedtransfer(
        channel_state,
        transfer,
    )

    safe_to_wait = is_safe_to_wait2(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )

    # if there is not enough time to safely withdraw the token on-chain
    # silently let the transfer expire.
    if is_valid and safe_to_wait:
        secret_request = SendSecretRequest(
            transfer.identifier,
            transfer.lock.amount,
            transfer.lock.hashlock,
            transfer.initiator,
        )

        iteration = TransitionResult(target_state, [secret_request])
    else:
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_secretreveal(state, state_change):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = sha3(state_change.secret) == state.from_transfer.hashlock

    if valid_secret:
        from_transfer = state.from_transfer
        from_route = state.from_route

        state.state = 'reveal_secret'
        from_transfer.secret = state_change.secret
        reveal = SendRevealSecret(
            from_transfer.identifier,
            from_transfer.secret,
            from_transfer.token,
            from_route.node_address,
            state.our_address,
        )

        iteration = TransitionResult(state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(state, list())

    return iteration


def handle_secretreveal2(target_state, state_change, channel_state):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = state_change.hashlock == target_state.transfer.lock.hashlock

    if valid_secret:
        channel.register_secret(
            channel_state,
            state_change.secret,
            state_change.hashlock,
        )

        transfer = target_state.transfer
        route = target_state.route

        target_state.state = 'reveal_secret'
        target_state.secret = state_change.secret
        reveal = SendRevealSecret2(
            transfer.identifier,
            target_state.secret,
            transfer.token,
            route.node_address,
        )

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_balanceproof(state, state_change):
    """ Handles a ReceiveBalanceProof state change. """
    iteration = TransitionResult(state, list())

    # TODO: byzantine behavior event when the sender doesn't match
    if state_change.node_address == state.from_route.node_address:
        state.state = 'balance_proof'

    return iteration


def handle_unlock(target_state, state_change, channel_state):
    """ Handles a ReceiveBalanceProof state change. """
    iteration = TransitionResult(target_state, list())

    if state_change.balance_proof.sender == target_state.route.node_address:
        is_valid, _ = channel.handle_unlock(
            channel_state,
            state_change,
        )

        if is_valid:
            transfer = target_state.transfer
            transfer_success = EventTransferReceivedSuccess(
                transfer.identifier,
                transfer.lock.amount,
                transfer.initiator,
            )

            unlock_success = EventWithdrawSuccess(
                transfer.identifier,
                transfer.lock.hashlock,
            )

            iteration = TransitionResult(None, [transfer_success, unlock_success])

    return iteration


def handle_block(state, state_change):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    state.block_number = max(
        state.block_number,
        state_change.block_number,
    )

    # only emit the close event once
    if state.state != 'waiting_close':
        close_events = events_for_close(state)
    else:
        close_events = list()

    iteration = TransitionResult(state, close_events)

    return iteration


def handle_block2(target_state, channel_state, block_number):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    transfer = target_state.transfer
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.hashlock,
    )

    if not secret_known and block_number > transfer.lock.expiration:
        # XXX: emit the event only once
        failed = EventWithdrawFailed(
            identifier=transfer.identifier,
            hashlock=transfer.lock.hashlock,
            reason='lock expired',
        )
        target_state.state = 'expired'
        events = [failed]

    elif target_state.state != 'waiting_close':  # only emit the close event once
        events = events_for_close2(target_state, channel_state, block_number)
    else:
        events = list()

    iteration = TransitionResult(target_state, events)
    return iteration


def handle_routechange(state, state_change):
    """ Handles an ActionRouteChange state change. """
    updated_route = state_change.route
    assert updated_route.node_address == state.from_route.node_address

    # the route might be closed by another task
    state.from_route = updated_route
    withdraw_events = events_for_withdraw(
        state.from_transfer,
        state.from_route,
    )

    iteration = TransitionResult(
        state,
        withdraw_events,
    )

    return iteration


def clear_if_finalized(iteration):
    """ Clears the state if the transfer was either completed or failed. """
    state = iteration.new_state

    if state is None:
        return iteration

    if state.from_transfer.secret is None and state.block_number > state.from_transfer.expiration:
        failed = EventWithdrawFailed(
            identifier=state.from_transfer.identifier,
            hashlock=state.from_transfer.hashlock,
            reason='lock expired',
        )
        iteration = TransitionResult(None, [failed])

    elif state.state == 'balance_proof':
        transfer_success = EventTransferReceivedSuccess(
            state.from_transfer.identifier,
            state.from_transfer.amount,
            state.from_transfer.initiator,
        )

        unlock_success = EventWithdrawSuccess(
            state.from_transfer.identifier,
            state.from_transfer.hashlock,
        )
        iteration = TransitionResult(None, [transfer_success, unlock_success])

    return iteration


def state_transition(state, state_change):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    iteration = TransitionResult(state, list())

    if state is None:
        if isinstance(state_change, ActionInitTarget):
            iteration = handle_inittarget(state_change)

    elif state.from_transfer.secret is None:
        if isinstance(state_change, ReceiveSecretReveal):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

    elif state.from_transfer.secret is not None:
        if isinstance(state_change, ReceiveBalanceProof):
            iteration = handle_balanceproof(state, state_change)

        elif isinstance(state_change, ActionRouteChange):
            iteration = handle_routechange(state, state_change)

        elif isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

    return clear_if_finalized(iteration)


def state_transition2(target_state, state_change, channel_state, block_number):
    """ State machine for the target node of a mediated transfer. """
    iteration = TransitionResult(target_state, list())

    if isinstance(state_change, ActionInitTarget2):
        iteration = handle_inittarget2(
            state_change,
            channel_state,
            block_number,
        )
    elif isinstance(state_change, Block):
        assert state_change.block_number == block_number

        iteration = handle_block2(
            target_state,
            channel_state,
            state_change.block_number,
        )
    elif isinstance(state_change, ReceiveSecretReveal):
        iteration = handle_secretreveal2(
            target_state,
            state_change,
            channel_state,
        )
    elif isinstance(state_change, ReceiveUnlock):
        iteration = handle_unlock(
            target_state,
            state_change,
            channel_state,
        )

    return iteration
