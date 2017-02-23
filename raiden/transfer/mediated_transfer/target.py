# -*- coding: utf-8 -*-
from raiden.utils import sha3
from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.state import TargetState
from raiden.transfer.state_change import (
    Block,
    ActionRouteChange,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveBalanceProof,
    ReceiveSecretReveal,
)
from raiden.transfer.mediated_transfer.events import (
    ContractSendChannelClose,
    ContractSendWithdraw,
    EventTransferCompleted,
    EventTransferFailed,
    SendSecretRequest,
)
from raiden.transfer.mediated_transfer.mediator import (
    is_safe_to_wait,
)


def events_for_close(from_transfer, from_route, block_number):
    """ Close the from_channel if the unsafe region prior to a on-chain
    withdraw.
    """
    safe_to_wait = is_safe_to_wait(
        from_transfer,
        from_route.reveal_timeout,
        block_number,
    )

    if not safe_to_wait:
        channel_close = ContractSendChannelClose(
            from_route.channel_address,
        )
        return [channel_close]

    return list()


def events_for_withdraw(from_transfer, from_route):
    """ Withdraw on the from_channel if it is closed and the secret is known. """
    channel_open = from_route.state == 'available'

    if not channel_open and from_transfer.secret is not None:
        withdraw = ContractSendWithdraw(
            from_transfer,
            from_route.channel_address,
        )
        return [withdraw]

    return list()


def handle_inittarget(state_change):
    """ Handle a ActionInitTarget state change. """
    from_transfer = state_change.from_transfer
    from_route = state_change.from_route
    block_number = state_change.block_number

    state = TargetState(
        state_change.our_address,
        from_route,
        from_transfer,
        state_change.hashlock,
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
        )

        iteration = Iteration(state, [secret_request])
    else:
        iteration = Iteration(state, list())

    return iteration


def handle_secretreveal(state, state_change):
    """ Validate and handle a ReceiveSecretReveal state change. """
    valid_secret = sha3(state_change.secret) == state.hashlock

    if valid_secret:
        state.from_transfer.secret = state_change.secret
        state.state = 'reveal_secret'
        reveal = ReceiveSecretReveal(
            state.from_transfer.identifier,
            state.from_transfer.secret,
            state.from_route.node_address,
            state.our_address,
        )

        iteration = Iteration(state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = Iteration(state, list())

    return iteration


def handle_balanceproof(state, state_change):
    """ Handle a ReceiveBalanceProof state change. """
    iteration = Iteration(state, list())

    # TODO: byzantine behavior event when the sender doesn't match
    if state_change.sender == state.from_transfer.sender:
        state.state = 'balance_proof'

    return iteration


def handle_block(state, state_change):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    state.block_number = state_change.block_number

    close_events = events_for_close(
        state.from_transfer,
        state.from_route,
        state.block_number,
    )
    iteration = Iteration(state, close_events)

    return iteration


def handle_routechange(state, state_change):
    """ Handle a ActionRouteChange state change. """
    updated_route = state_change.route
    assert updated_route.node_address == state.from_route.node_address

    # the route might be closed by another task
    state.from_route = updated_route
    withdraw_events = events_for_withdraw(
        state.from_transfer,
        state.from_route,
    )

    iteration = Iteration(
        state,
        withdraw_events,
    )

    return iteration


def clear_if_finalized(iteration):
    """ Clear the state if the transfer was either completed or failed. """
    state = iteration.state

    if state.from_transfer.secret is None and state.block_number > state.from_transfer.expiration:
        failed = EventTransferFailed(
            identifier=state.transfer.identifier,
            reason='lock expired',
        )
        iteration = Iteration(None, [failed])

    elif state.state == 'balance_proof':
        completed = EventTransferCompleted(
            state.from_transfer.identifier,
            state.from_transfer.secret,
            state.from_transfer.hashlock,
        )
        iteration = Iteration(None, completed)

    return iteration


def state_transition(state, state_change):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if state is None:
        if isinstance(state_change, ActionInitTarget):
            iteration = handle_inittarget(state_change)

    elif state.secret is None:
        if isinstance(state_change, ReceiveSecretReveal):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

    elif state.secret is not None:
        if isinstance(state_change, ReceiveBalanceProof):
            iteration = handle_balanceproof(state, state_change)

        elif isinstance(state_change, ActionRouteChange):
            iteration = handle_routechange(state, state_change)

        elif isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

    return clear_if_finalized(iteration)
