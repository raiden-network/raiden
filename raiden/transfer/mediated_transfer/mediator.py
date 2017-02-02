# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.mediated_transfer.state import MediatorState
from raiden.transfer.mediated_transfer.state_change import (
    # machine state
    InitMediator,
    # protocol messages
    TransferRefundReceived,
    SecretRevealReceived,
)
from raiden.transfer.state_change import (
    # blockchain events
    Blocknumber,
    RouteChange,
)
from raiden.transfer.mediated_transfer.events import (
    MediatedTransfer,
    RefundTransfer,
    RevealSecretTo,
    TransferFailed,
    TransferCompleted,
    SettleOnChain,
)
from raiden.utils import sha3


def try_next_route(next_state):
    assert next_state.route is None, 'cannot try a new route while one is being used.'
    assert next_state.message is None, 'cannot try a new route while a message is in flight.'

    from_transfer = next_state.from_transfer

    settle_timeout = next_state.from_route.blocks_until_settlement
    lock_timeout = from_transfer.expiration - next_state.block_number
    last_timeout = next_state.last_expiration - next_state.block_number

    # The lock timeout is crucial for safety of the mediate transfer, the value
    # must be choosen so that the next hop is forced to reveal the secret with
    # sufficient time for this node to claim the received transfer from the
    # previous hop.
    #
    # These are the upper limits for the expiration timeout, since the token
    # can not be recover after any of these expirations has passed (each of
    # these values must be decremented of reveal_timeout):
    #
    # - The from_channel.settlement_timeout, since the previous channel can
    #   be closed at any time
    # - If the previous channel is already closed, the number of blocks
    #   until the settlement period is over.
    # - The last received lock expiration, since the smart contract must
    #   not allow unlocking of expired locks.
    #
    # reveal_timeout is a configurable number of blocks that this node uses to
    # to learn the secret from the next hop and call close/unlock on-chain.
    timeout = min(settle_timeout, lock_timeout, last_timeout)

    try_route = None
    while next_state.routes.available_routes:
        route = next_state.routes.available_routes.pop()
        new_lock_timeout = timeout - route.reveal_timeout

        enough_balance = route.available_balance >= from_transfer.amount

        if enough_balance and new_lock_timeout > 0:
            try_route = route
            break
        else:
            next_state.routes.ignored_routes.append(route)

    if try_route is None:
        # No route available, refund the previous hop so that it can try a new
        # route.
        #
        # The refund expiration must be decremented by reveal_timeout.
        #
        # For the paths A-B-C and A-B-D, if C sent a refund to B and the path
        # A-B-D succeeded, B can go on-chain to close the channel and only
        # withdraw the lock at the last block before it expires, if the refund
        # expiration is equal to the original transfer there is not enough time
        # for C to learn the secret and unlock the B-C transfer.

        new_lock_timeout = timeout - next_state.from_route.reveal_timeout

        if new_lock_timeout > 0:
            new_lock_expiration = new_lock_timeout + next_state.block_number

            refund = RefundTransfer(
                from_transfer.identifier,
                from_transfer.token,
                from_transfer.amount,
                from_transfer.hashlock,
                new_lock_expiration,
                next_state.from_route.node_address,
            )

            next_state.sent_refund = refund
            next_state.last_expiration = new_lock_expiration

            iteration = Iteration(next_state, [refund])
        else:
            iteration = Iteration(next_state, list())

    else:
        new_lock_expiration = new_lock_timeout + next_state.block_number

        mediated_transfer = MediatedTransfer(
            from_transfer.identifier,
            from_transfer.token,
            from_transfer.amount,
            from_transfer.hashlock,
            from_transfer.target,
            new_lock_expiration,
            try_route.node_address,
        )

        next_state.message = mediated_transfer
        next_state.last_expiration = new_lock_expiration

        iteration = Iteration(next_state, [mediated_transfer])

    return iteration


def state_transition(next_state, state_change):
    """ State machine for a node mediating a transfer. """
    # Notes:
    # - A user cannot cancel a mediated transfer after it was initiated, she
    #   may only reject to mediated it before hand. This is because the
    #   mediator doesn't control the secret reveal and needs to wait for the
    #   lock expiration before safely discarding the transfer.

    if next_state is None:
        state_uninitialized = True
        state_wait_secret = False
        state_wait_withdraw = False
    else:
        state_uninitialized = False
        state_wait_withdraw = next_state.transfer.secret is not None

        # At this state either:
        # - there is a message in-flight, and we are waiting for the secret
        #   from the next_hop.
        # - all routes failed with a refund and we are waiting either for the
        #   lock to expire or to the secret to be revealed.
        state_wait_secret = not state_wait_withdraw

    iteration = Iteration(next_state, list())

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            block_number = state_change.block_number
            next_state.block_number = block_number

            from_transfer = next_state.from_transfer

            # We may only clear the state after the *received* lock has
            # expired, at this point all the locks sent have also expired.
            if block_number > from_transfer.lock.expiration:
                failed = TransferFailed(
                    state_change.from_transfer.identifier,
                    reason='Lock expired and the secret was not learned.'
                )
                iteration = Iteration(None, [failed])

            # A node may wait for a new balance proof until the block
            # reveal_timeout - 1, after that block it needs to settle on-chain.
            elif next_state.transfer.secret:
                # exploit the order of the transfers_refunded (lowest expiration are at the end)
                if next_state.transfers_refunded:
                    route, refund_transfer = next_state.transfers_refunded[-1]
                    safe_until_block = refund_transfer.expiration - route.reveal_timeout - 1

                    if block_number >= safe_until_block:
                        # move the transfer to the settling list
                        next_state.transfers_refunded.pop()
                        next_state.transfers_settling.append(
                            (route, refund_transfer)
                        )

                        settle_channel = SettleOnChain(
                            refund_transfer,
                            route.channel_address,
                        )
                        iteration = Iteration(state_change, [settle_channel])
                else:
                    safe_until_block = from_transfer.expiration - next_state.route.reveal_timeout - 1

                    if block_number >= safe_until_block:
                        settle_channel = SettleOnChain(
                            from_transfer,
                            next_state.route.channel_address,
                        )
                        iteration = Iteration(state_change, [settle_channel])

        elif isinstance(state_change, RouteChange):
            update_route(next_state, state_change)

    if state_uninitialized:
        if isinstance(state_change, InitMediator):
            routes = state_change.routes
            from_transfer = state_change.from_transfer
            from_route = state_change.from_route

            next_state = MediatorState(
                state_change.our_address,
                from_transfer,
                routes,
                state_change.block_number,
                from_route,
            )

            iteration = try_next_route(next_state)

    elif state_wait_secret:
        valid_reveal_secret = (
            isinstance(state_change, SecretRevealReceived) and
            sha3(state_change.secret) == next_state.transfer.hashlock
        )

        if valid_reveal_secret:
            secret = state_change.secret
            next_state.transfer.secret = secret

            reveal = RevealSecretTo(
                next_state.transfer.identifier,
                secret,
                next_state.from_route.node_address,
                next_state.our_address,
            )

            # reveal the secret unlocking the token from the message sent by
            # this node
            unlocks = [
                RevealSecretTo(
                    transfer.identifier,
                    secret,
                    transfer.node_address,
                    next_state.our_address,
                )
                for _, transfer in next_state.transfers_refunded
            ]

            iteration = Iteration(next_state, [reveal] + unlocks)

        elif next_state.message is not None:
            our_message = next_state.message

            # TODO: Use an event to notify about byzantine behavior if the next
            # hop send a message that doesnt match amount, hashlock, amount, or
            # expiration doesnt decrease
            valid_refund = (
                isinstance(state_change, TransferRefundReceived) and
                our_message.identifier == state_change.message.identifier and
                our_message.amount == state_change.message.amount and
                our_message.hashlock == state_change.message.hashlock and
                our_message.sender == next_state.message.node_address and
                our_message.expiration > state_change.message.expiration
            )

            if valid_refund:
                next_state.routes.refund_routes.append(next_state.route)
                next_state.last_expiration = state_change.message.expiration

                # keep a list of the messages that we are going to receive
                # tokens from
                next_state.transfers_refunded.append(
                    (next_state.route, state_change.message)
                )

                next_state.route = None
                next_state.message = None

                iteration = try_next_route(next_state)

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, SecretRevealReceived)
        )

        if valid_secret:
            if state_change.sender == next_state.from_route.node_address:
                next_state.from_transfer = None
            else:
                remove = None
                for idx, (route, _) in state_change.transfers_refunded:
                    if route.node_address == state_change.sender:
                        remove = idx
                        break

                if remove is not None:
                    state_change.transfers_refunded.pop(remove)

            # wait for the balance proof from all the received transfers
            if next_state.from_transfer is None and len(next_state.transfers_refunded) == 0:
                complete = TransferCompleted(
                    next_state.transfer.identifier,
                    next_state.transfer.secret,
                    next_state.transfer.hashlock,
                )
                iteration = Iteration(None, [complete])

    return iteration
