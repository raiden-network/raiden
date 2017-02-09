# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.mediated_transfer.state import (
    MediatorState,
    MediationPairState,
)
from raiden.transfer.mediated_transfer.state_change import (
    BalanceProofReceived,
    InitMediator,
    NettingChannelWithdraw,
    SecretRevealReceived,
    TransferRefundReceived,
)
from raiden.transfer.state_change import (
    Blocknumber,
    RouteChange,
)
from raiden.transfer.mediated_transfer.events import (
    MediatedTransfer,
    RefundTransfer,
    RevealSecretTo,
    SendBalanceProof,
    WithdrawOnChain,
)
from raiden.utils import sha3

# Reduce the lock expiration by some additional blocks to prevent this exploit:
# The payee could reveal the secret on it's lock expiration block, the lock
# would be valid and the previous lock can be safely unlocked so the mediator
# would follow the secret reveal with a balance-proof, at this point the secret
# is know, the payee transfer is payed, and if the payer expiration is exactly
# reveal_timeout blocks away the mediator will be forced to close the channel
# to be safe.
TRANSIT_BLOCKS = 2  # TODO: make this a configuration variable


STATE_SECRET_KNOWN = (
    'payee_secret_revealed',
    'payee_channel_withdraw',
    'payee_balance_proof',

    'payer_secret_revealed',
    'payer_channel_withdraw',
    'payer_balance_proof',
)
STATE_TRANSFER_PAYED = (
    'payee_channel_withdraw',
    'payee_balance_proof',

    'payer_channel_withdraw',
    'payer_balance_proof',
)
STATE_TRANSFER_FINAL = (
    'payee_channel_withdraw',
    'payee_balance_proof',
    'payee_expired',

    'payer_channel_withdraw',
    'payer_balance_proof',
    'payer_expired',
)


def is_lock_valid(block_number, transfer):
    """ True if the lock has not expired. """
    return transfer.expiration < block_number


def is_safe_to_wait(block_number, transfer, reveal_timeout):
    """ True if there are more than enough blocks to safely settle on chain and
    waiting is safe.
    """
    # A node may wait for a new balance proof while there are reveal_timeout
    # left, after that block it is not safe to wait.
    return block_number >= transfer.expiration - reveal_timeout


def is_valid_refund(original_transfer, refund_transfer):
    """ True if the refund transfer matches the original transfer. """
    # Ignore a refund from the target
    if refund_transfer.node_address == original_transfer.target:
        return False

    return (
        original_transfer.identifier == refund_transfer.identifier and
        original_transfer.amount == refund_transfer.amount and
        original_transfer.hashlock == refund_transfer.hashlock and
        original_transfer.sender == refund_transfer.node_address and

        # A larger-or-equal expiration is byzantine behavior that favors this
        # node, neverthless it's being ignored since the only reason for the
        # other node to use an invalid expiration is to play the protocol.
        original_transfer.expiration > refund_transfer.expiration
    )


def clear_if_finalized(iteration):
    """ Clear the state if all transfer pairs have finalized. """
    state = iteration.state

    all_finalized = all(
        pair.payee_state in STATE_TRANSFER_FINAL and pair.payer_state in STATE_TRANSFER_FINAL
        for pair in state.transfers_pair
    )

    if all_finalized:
        iteration.state = None

    # TODO: how do we define success and failure for a mediator since the state
    # of individual paths may differ?

    return iteration


def get_pending_transfer_pairs(transfers_pair):
    """ Return the transfer pairs that han't reached a final state. """
    pending_pairs = list(
        pair
        for pair in transfers_pair
        if pair.payee_state not in STATE_TRANSFER_FINAL or
        pair.payer_state not in STATE_TRANSFER_FINAL
    )
    return pending_pairs


def set_secret(state, secret):
    """ Set the secret to all mediated transfers.

    It doesnt matter if the secret was learned through the blockchain or a
    secret reveal message.

    Note:
        `state` is changed in place.
    """
    state.secret = secret

    for pair in state.transfers_pair:
        pair.payer_transfer.secret = secret
        pair.payee_transfer.secret = secret


def set_payee_state_and_check_reveal_order(transfers_pair,
                                           payee_address,
                                           new_payee_state):
    """ Set the state of a transfer *sent* to a payee and check the secret is
    being revealed backwards.

    Note:
        the elements from transfers_pair are changed in place, the list must
        contain all the know transfers to properly check reveal order.
    """
    assert new_payee_state in MediationPairState.valid_payee_states

    wrong_reveal_order = False
    for back in reversed(transfers_pair):
        if back.payee_route.node_address == payee_address:
            back.payee_state = new_payee_state
            break

        elif back.payee_state not in STATE_SECRET_KNOWN:
            wrong_reveal_order = True

    if wrong_reveal_order:
        # TODO: append an event for byzantine behavior
        return list()

    return list()


def secret_learned(state, secret, payee_address, new_payee_state):
    """ Set the state of the `payee_address` transfer, check the secret is
    being revealed backwards, and if necessary send out RevealSecret and
    BalanceProof.
    """
    assert new_payee_state in STATE_SECRET_KNOWN

    # TODO: if any of the transfers is in expired state, event for byzantine
    # behavior

    if state.secret is None:
        set_secret(state, secret)

    # change the payee state
    wrong_order = set_payee_state_and_check_reveal_order(
        state.transfers_pair,
        payee_address,
        new_payee_state,
    )

    # reveal the secret backwards
    secret_reveal = event_reveal_secret_backwards(
        state
    )

    # send the balance proof to payee that knows the secret but is not payed
    # yet
    balance_proof = events_for_balance_proof(
        state
    )

    iteration = Iteration(
        state,
        wrong_order + secret_reveal + balance_proof,
    )

    return iteration


def event_reveal_secret_backwards(state):
    """ Reveal the secret backwards.

    This node is named N, suppose there is a mediated transfer with two
    refund transfers, one from B and one from C:

        A-N-B...B-N-C..C-N-D

    Under normal operation this will first learn the secret from D, then
    reveal to C, wait for C to tell us that it knows the secret then reveal
    it to B, and again wait for B before revealing the secret to A.

    If B somehow sent a reveal secret before C and D, then the secret will be
    revealed to A, but not C and D, meaning the secret won't be propagate
    forward.

    If B and D sent a reveal secret at about the same time, the secret will
    only be revealed to B upon confirmation from C. B should not have learnt
    the secret before time but since it knows it may withdraw on-chain, so N
    needs to proceed with the protol backwards to stay even.
    """

    events = list()
    for pair in reversed(state.transfers_pair):
        payee_secret = pair.payee_transfer.state in STATE_SECRET_KNOWN
        payer_secret = pair.payer_transfer.state in STATE_SECRET_KNOWN

        if payee_secret and not payer_secret:
            pair.payer_transfer.state = 'payer_secret_revealed'
            reveal_secret = RevealSecretTo(
                pair.payer_transfer.identifier,
                pair.payer_transfer.secret,
                pair.payer_route.node_address,
                state.our_address,
            )
            events.append(reveal_secret)

    return events


def events_for_balance_proof(state):
    """ Send the balance proof to nodes that know the secret. """

    events = list()
    for pair in reversed(state.transfers_pair):
        payee_secret = pair.payee_transfer.state in STATE_SECRET_KNOWN
        payee_payed = pair.payee_transfer.state in STATE_TRANSFER_PAYED
        lock_valid = is_lock_valid(state.block_number, pair.payee_transfer)

        if payee_secret and not payee_payed and lock_valid:
            pair.payee_transfer.state = 'payee_balance_proof'
            balance_proof = SendBalanceProof(
                pair.payee_transfer.identifier,
                pair.payee_route.node_address,
            )
            events.append(balance_proof)

    return events


def handle_new_block(state):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time locks.

    Args:
        state (MediatorState): The current state.

    Return:
        Iteration: The resulting iteration
    """
    block_number = state.block_number

    events = list()
    pending_transfers_pairs = get_pending_transfer_pairs(state.transfers_pair)

    for pair in reversed(pending_transfers_pairs):
        # Only withdraw on chain if the corresponding payee transfer is payed,
        # this prevents attacks were tokens are burned to force a channel close.
        payee_payed = pair.payee_transfer.state in STATE_TRANSFER_PAYED
        payer_payed = pair.payer_transfer.state in STATE_TRANSFER_PAYED
        witdrawing = pair.payer_state == 'payer_waiting_withdraw'

        if payee_payed and not payer_payed and not witdrawing:
            safe_to_wait = is_safe_to_wait(
                block_number,
                pair.payer_transfer,
                pair.payer_route.reveal_timeout,
            )

            if not safe_to_wait:
                pair.payer_state = 'payer_waiting_withdraw'
                settle_channel = WithdrawOnChain(
                    pair.payer_transfer,
                    pair.payer_route.channel_address,
                )
                events.append(settle_channel)

        if pair.payer_transfer.expiration > block_number:
            assert pair.payee_state not in STATE_TRANSFER_PAYED
            pair.payee_state = 'payee_expired'
            pair.payer_state = 'payer_expired'

    iteration = Iteration(state, events)

    return iteration


def handle_refundtransfer(state, state_change):
    """ Validate and handle a TransferRefundReceived state change.

    Args:
        state (MediatorState): Current state.
        state_change (TransferRefundReceived): The state change.

    Returns:
        Iteration: The resulting iteration.
    """
    assert state.secret is None, 'refunds are not allowed if the secret is revealed'

    # The last sent transfer is the only one thay may be refunded, all the
    # previous ones are refunded already.
    transfer_pair = state.transfers_pair[-1]
    payee_transfer = transfer_pair.payee_transfer

    if is_valid_refund(payee_transfer, state_change.message):
        payee_route = transfer_pair.payee_route

        state.routes.refund_routes.append(state.route)
        state.route = None

        iteration = mediate_transfer(
            state,
            payee_route,
            payee_transfer,
        )

    else:
        # TODO: Use an event to notify about byzantine behavior
        iteration = Iteration(state, list())

    return iteration


def handle_secretreveal(state, state_change):
    """ Validate and handle a SecretRevealReceived state change.

    The Secret must propagate backwards through the chain of mediators, this
    function will record the learned secret, check if the secret is propagating
    backwards (for the known paths), and send the BalanceProof/RevealSecret if
    necessary.
    """
    secret = state_change.secret

    if sha3(secret) == state.hashlock:
        iteration = secret_learned(
            state,
            secret,
            state_change.sender,
            'payee_secret_revealed',
        )

    else:
        # TODO: event for byzantine behavior
        iteration = Iteration(state, list())

    return iteration


def handle_channelwithdraw(state, state_change):
    """ Handle a NettingChannelUnlock state change. """
    assert sha3(state.secret) == state.hashlock, 'the secret must be validated by the smart contract'

    for pair in state.transfers_pair:
        if pair.payer_route.channel_address == state_change.channel_address:
            pair.payer_state = 'payer_channel_withdraw'
            break
    else:
        iteration = secret_learned(
            state,
            state_change.secret,
            state_change.sender,
            'payee_channel_withdraw',
        )

    return iteration


def handle_balanceproof(state, state_change):
    """ Handle a BalanceProofReceived state change. """
    for pair in state.transfers_pair:
        if pair.payer_route.channel_address == state_change.node_address:
            pair.payer_state = 'payer_balance_proof'


def mediate_transfer(state, payer_route, payer_transfer):
    """ Given a mediation payer route tries a new route to proceed with the
    mediation.

    A node might participate in mediated transfer more than once because of
    refund transfers, eg. A-B-C-B-D-T, B tried to mediated the transfer through
    C, which didn't have a available route to proceed and refunds B, at this
    point B is part of the path again and will try a new partner to proceed
    with the mediation through D, D finally reaches the target T.

    In the above scenario B has two pairs of payer and payee transfers:

        payer:A payee:C from the first MediatedTransfer
        payer:C payee:D from the following RefundTransfer

    Args:
        state (MediatorState): The current state of the task.
        payer_route (RouteState): The previous route in the path that provides
            the token for the mediation.
        payer_transfer (LockedTransferState): The transfer received from the
            payer_route.
    """
    assert state.route is None, 'New path allowed only if the previous have a refund'

    # The payee lock timeout is crucial for safety of the mediate transfer, the
    # value must be choosen so that the next hop is forced to reveal the secret
    # with sufficient time for this node to claim the received lock from the
    # previous hop.
    #
    # The lock timeout must be the smallest of:
    #
    # - payer_transfer.expiration: The payer lock expiration, to force the
    #   payee to reveal the secret in due time.
    # - payer_route.blocks_until_settlement: Lock expiration must be lower than
    #   the settlement period since the lock cannot be claimed after the channel
    #   is settled, this might be the settlement_timeout if the payer_route is
    #   not in the close state or the number of blocks left.
    #
    settle_timeout = payer_route.blocks_until_settlement
    lock_timeout = payer_transfer.expiration - state.block_number
    timeout = min(settle_timeout, lock_timeout)

    try_route = None
    from_transfer = state.from_transfer

    while state.routes.available_routes:
        route = state.routes.available_routes.pop()

        # reveal_timeout is the number of blocks to learn the secret from the
        # blockchain (revealed by the next hop when unlocking on chain) and
        # call close+unlock on-chain.
        lock_timeout = timeout - route.reveal_timeout
        lock_timeout -= TRANSIT_BLOCKS

        enough_balance = route.available_balance >= from_transfer.amount

        if enough_balance and lock_timeout > 0:
            try_route = route
            break
        else:
            state.routes.ignored_routes.append(route)

    if try_route is None:
        # No route available, refund the from_route hop so that it can try a
        # new route.
        #
        # A refund transfer works like a special MediatedTransfer, so it must
        # follow the same rules and decrement reveal_timeout from the
        # payee_transfer.
        new_lock_timeout = timeout - state.from_route.reveal_timeout
        new_lock_timeout -= TRANSIT_BLOCKS

        if new_lock_timeout > 0:
            new_lock_expiration = new_lock_timeout + state.block_number

            refund_transfer = RefundTransfer(
                from_transfer.identifier,
                from_transfer.token,
                from_transfer.amount,
                from_transfer.hashlock,
                new_lock_expiration,
                state.from_route.node_address,
            )

            iteration = Iteration(state, [refund_transfer])
        else:
            # Can not create a refund lock with a safe expiration, so don't do
            # anything and wait for the received lock to expire.
            iteration = Iteration(state, list())

    else:
        lock_expiration = lock_timeout + state.block_number

        mediated_transfer = MediatedTransfer(
            from_transfer.identifier,
            from_transfer.token,
            from_transfer.amount,
            from_transfer.hashlock,
            from_transfer.target,
            lock_expiration,
            try_route.node_address,
        )

        transfer_pair = MediationPairState(
            payer_route,
            payer_transfer,
            try_route,
            mediated_transfer,
        )

        state.route = try_route

        # the list must be ordered from high to low expiration, expiration
        # handling depends on it
        state.transfers_pair.append(transfer_pair)

        iteration = Iteration(state, [mediated_transfer])

    return iteration


def state_transition(state, state_change):
    """ State machine for a node mediating a transfer. """
    # Notes:
    # - A user cannot cancel a mediated transfer after it was initiated, she
    #   may only reject to mediate before hand. This is because the mediator
    #   doesn't control the secret reveal and needs to wait for the lock
    #   expiration before safely discarding the transfer.

    if state is None:
        if isinstance(state_change, InitMediator):
            routes = state_change.routes

            from_route = state_change.from_route
            from_transfer = state_change.from_transfer

            state = MediatorState(
                state_change.our_address,
                routes,
                state_change.block_number,
                from_transfer.hashlock,
            )

            iteration = mediate_transfer(state, from_route, from_transfer)

    elif state.secret is None:
        # while waiting for the secret refunds are valid
        if isinstance(state_change, TransferRefundReceived):
            iteration = handle_refundtransfer(state, state_change)

        elif isinstance(state_change, SecretRevealReceived):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, NettingChannelWithdraw):
            iteration = handle_channelwithdraw(state, state_change)

        elif isinstance(state_change, Blocknumber):
            state.block_number = state_change.block_number
            iteration = handle_new_block(state)

        elif isinstance(state_change, RouteChange):
            update_route(state, state_change)
            iteration = Iteration(state, list())

    else:
        # when the secret is revealed the path cannot change anymore, so ignore
        # refunds and route changes

        if isinstance(state_change, SecretRevealReceived):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, NettingChannelWithdraw):
            iteration = handle_channelwithdraw(state, state_change)

        elif isinstance(state_change, BalanceProofReceived):
            handle_balanceproof(state, state_change)
            iteration = Iteration(state, list())

        elif isinstance(state_change, Blocknumber):
            state.block_number = state_change.block_number
            iteration = handle_new_block(state)

    return clear_if_finalized(iteration)
