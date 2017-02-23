# -*- coding: utf-8 -*-
import itertools

from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.mediated_transfer.state import (
    MediatorState,
    MediationPairState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveBalanceProof,
    ActionInitMediator,
    ContractReceiveWithdraw,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state_change import (
    Block,
    ActionRouteChange,
)
from raiden.transfer.mediated_transfer.events import (
    mediatedtransfer,

    ContractSendWithdraw,
    SendBalanceProof,
    SendRefundTransfer,
    SendRevealSecret,
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
    'payee_refund_withdraw',
    'payee_contract_withdraw',
    'payee_balance_proof',

    'payer_secret_revealed',
    'payer_waiting_withdraw',
    'payer_contract_withdraw',
    'payer_balance_proof',
)
STATE_TRANSFER_PAYED = (
    'payee_contract_withdraw',
    'payee_balance_proof',

    'payer_contract_withdraw',
    'payer_balance_proof',
)
# TODO: fix expired state, it is not final
STATE_TRANSFER_FINAL = (
    'payee_contract_withdraw',
    'payee_balance_proof',
    'payee_expired',

    'payer_contract_withdraw',
    'payer_balance_proof',
    'payer_expired',
)


def is_lock_valid(block_number, transfer):
    """ True if the lock has not expired. """
    return block_number <= transfer.expiration


def is_safe_to_wait(block_number, transfer, reveal_timeout):
    """ True if there are more than enough blocks to safely settle on chain and
    waiting is safe.
    """
    # A node may wait for a new balance proof while there are reveal_timeout
    # left, at that block and onwards it is not safe to wait.
    return block_number < transfer.expiration - reveal_timeout


def is_valid_refund(original_transfer, refund_sender, refund_transfer):
    """ True if the refund transfer matches the original transfer. """
    # Ignore a refund from the target
    if refund_sender == original_transfer.target:
        return False

    return (
        original_transfer.identifier == refund_transfer.identifier and
        original_transfer.amount == refund_transfer.amount and
        original_transfer.hashlock == refund_transfer.hashlock and
        original_transfer.target == refund_transfer.target and

        # A larger-or-equal expiration is byzantine behavior that favors this
        # node, neverthless it's being ignored since the only reason for the
        # other node to use an invalid expiration is to play the protocol.
        original_transfer.expiration > refund_transfer.expiration
    )


def get_pending_transfer_pairs(transfers_pair):
    """ Return the transfer pairs that han't reached a final state. """
    pending_pairs = list(
        pair
        for pair in transfers_pair
        if pair.payee_state not in STATE_TRANSFER_FINAL or
        pair.payer_state not in STATE_TRANSFER_FINAL
    )
    return pending_pairs


def get_timeout_blocks(payer_route, payer_transfer, block_number):
    """ Return the timeout blocks, it's the base value from which the payee's
    lock timeout must be computed.

    The payee lock timeout is crucial for safety of the mediate transfer, the
    value must be choosen so that the payee hop is forced to reveal the secret
    with sufficient time for this node to claim the received lock from the
    payer hop.

    The timeout blocks must be the smallest of:

    - payer_transfer.expiration: The payer lock expiration, to force the payee
      to reveal the secret before the lock expires.
    - payer_route.settle_timeout: Lock expiration must be lower than
      the settlement period since the lock cannot be claimed after the channel is
      settled.
    - payer_route.close_block: If the block is closed the settlement period is
      running and the lock expiration must be lower than number of blocks left.
    """
    blocks_until_settlement = payer_route.settle_timeout

    if payer_route.close_block is not None:
        assert block_number >= payer_route.close_block

        elapsed_blocks = block_number - payer_route.close_block
        blocks_until_settlement -= elapsed_blocks

    safe_payer_timeout = min(
        blocks_until_settlement,
        payer_transfer.expiration - block_number,
    )
    timeout_blocks = safe_payer_timeout - TRANSIT_BLOCKS

    return timeout_blocks


def sanity_check(state):
    """ Check invariants that must hold. """

    # if a transfer is paid we must know the secret
    all_transfers_states = itertools.chain(
        (pair.payee_state for pair in state.transfers_pair),
        (pair.payer_state for pair in state.transfers_pair),
    )
    if any(state in STATE_TRANSFER_PAYED for state in all_transfers_states):
        assert state.secret is not None

    # the "transitivity" for these values is checked bellow as part of
    # almost_equal check
    if state.transfers_pair:
        first_pair = state.transfers_pair[0]
        assert state.hashlock == first_pair.payer_transfer.hashlock
        if state.secret is not None:
            assert first_pair.payer_transfer.secret == state.secret

    for pair in state.transfers_pair:
        assert pair.payer_transfer.almost_equal(pair.payee_transfer)
        assert pair.payer_transfer.expiration > pair.payee_transfer.expiration

        assert pair.payer_state in pair.valid_payer_states
        assert pair.payee_state in pair.valid_payee_states

    for original, refund in zip(state.transfers_pair[:-1], state.transfers_pair[1:]):
        assert original.payee_transfer.almost_equal(refund.payer_transfer)
        assert original.payee_route.node_address == refund.payer_route.node_address
        assert original.payee_transfer.expiration > refund.payer_transfer.expiration


def clear_if_finalized(iteration):
    """ Clear the state if all transfer pairs have finalized. """
    state = iteration.new_state

    # TODO: clear the expired transfer, this needs will need synchronization
    # messages
    all_finalized = all(
        pair.payee_state in STATE_TRANSFER_PAYED and pair.payer_state in STATE_TRANSFER_PAYED
        for pair in state.transfers_pair
    )

    # TODO: how do we define success and failure for a mediator since the state
    # of individual paths may differ?

    if all_finalized:
        return Iteration(None, iteration.events)
    return iteration


def next_route(routes_state, timeout_blocks, transfer_amount):
    """ Finds the route first route available that can be used.

    Args:
        routes_state (RoutesState): The route states to do the search, it's
            assume thet available_routes is ordered from best to worst route.
        timeout_blocks (int): Base number of available blocks used to compute
            the lock timeout.
        transfer_amount (int): The amount of tokens that will be transferred
            through the given route.

    Returns:
        (RouteState): The next route.
    """
    while routes_state.available_routes:
        route = routes_state.available_routes.pop(0)

        lock_timeout = timeout_blocks - route.reveal_timeout
        enough_balance = route.available_balance >= transfer_amount

        if enough_balance and lock_timeout > 0:
            return route
        else:
            routes_state.ignored_routes.append(route)

    return None


def next_transfer_pair(payer_route, payer_transfer, routes_state, timeout_blocks, block_number):
    """ Given a mediation payer route tries a new route to proceed with the
    mediation.

    Args:
        payer_route (RouteState): The previous route in the path that provides
            the token for the mediation.
        payer_transfer (LockedTransferState): The transfer received from the
            payer_route.
        routes_state (RoutesState): The route states to do the search, it's
            assume thet available_routes is ordered from best to worst route.
        timeout_blocks (int): Base number of available blocks used to compute
            the lock timeout.
        block_number (int): The current block number.
    """
    assert timeout_blocks > 0
    assert timeout_blocks <= payer_transfer.expiration - block_number

    transfer_pair = None
    mediated_events = list()

    payee_route = next_route(
        routes_state,
        timeout_blocks,
        payer_transfer.amount,
    )

    if payee_route:
        assert payee_route.reveal_timeout < timeout_blocks

        lock_timeout = timeout_blocks - payee_route.reveal_timeout
        lock_expiration = lock_timeout + block_number

        payee_transfer = LockedTransferState(
            payer_transfer.identifier,
            payer_transfer.amount,
            payer_transfer.token,
            payer_transfer.target,
            lock_expiration,
            payer_transfer.hashlock,
            payer_transfer.secret,
        )

        transfer_pair = MediationPairState(
            payer_route,
            payer_transfer,
            payee_route,
            payee_transfer,
        )

        mediated_events = [
            mediatedtransfer(payee_transfer, payer_route.node_address),
        ]

    return (
        transfer_pair,
        mediated_events,
    )


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


def set_payee_state_and_check_reveal_order(transfers_pair,  # pylint: disable=invalid-name
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


def events_for_refund_transfer(refund_route, refund_transfer, timeout_blocks, block_number):
    """ Refund the transfer.

    Args:
        refund_route (RouteState): The original route that sent the mediated
            transfer to this node.
        refund_transfer (LockedTransferState): The original mediated transfer
            from the refund_route.
        timeout_blocks (int): The number of blocks available from the /latest
            transfer/ received by this node, this transfer might be the
            refund_transfer (if no route was available) or a refund transfer from a
            down stream node.
        block_number (int): The current block number.

    Returns:
        An empty list if there are not enough blocks to safely create a refund,
        or a list with an refund event.
    """
    # A refund transfer works like a special SendMediatedTransfer, so it must
    # follow the same rules and decrement reveal_timeout from the
    # payee_transfer.
    new_lock_timeout = timeout_blocks - refund_route.reveal_timeout

    if new_lock_timeout > 0:
        new_lock_expiration = new_lock_timeout + block_number

        refund_transfer = SendRefundTransfer(
            refund_transfer.identifier,
            refund_transfer.token,
            refund_transfer.amount,
            refund_transfer.hashlock,
            new_lock_expiration,
            refund_route.node_address,
        )

        return [refund_transfer]

    # Can not create a refund lock with a safe expiration, so don't do anything
    # and wait for the received lock to expire.
    return list()


def events_for_revealsecret(transfers_pair, our_address):
    """ Reveal the secret backwards.

    This node is named N, suppose there is a mediated transfer with two
    refund transfers, one from B and one from C:

        A-N-B...B-N-C..C-N-D

    Under normal operation N will first learn the secret from D, then reveal to
    C, wait for C to inform the secret is known before revealing it to B, and
    again wait for B before revealing the secret to A.

    If B somehow sent a reveal secret before C and D, then the secret will be
    revealed to A, but not C and D, meaning the secret won't be propagate
    forward. Even if D sent a reveal secret at about the same time, the secret
    will only be revealed to B upon confirmation from C.

    Even though B somehow learnt the secret out-of-order N is safe to proceed
    with the protocol, the TRANSIT_BLOCKS configuration adds enough time for
    the reveal secrets to propagate backwards and for B to send the balance
    proof. If the proof doesn't arrive in time and the lock's expiration is at
    risk, N won't lose tokens since it knows the secret can go on-chain at any
    time.
    """
    events = list()
    for pair in reversed(transfers_pair):
        payee_secret = pair.payee_state in STATE_SECRET_KNOWN
        payer_secret = pair.payer_state in STATE_SECRET_KNOWN

        if payee_secret and not payer_secret:
            pair.payer_state = 'payer_secret_revealed'
            reveal_secret = SendRevealSecret(
                pair.payer_transfer.identifier,
                pair.payer_transfer.secret,
                pair.payer_route.node_address,
                our_address,
            )
            events.append(reveal_secret)

    return events


def events_for_balanceproof(transfers_pair, block_number):
    """ Send the balance proof to nodes that know the secret. """

    events = list()
    for pair in reversed(transfers_pair):
        payee_knows_secret = pair.payee_state in STATE_SECRET_KNOWN
        payee_payed = pair.payee_state in STATE_TRANSFER_PAYED
        payee_channel_open = pair.payee_route.state == 'available'

        # XXX: All nodes must close the channel and withdraw on-chain if the
        # lock is nearing it's expiration block, what should be the strategy
        # for sending a balance proof to a node that knowns the secret but has
        # not gone on-chain while near the expiration? (The problem is how to
        # define the unsafe region, since that is a local configuration)
        lock_valid = is_lock_valid(block_number, pair.payee_transfer)

        if payee_channel_open and payee_knows_secret and not payee_payed and lock_valid:
            pair.payee_state = 'payee_balance_proof'
            balance_proof = SendBalanceProof(
                pair.payee_transfer.identifier,
                pair.payee_route.node_address,
            )
            events.append(balance_proof)

    return events


def events_for_expiration(transfers_pair, block_number):
    """ Requests for settlement on-chain if the hash time lock reached the
    limit block to safely withdraw on-chain.
    """
    events = list()
    pending_transfers_pairs = get_pending_transfer_pairs(transfers_pair)

    for pair in reversed(pending_transfers_pairs):
        # Only withdraw on chain if the corresponding payee transfer is payed,
        # this prevents attacks were tokens are burned to force a channel close.
        payee_payed = pair.payee_state in STATE_TRANSFER_PAYED
        payer_payed = pair.payer_state in STATE_TRANSFER_PAYED
        witdrawing = pair.payer_state == 'payer_waiting_withdraw'

        if payee_payed and not payer_payed and not witdrawing:
            safe_to_wait = is_safe_to_wait(
                block_number,
                pair.payer_transfer,
                pair.payer_route.reveal_timeout,
            )

            if not safe_to_wait:
                pair.payer_state = 'payer_waiting_withdraw'
                settle_channel = ContractSendWithdraw(
                    pair.payer_transfer,
                    pair.payer_route.channel_address,
                )
                events.append(settle_channel)

        # NOTE: order of elif is important, payer test is first because it's
        # expiration block is always larger
        elif block_number > pair.payer_transfer.expiration:
            assert pair.payee_state == 'payee_expired'
            assert pair.payee_transfer.expiration < pair.payer_transfer.expiration
            pair.payer_state = 'payer_expired'

        elif block_number > pair.payee_transfer.expiration:
            assert pair.payee_state not in STATE_TRANSFER_PAYED
            assert pair.payee_transfer.expiration < pair.payer_transfer.expiration
            pair.payee_state = 'payee_expired'

    return events


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
    secret_reveal = events_for_revealsecret(
        state.transfers_pair,
        state.our_address,
    )

    # send the balance proof to payee that knows the secret but is not payed
    # yet
    balance_proof = events_for_balanceproof(
        state.transfers_pair,
        state.block_number,
    )

    iteration = Iteration(
        state,
        wrong_order + secret_reveal + balance_proof,
    )

    return iteration


def mediate_transfer(state, payer_route, payer_transfer):
    """ Try a new route or fail back to a refund.

    The mediator can safely try a new route knowing that the tokens from
    payer_transfer will cover the expenses of the mediation. If there is no
    route available that may be used at the moment of the call the mediator may
    send a refund back to the payer, allowing the payer to try a different
    route.
    """
    transfer_pair = None
    mediated_events = list()

    timeout_blocks = get_timeout_blocks(
        payer_route,
        payer_transfer,
        state.block_number,
    )

    if timeout_blocks > 0:
        transfer_pair, mediated_events = next_transfer_pair(
            payer_route,
            payer_transfer,
            state.routes,
            timeout_blocks,
            state.block_number,
        )

    if transfer_pair is None:
        if state.transfers_pair:
            original_transfer = state.transfers_pair[0].payer_transfer
            original_route = state.transfers_pair[0].payer_route
        else:
            original_route = payer_route
            original_transfer = payer_transfer

        refund_events = events_for_refund_transfer(
            original_route,
            original_transfer,
            timeout_blocks,
            state.block_number,
        )

        iteration = Iteration(state, refund_events)

    else:
        # the list must be ordered from high to low expiration, expiration
        # handling depends on it
        state.transfers_pair.append(transfer_pair)
        iteration = Iteration(state, mediated_events)

    return iteration


def handle_block(state, state_change):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time locks.

    Args:
        state (MediatorState): The current state.

    Return:
        Iteration: The resulting iteration
    """
    block_number = state_change.block_number
    state.block_number = block_number

    events = events_for_expiration(
        state.transfers_pair,
        block_number,
    )

    iteration = Iteration(state, events)

    return iteration


def handle_refundtransfer(state, state_change):
    """ Validate and handle a ReceiveTransferRefund state change.

    A node might participate in mediated transfer more than once because of
    refund transfers, eg. A-B-C-B-D-T, B tried to mediated the transfer through
    C, which didn't have a available route to proceed and refunds B, at this
    point B is part of the path again and will try a new partner to proceed
    with the mediation through D, D finally reaches the target T.

    In the above scenario B has two pairs of payer and payee transfers:

        payer:A payee:C from the first SendMediatedTransfer
        payer:C payee:D from the following SendRefundTransfer

    Args:
        state (MediatorState): Current state.
        state_change (ReceiveTransferRefund): The state change.

    Returns:
        Iteration: The resulting iteration.
    """
    assert state.secret is None, 'refunds are not allowed if the secret is revealed'

    # The last sent transfer is the only one thay may be refunded, all the
    # previous ones are refunded already.
    transfer_pair = state.transfers_pair[-1]
    payee_transfer = transfer_pair.payee_transfer

    if is_valid_refund(payee_transfer, state_change.sender, state_change.transfer):
        payer_route = transfer_pair.payee_route
        payer_transfer = state_change.transfer
        state.routes.refund_routes.append(payer_route)
        iteration = mediate_transfer(
            state,
            payer_route,
            payer_transfer,
        )

    else:
        # TODO: Use an event to notify about byzantine behavior
        iteration = Iteration(state, list())

    return iteration


def handle_secretreveal(state, state_change):
    """ Validate and handle a ReceiveSecretReveal state change.

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


def handle_contractwithdraw(state, state_change):
    """ Handle a NettingChannelUnlock state change. """
    assert sha3(state.secret) == state.hashlock, 'secret must be validated by the smart contract'

    # For all but the last pair in transfer pair a refund transfer ocurred,
    # meaning the same channel was used twice, once when this node sent the
    # mediated transfer and once when the refund transfer was received. A
    # ContractReceiveWithdraw state change may be used for each.

    # This node withdrew the refund
    if state_change.receiver == state.our_address:
        for previous_pos, pair in enumerate(state.transfers_pair, -1):
            if pair.payer_route.channel_address == state_change.channel_address:
                # always set the contract_withdraw regardless of the previous
                # state (even expired)
                pair.payer_state = 'payer_contract_withdraw'

                # if the current pair is backed by a refund set the sent
                # mediated transfer to a 'secret know' state
                if previous_pos > -1:
                    previous_pair = state.transfers_pair[previous_pos]

                    if previous_pair.payee_state not in STATE_TRANSFER_FINAL:
                        previous_pair.payee_state = 'payee_refund_withdraw'

    # A partner withdrew the mediated transfer
    else:
        for pair in state.transfers_pair:
            if pair.payer_route.channel_address == state_change.channel_address:
                pair.payee_state = 'payee_contract_withdraw'

    iteration = secret_learned(
        state,
        state_change.secret,
        state_change.receiver,
        'payee_contract_withdraw',
    )

    return iteration


def handle_balanceproof(state, state_change):
    """ Handle a ReceiveBalanceProof state change. """
    for pair in state.transfers_pair:
        if pair.payer_route.channel_address == state_change.node_address:
            pair.payer_state = 'payer_balance_proof'

    iteration = Iteration(state, list())

    return iteration


def handle_routechange(state, state_change):
    """ Hande a ActionRouteChange state change. """
    # TODO: `update_route` only changes the RoutesState, instead of moving the
    # routes to the MediationPairState use identifier to reference the routes
    new_route = state_change.route
    used = False

    # a route in use might be closed because of another task, update the pair
    # state in-place
    for pair in state.transfers_pair:
        if pair.payee_route.node_address == new_route.node_address:
            pair.payee_route = new_route
            used = True

        if pair.payer_route.node_address == new_route.node_address:
            pair.payer_route = new_route
            used = True

    if not used:
        update_route(state, state_change)

    iteration = Iteration(state, list())
    return iteration


def state_transition(state, state_change):
    """ State machine for a node mediating a transfer. """
    # pylint: disable=too-many-branches
    # Notes:
    # - A user cannot cancel a mediated transfer after it was initiated, she
    #   may only reject to mediate before hand. This is because the mediator
    #   doesn't control the secret reveal and needs to wait for the lock
    #   expiration before safely discarding the transfer.

    if state is None:
        if isinstance(state_change, ActionInitMediator):
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
        if isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

        elif isinstance(state_change, ActionRouteChange):
            iteration = handle_routechange(state, state_change)

        elif isinstance(state_change, ReceiveTransferRefund):
            iteration = handle_refundtransfer(state, state_change)

        elif isinstance(state_change, ReceiveSecretReveal):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, ContractReceiveWithdraw):
            iteration = handle_contractwithdraw(state, state_change)

    else:
        if isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

        if isinstance(state_change, ReceiveSecretReveal):
            iteration = handle_secretreveal(state, state_change)

        elif isinstance(state_change, ReceiveBalanceProof):
            iteration = handle_balanceproof(state, state_change)

        elif isinstance(state_change, ContractReceiveWithdraw):
            iteration = handle_contractwithdraw(state, state_change)

    # this is the place for paranoia
    sanity_check(iteration.new_state)

    return clear_if_finalized(iteration)
