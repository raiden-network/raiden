# -*- coding: utf-8 -*-
import itertools
from typing import List, Dict

from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import ContractSendChannelWithdraw
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    LockedTransferUnsignedState,
    MediationPairState2,
    MediatorTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator2,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelWithdraw,
    ReceiveUnlock,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendRevealSecret2,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
)
from raiden.utils import sha3

# Reduce the lock expiration by some additional blocks to prevent this exploit:
# The payee could reveal the secret on it's lock expiration block, the lock
# would be valid and the previous lock can be safely unlocked so the mediator
# would follow the secret reveal with a balance-proof, at this point the secret
# is known, the payee transfer is payed, and if the payer expiration is exactly
# reveal_timeout blocks away the mediator will be forced to close the channel
# to be safe.
TRANSIT_BLOCKS = 2  # TODO: make this a configuration variable


STATE_SECRET_KNOWN = (
    'payee_secret_revealed',
    'payee_refund_withdraw',
    'payee_contract_withdraw',
    'payee_balance_proof',

    'payer_secret_revealed',
    'payer_waiting_close',
    'payer_waiting_withdraw',
    'payer_contract_withdraw',
    'payer_balance_proof',
)
STATE_TRANSFER_PAID = (
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


def is_lock_valid(expiration, block_number):
    """ True if the lock has not expired. """
    return block_number <= expiration


def is_safe_to_wait2(lock_expiration, reveal_timeout, block_number):
    """ True if there are more than enough blocks to safely settle on chain and
    waiting is safe.
    """
    # reveal timeout will not ever be larger than the lock_expiration otherwise
    # the expected block_number is negative
    assert block_number > 0
    assert lock_expiration > reveal_timeout > 0

    # A node may wait for a new balance proof while there are reveal_timeout
    # blocks left, at that block and onwards it is not safe to wait.
    return block_number < lock_expiration - reveal_timeout


def is_valid_refund2(
        original_transfer: LockedTransferUnsignedState,
        refund_transfer: LockedTransferSignedState):
    """ True if the refund transfer matches the original transfer. """
    refund_transfer_sender = refund_transfer.balance_proof.sender

    # Ignore a refund from the target
    if refund_transfer_sender == original_transfer.target:
        return False

    return (
        original_transfer.identifier == refund_transfer.identifier and
        original_transfer.lock.amount == refund_transfer.lock.amount and
        original_transfer.lock.hashlock == refund_transfer.lock.hashlock and
        original_transfer.target == refund_transfer.target and

        # The refund transfer is not tied to the other direction of the same
        # channel, it may reach this node through a different route depending
        # on the path finding strategy
        # original_receiver == refund_transfer_sender and
        original_transfer.token == refund_transfer.token and

        # A larger-or-equal expiration is byzantine behavior that favors the
        # receiver node, neverthless it's being ignored since the only reason
        # for the other node to use an invalid expiration is to play the
        # protocol.
        original_transfer.lock.expiration > refund_transfer.lock.expiration
    )


def is_channel_close_needed2(payer_channel, transfer_pair, block_number):
    """ True if this node needs to close the channel to withdraw on-chain.
    Only close the channel to withdraw on chain if the corresponding payee node
    has received, this prevents attacks were the payee node burns it's payment
    to force a close with the payer channel.
    """
    payee_received = transfer_pair.payee_state in STATE_TRANSFER_PAID
    payer_payed = transfer_pair.payer_state in STATE_TRANSFER_PAID

    payer_channel_open = channel.get_status(payer_channel) == CHANNEL_STATE_OPENED
    already_closing = channel.get_status(payer_channel) == CHANNEL_STATE_CLOSING

    safe_to_wait = is_safe_to_wait2(
        transfer_pair.payer_transfer.lock.expiration,
        payer_channel.reveal_timeout,
        block_number,
    )

    return (
        payee_received and
        not payer_payed and

        payer_channel_open and
        not already_closing and
        not safe_to_wait
    )


def is_send_transfer_almost_equal(
        send: LockedTransferUnsignedState,
        received: LockedTransferSignedState
):
    """ True if both transfers are for the same mediated transfer. """
    # the only value that may change for each hop is the expiration
    return (
        isinstance(send, LockedTransferUnsignedState) and
        isinstance(received, LockedTransferSignedState) and
        send.identifier == received.identifier and
        send.token == received.token and
        send.lock.amount == received.lock.amount and
        send.lock.hashlock == received.lock.hashlock and
        send.initiator == received.initiator and
        send.target == received.target
    )


def filter_available_routes(transfers_pair, routes):
    channelid_to_route = {r.channel_identifier: r for r in routes}

    for pair in transfers_pair:
        channelid = pair.payer_transfer.balance_proof.channel_address
        if channelid in channelid_to_route:
            del channelid_to_route[channelid]

        channelid = pair.payee_transfer.balance_proof.channel_address
        if channelid in channelid_to_route:
            del channelid_to_route[channelid]

    return list(channelid_to_route.values())


def get_payee_channel(channelidentifiers_to_channels, transfer_pair):
    """ Returns the payee channel of a given transfer pair. """
    payee_channel_identifier = transfer_pair.payee_transfer.balance_proof.channel_address
    assert payee_channel_identifier in channelidentifiers_to_channels
    payee_channel = channelidentifiers_to_channels[payee_channel_identifier]

    return payee_channel


def get_payer_channel(channelidentifiers_to_channels, transfer_pair):
    """ Returns the payer channel of a given transfer pair. """
    payer_channel_identifier = transfer_pair.payer_transfer.balance_proof.channel_address
    assert payer_channel_identifier in channelidentifiers_to_channels
    payer_channel = channelidentifiers_to_channels[payer_channel_identifier]

    return payer_channel


def get_pending_transfer_pairs(transfers_pair):
    """ Return the transfer pairs that are not at a final state. """
    pending_pairs = list(
        pair
        for pair in transfers_pair
        if pair.payee_state not in STATE_TRANSFER_FINAL or
        pair.payer_state not in STATE_TRANSFER_FINAL
    )
    return pending_pairs


def get_timeout_blocks2(settle_timeout, closed_block_number, payer_lock_expiration, block_number):
    """ Return the timeout blocks, it's the base value from which the payees
    lock timeout must be computed.
    The payee lock timeout is crucial for safety of the mediated transfer, the
    value must be chosen so that the payee hop is forced to reveal the secret
    with sufficient time for this node to claim the received lock from the
    payer hop.
    The timeout blocks must be the smallest of:
    - payer_lock_expiration: The payer lock expiration, to force the payee
      to reveal the secret before the lock expires.
    - settle_timeout: Lock expiration must be lower than
      the settlement period since the lock cannot be claimed after the channel is
      settled.
    - closed_block_number: If the channel is closed then the settlement
      period is running and the lock expiration must be lower than number of
      blocks left.
    """
    blocks_until_settlement = settle_timeout

    if closed_block_number is not None:
        assert block_number >= closed_block_number > 0

        elapsed_blocks = block_number - closed_block_number
        blocks_until_settlement -= elapsed_blocks

    safe_payer_timeout = min(
        blocks_until_settlement,
        payer_lock_expiration - block_number,
    )
    timeout_blocks = safe_payer_timeout - TRANSIT_BLOCKS

    return timeout_blocks


def sanity_check2(state):
    """ Check invariants that must hold. """

    # if a transfer is paid we must know the secret
    all_transfers_states = itertools.chain(
        (pair.payee_state for pair in state.transfers_pair),
        (pair.payer_state for pair in state.transfers_pair),
    )
    if any(state in STATE_TRANSFER_PAID for state in all_transfers_states):
        assert state.secret is not None

    # the "transitivity" for these values is checked below as part of
    # almost_equal check
    if state.transfers_pair:
        first_pair = state.transfers_pair[0]
        assert state.hashlock == first_pair.payer_transfer.lock.hashlock

    for pair in state.transfers_pair:
        assert is_send_transfer_almost_equal(pair.payee_transfer, pair.payer_transfer)
        assert pair.payer_transfer.lock.expiration > pair.payee_transfer.lock.expiration

        assert pair.payer_state in pair.valid_payer_states
        assert pair.payee_state in pair.valid_payee_states

    for original, refund in zip(state.transfers_pair[:-1], state.transfers_pair[1:]):
        assert is_send_transfer_almost_equal(original.payee_transfer, refund.payer_transfer)
        assert original.payee_address == refund.payer_address
        assert original.payee_transfer.lock.expiration > refund.payer_transfer.lock.expiration


def clear_if_finalized(iteration):
    """ Clear the state if all transfer pairs have finalized. """
    state = iteration.new_state

    if state is None:
        return iteration

    # TODO: clear the expired transfer, this will need some sort of
    # synchronization among the nodes
    all_finalized = all(
        pair.payee_state in STATE_TRANSFER_PAID and pair.payer_state in STATE_TRANSFER_PAID
        for pair in state.transfers_pair
    )

    if all_finalized:
        return TransitionResult(None, iteration.events)
    return iteration


def next_channel_from_routes(
        available_routes: List['RouteState'],
        channelidentifiers_to_channels: Dict,
        transfer_amount: int,
        timeout_blocks: int
) -> 'NettingChannelState':
    """ Returns the first route that may be used to mediated the transfer.
    The routing service can race with local changes, so the recommended routes
    must be validated.
    Args:
        available_routes: Current available routes that may be used, it's
            assumed that the available_routes list is ordered from best to
            worst.
        channelidentifiers_to_channels: Mapping from channel identifier
            to NettingChannelState.
        transfer_amount: The amount of tokens that will be transferred
            through the given route.
        timeout_blocks: Base number of available blocks used to compute
            the lock timeout.
    Returns:
        The next route.
    """
    for route in available_routes:
        channel_identifier = route.channel_identifier
        channel_state = channelidentifiers_to_channels.get(channel_identifier)

        if not channel_state:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )
        if transfer_amount > distributable:
            continue

        lock_timeout = timeout_blocks - channel_state.reveal_timeout
        if lock_timeout <= 0:
            continue

        return channel_state


def next_transfer_pair2(
        payer_transfer: LockedTransferSignedState,
        available_routes: List['RouteState'],
        channelidentifiers_to_channels: Dict,
        timeout_blocks: int,
        block_number: int
):
    """ Given a payer transfer tries a new route to proceed with the mediation.
    Args:
        payer_transfer: The transfer received from the payer_channel.
        routes: Current available routes that may be used, it's assumed that
            the routes list is ordered from best to worst.
        timeout_blocks: Base number of available blocks used to compute
            the lock timeout.
        block_number: The current block number.
    """
    assert timeout_blocks > 0
    assert timeout_blocks <= payer_transfer.lock.expiration - block_number

    transfer_pair = None
    mediated_events = list()

    payee_channel = next_channel_from_routes(
        available_routes,
        channelidentifiers_to_channels,
        payer_transfer.lock.amount,
        timeout_blocks,
    )

    if payee_channel:
        assert payee_channel.reveal_timeout < timeout_blocks
        assert payee_channel.token_address == payer_transfer.token

        lock_timeout = timeout_blocks - payee_channel.reveal_timeout
        lock_expiration = lock_timeout + block_number

        mediatedtransfer_event = channel.send_mediatedtransfer(
            payee_channel,
            payer_transfer.initiator,
            payer_transfer.target,
            payer_transfer.lock.amount,
            payer_transfer.identifier,
            lock_expiration,
            payer_transfer.lock.hashlock
        )
        assert mediatedtransfer_event

        transfer_pair = MediationPairState2(
            payer_transfer,
            payee_channel.partner_state.address,
            mediatedtransfer_event.transfer,
        )

        mediated_events = [mediatedtransfer_event]

    return (
        transfer_pair,
        mediated_events,
    )


def set_secret2(state, channelidentifiers_to_channels, secret, hashlock):
    """ Set the secret to all mediated transfers.
    It doesn't matter if the secret was learned through the blockchain or a
    secret reveal message.
    """
    state.secret = secret

    for pair in state.transfers_pair:
        payer_channel = channelidentifiers_to_channels[
            pair.payer_transfer.balance_proof.channel_address
        ]
        channel.register_secret(
            payer_channel,
            secret,
            hashlock,
        )

        payee_channel = channelidentifiers_to_channels[
            pair.payer_transfer.balance_proof.channel_address
        ]
        channel.register_secret(
            payee_channel,
            secret,
            hashlock,
        )


def set_payee_state_and_check_reveal_order2(  # pylint: disable=invalid-name
        transfers_pair,
        payee_address,
        new_payee_state
):
    """ Set the state of a transfer *sent* to a payee and check the secret is
    being revealed backwards.
    Note:
        The elements or transfers_pair are changed in place, the list must
        contain all the known transfers to properly check reveal order.
    """
    assert new_payee_state in MediationPairState2.valid_payee_states

    wrong_reveal_order = False
    for back in reversed(transfers_pair):
        if back.payee_address == payee_address:
            back.payee_state = new_payee_state
            break

        elif back.payee_state not in STATE_SECRET_KNOWN:
            wrong_reveal_order = True

    if wrong_reveal_order:
        # TODO: Append an event for byzantine behavior.
        # XXX: This can happen if a mediator in the middle of the chain of hops
        # learns the secret faster than its subsequent nodes. Should a byzantine
        # behavior notification be added or should we fix the events_for_withdraw function?
        return list()

    return list()


def set_expired_pairs2(transfers_pair, block_number):
    """ Set the state of expired transfers, and return the failed events. """
    pending_transfers_pairs = get_pending_transfer_pairs(transfers_pair)

    events = list()
    for pair in pending_transfers_pairs:
        if block_number > pair.payer_transfer.lock.expiration:
            assert pair.payee_state == 'payee_expired'
            assert pair.payee_transfer.lock.expiration < pair.payer_transfer.lock.expiration

            if pair.payer_state != 'payer_expired':
                pair.payer_state = 'payer_expired'
                # XXX: emit the event only once
                withdraw_failed = EventWithdrawFailed(
                    pair.payer_transfer.identifier,
                    pair.payer_transfer.lock.hashlock,
                    'lock expired',
                )
                events.append(withdraw_failed)

        elif block_number > pair.payee_transfer.lock.expiration:
            assert pair.payee_state not in STATE_TRANSFER_PAID
            assert pair.payee_transfer.lock.expiration < pair.payer_transfer.lock.expiration

            if pair.payee_state != 'payee_expired':
                pair.payee_state = 'payee_expired'
                unlock_failed = EventUnlockFailed(
                    pair.payee_transfer.identifier,
                    pair.payee_transfer.lock.hashlock,
                    'lock expired',
                )
                events.append(unlock_failed)

    return events


def events_for_refund_transfer2(refund_channel, refund_transfer, timeout_blocks, block_number):
    """ Refund the transfer.
    Args:
        refund_route (RouteState): The original route that sent the mediated
            transfer to this node.
        refund_transfer (LockedTransferSignedState): The original mediated transfer
            from the refund_route.
        timeout_blocks (int): The number of blocks available from the /latest
            transfer/ received by this node, this transfer might be the
            original mediated transfer (if no route was available) or a refund
            transfer from a down stream node.
        block_number (int): The current block number.
    Returns:
        An empty list if there are not enough blocks to safely create a refund,
        or a list with a refund event.
    """
    # A refund transfer works like a special SendMediatedTransfer, so it must
    # follow the same rules and decrement reveal_timeout from the
    # payee_transfer.
    new_lock_timeout = timeout_blocks - refund_channel.reveal_timeout

    distributable = channel.get_distributable(
        refund_channel.our_state,
        refund_channel.partner_state,
    )

    if new_lock_timeout > 0 and refund_transfer.lock.amount <= distributable:
        new_lock_expiration = new_lock_timeout + block_number

        refund_transfer = channel.send_refundtransfer(
            refund_channel,
            refund_transfer.initiator,
            refund_transfer.target,
            refund_transfer.lock.amount,
            refund_transfer.identifier,
            new_lock_expiration,
            refund_transfer.lock.hashlock,
        )

        return [refund_transfer]

    # Can not create a refund lock with a safe expiration, so don't do anything
    # and wait for the received lock to expire.
    return list()


def events_for_revealsecret2(transfers_pair, secret):
    """ Reveal the secret backwards.
    This node is named N, suppose there is a mediated transfer with two refund
    transfers, one from B and one from C:
        A-N-B...B-N-C..C-N-D
    Under normal operation N will first learn the secret from D, then reveal to
    C, wait for C to inform the secret is known before revealing it to B, and
    again wait for B before revealing the secret to A.
    If B somehow sent a reveal secret before C and D, then the secret will be
    revealed to A, but not C and D, meaning the secret won't be propagated
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
            payer_transfer = pair.payer_transfer
            reveal_secret = SendRevealSecret2(
                payer_transfer.identifier,
                secret,
                payer_transfer.token,
                payer_transfer.balance_proof.sender,
            )
            events.append(reveal_secret)

    return events


def events_for_balanceproof2(
        channelidentifiers_to_channels,
        transfers_pair,
        block_number,
        secret,
        hashlock):
    """ Send the balance proof to nodes that know the secret. """

    events = list()
    for pair in reversed(transfers_pair):
        payee_knows_secret = pair.payee_state in STATE_SECRET_KNOWN
        payee_payed = pair.payee_state in STATE_TRANSFER_PAID

        payee_channel = get_payee_channel(channelidentifiers_to_channels, pair)
        payee_channel_open = channel.get_status(payee_channel) == CHANNEL_STATE_OPENED

        # XXX: All nodes must close the channel and withdraw on-chain if the
        # lock is nearing it's expiration block, what should be the strategy
        # for sending a balance proof to a node that knowns the secret but has
        # not gone on-chain while near the expiration? (The problem is how to
        # define the unsafe region, since that is a local configuration)
        lock_valid = is_lock_valid(pair.payee_transfer.lock.expiration, block_number)

        if payee_channel_open and payee_knows_secret and not payee_payed and lock_valid:
            pair.payee_state = 'payee_balance_proof'

            unlock_lock = channel.send_unlock(
                payee_channel,
                pair.payee_transfer.identifier,
                secret,
                hashlock,
            )

            unlock_success = EventUnlockSuccess(
                pair.payer_transfer.identifier,
                pair.payer_transfer.lock.hashlock,
            )
            events.append(unlock_lock)
            events.append(unlock_success)

    return events


def events_for_close2(channelidentifiers_to_channels, transfers_pair, block_number):
    """ Close the channels that are in the unsafe region prior to an on-chain
    withdraw.
    """
    events = list()
    pending_transfers_pairs = get_pending_transfer_pairs(transfers_pair)

    for pair in reversed(pending_transfers_pairs):
        payer_channel = get_payer_channel(channelidentifiers_to_channels, pair)

        if is_channel_close_needed2(payer_channel, pair, block_number):
            pair.payer_state = 'payer_waiting_close'
            close_events = channel.events_for_close(payer_channel, block_number)
            events.extend(close_events)

    return events


def events_for_withdraw_if_closed(
        channelidentifiers_to_channels,
        transfers_pair,
        secret,
        hashlock):
    """ Withdraw on chain if the payer channel is closed and the secret is known.
    If a channel is closed because of another task a balance proof will not be
    received, so there is no reason to wait for the unsafe region before
    calling close.
    This may break the reverse reveal order:
        Path: A -- B -- C -- B -- D
        B learned the secret from D and has revealed to C.
        C has not confirmed yet.
        channel(A, B).closed is True.
        B will withdraw on channel(A, B) before C's confirmation.
        A may learn the secret faster than other nodes.
    """
    events = list()
    pending_transfers_pairs = get_pending_transfer_pairs(transfers_pair)

    for pair in pending_transfers_pairs:
        payer_channel = get_payer_channel(channelidentifiers_to_channels, pair)

        payer_channel_open = channel.get_status(payer_channel) == CHANNEL_STATE_OPENED

        # The withdraw is done by the channel
        if not payer_channel_open:
            pair.payer_state = 'payer_waiting_withdraw'

            partner_state = payer_channel.partner_state
            lock = channel.get_lock(partner_state, hashlock)
            unlock_proof = channel.compute_proof_for_lock(
                partner_state,
                secret,
                lock,
            )
            withdraw = ContractSendChannelWithdraw(
                payer_channel.identifier,
                [unlock_proof],
            )
            events.append(withdraw)

    return events


def secret_learned2(
        state,
        channelidentifiers_to_channels,
        block_number,
        secret,
        hashlock,
        payee_address,
        new_payee_state):
    """ Set the state of the `payee_address` transfer, check the secret is
    being revealed backwards, and if necessary send out RevealSecret,
    SendBalanceProof, and Withdraws.
    """
    assert new_payee_state in STATE_SECRET_KNOWN
    assert payee_address in (pair.payee_address for pair in state.transfers_pair)

    # TODO: if any of the transfers is in expired state, event for byzantine
    # behavior

    if state.secret is None:
        set_secret2(
            state,
            channelidentifiers_to_channels,
            secret,
            hashlock,
        )

        # This task only needs to withdraw if the channel is closed when the
        # secret is learned, otherwise the channel task will do it
        # automatically
        withdraw = events_for_withdraw_if_closed(
            channelidentifiers_to_channels,
            state.transfers_pair,
            secret,
            hashlock,
        )
    else:
        withdraw = []

    wrong_order = set_payee_state_and_check_reveal_order2(
        state.transfers_pair,
        payee_address,
        new_payee_state,
    )

    secret_reveal = events_for_revealsecret2(
        state.transfers_pair,
        secret,
    )

    balance_proof = events_for_balanceproof2(
        channelidentifiers_to_channels,
        state.transfers_pair,
        block_number,
        secret,
        hashlock,
    )

    iteration = TransitionResult(
        state,
        wrong_order + secret_reveal + balance_proof + withdraw,
    )

    return iteration


def mediate_transfer2(
        state,
        possible_routes,
        payer_channel,
        channelidentifiers_to_channels,
        payer_transfer,
        block_number):
    """ Try a new route or fail back to a refund.
    The mediator can safely try a new route knowing that the tokens from
    payer_transfer will cover the expenses of the mediation. If there is no
    route available that may be used at the moment of the call the mediator may
    send a refund back to the payer, allowing the payer to try a different
    route.
    """
    transfer_pair = None
    mediated_events = list()

    if payer_channel.close_transaction:
        closed_block_number = payer_channel.close_transaction.finished_block_number
    else:
        closed_block_number = None

    timeout_blocks = get_timeout_blocks2(
        payer_channel.settle_timeout,
        closed_block_number,
        payer_transfer.lock.expiration,
        block_number,
    )

    available_routes = filter_available_routes(
        state.transfers_pair,
        possible_routes,
    )

    if timeout_blocks > 0:
        assert payer_channel.partner_state.address == payer_transfer.balance_proof.sender

        transfer_pair, mediated_events = next_transfer_pair2(
            payer_transfer,
            available_routes,
            channelidentifiers_to_channels,
            timeout_blocks,
            block_number,
        )

    # If none of the available_routes could be used, try a refund
    if transfer_pair is None:
        if state.transfers_pair:
            original_pair = state.transfers_pair[0]
            original_transfer = original_pair.payer_transfer
            original_channel = get_payer_channel(
                channelidentifiers_to_channels,
                original_pair,
            )
        else:
            original_channel = payer_channel
            original_transfer = payer_transfer

        refund_events = events_for_refund_transfer2(
            original_channel,
            original_transfer,
            timeout_blocks,
            block_number,
        )

        iteration = TransitionResult(state, refund_events)

    else:
        # the list must be ordered from high to low expiration, expiration
        # handling depends on it
        state.transfers_pair.append(transfer_pair)
        iteration = TransitionResult(state, mediated_events)

    return iteration


def handle_init(state_change, channelidentifiers_to_channels, block_number):
    routes = state_change.routes

    from_route = state_change.from_route
    from_transfer = state_change.from_transfer
    payer_channel = channelidentifiers_to_channels.get(from_route.channel_identifier)

    # There is no corresponding channel for the message, ignore it
    if not payer_channel:
        return TransitionResult(None, [])

    mediator_state = MediatorTransferState(from_transfer.lock.hashlock)

    is_valid, _ = channel.handle_receive_mediatedtransfer(
        payer_channel,
        from_transfer,
    )
    if not is_valid:
        return TransitionResult(None, [])

    iteration = mediate_transfer2(
        mediator_state,
        routes,
        payer_channel,
        channelidentifiers_to_channels,
        from_transfer,
        block_number,
    )
    return iteration


def handle_block2(channelidentifiers_to_channels, state, state_change, block_number):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time locks.
    Args:
        state (MediatorTransferState): The current state.
    Return:
        TransitionResult: The resulting iteration
    """
    close_events = events_for_close2(
        channelidentifiers_to_channels,
        state.transfers_pair,
        block_number,
    )

    # Withdraw is handled by the channel once the close transaction is mined
    # withdraw_events = events_for_withdraw(
    #     channelidentifiers_to_channels,
    #     state.transfers_pair,
    # )

    unlock_fail_events = set_expired_pairs2(
        state.transfers_pair,
        block_number,
    )

    iteration = TransitionResult(
        state,
        close_events + unlock_fail_events,
    )

    return iteration


def handle_refundtransfer2(
        mediator_state,
        mediator_state_change,
        channelidentifiers_to_channels,
        block_number):
    """ Validate and handle a ReceiveTransferRefund mediator_state change.
    A node might participate in mediated transfer more than once because of
    refund transfers, eg. A-B-C-B-D-T, B tried to mediate the transfer through
    C, which didn't have an available route to proceed and refunds B, at this
    point B is part of the path again and will try a new partner to proceed
    with the mediation through D, D finally reaches the target T.
    In the above scenario B has two pairs of payer and payee transfers:
        payer:A payee:C from the first SendMediatedTransfer
        payer:C payee:D from the following SendRefundTransfer
    Args:
        mediator_state (MediatorTransferState): Current mediator_state.
        mediator_state_change (ReceiveTransferRefund): The mediator_state change.
    Returns:
        TransitionResult: The resulting iteration.
    """
    iteration = TransitionResult(mediator_state, list())

    if mediator_state.secret is None:
        # The last sent transfer is the only one thay may be refunded, all the
        # previous ones are refunded already.
        transfer_pair = mediator_state.transfers_pair[-1]
        payee_transfer = transfer_pair.payee_transfer

        is_valid = is_valid_refund2(
            payee_transfer,
            mediator_state_change.transfer,
        )
        if is_valid:
            payer_transfer = mediator_state_change.transfer
            channel_address = payer_transfer.balance_proof.channel_address
            payer_channel = channelidentifiers_to_channels[channel_address]

            iteration = mediate_transfer2(
                mediator_state,
                mediator_state_change.routes,
                payer_channel,
                channelidentifiers_to_channels,
                payer_transfer,
                block_number,
            )

        # else: TODO: Use an event to notify about byzantine behavior

    return iteration


def handle_secretreveal2(
        mediator_state,
        mediator_state_change,
        channelidentifiers_to_channels,
        block_number):
    """ Validate and handle a ReceiveSecretReveal mediator_state change.
    The Secret must propagate backwards through the chain of mediators, this
    function will record the learned secret, check if the secret is propagating
    backwards (for the known paths), and send the SendBalanceProof/RevealSecret if
    necessary.
    """
    is_secret_unknown = mediator_state.secret is None
    is_valid_reveal = mediator_state_change.hashlock == mediator_state.hashlock

    if is_secret_unknown and is_valid_reveal:
        iteration = secret_learned2(
            mediator_state,
            channelidentifiers_to_channels,
            block_number,
            mediator_state_change.secret,
            mediator_state_change.hashlock,
            mediator_state_change.sender,
            'payee_secret_revealed',
        )

    else:
        iteration = TransitionResult(mediator_state, list())

    return iteration


def handle_contractwithdraw2(state, state_change, channelidentifiers_to_channels, block_number):
    """ Handle a NettingChannelUnlock state change. """
    assert sha3(state.secret) == state.hashlock, 'secret must be validated by the smart contract'

    # For all but the last pair in transfer pair a refund transfer ocurred,
    # meaning the same channel was used twice, once when this node sent the
    # mediated transfer and once when the refund transfer was received. A
    # ContractReceiveChannelWithdraw state change may be used for each.

    events = list()

    # This node withdrew the refund
    if state_change.receiver == state.our_address:
        for previous_pos, pair in enumerate(state.transfers_pair, -1):
            payer_channel = get_payer_channel(channelidentifiers_to_channels, pair)
            if payer_channel.identifier == state_change.channel_identifier:
                # always set the contract_withdraw regardless of the previous
                # state (even expired)
                pair.payer_state = 'payer_contract_withdraw'

                withdraw = EventWithdrawSuccess(
                    pair.payer_transfer.identifier,
                    pair.payer_transfer.lock.hashlock,
                )
                events.append(withdraw)

                # if the current pair is backed by a refund set the sent
                # mediated transfer to a 'secret known' state
                if previous_pos > -1:
                    previous_pair = state.transfers_pair[previous_pos]

                    if previous_pair.payee_state not in STATE_TRANSFER_FINAL:
                        previous_pair.payee_state = 'payee_refund_withdraw'

    # A partner withdrew the mediated transfer
    else:
        for pair in state.transfers_pair:
            payee_channel = get_payee_channel(channelidentifiers_to_channels, pair)
            if payee_channel.identifier == state_change.channel_identifier:
                unlock = EventUnlockSuccess(
                    pair.payee_transfer.identifier,
                    pair.payee_transfer.lock.hashlock,
                )
                events.append(unlock)

                pair.payee_state = 'payee_contract_withdraw'

    iteration = secret_learned2(
        state,
        channelidentifiers_to_channels,
        block_number,
        state_change.secret,
        state_change.hashlock,
        state_change.receiver,
        'payee_contract_withdraw',
    )

    iteration.events.extend(events)

    return iteration


def handle_unlock(mediator_state, state_change, channelidentifiers_to_channels):
    """ Handle a ReceiveUnlock state change. """
    events = list()
    balance_proof_sender = state_change.balance_proof.sender
    channel_identifier = state_change.balance_proof.channel_address

    for pair in mediator_state.transfers_pair:
        if pair.payer_transfer.balance_proof.sender == balance_proof_sender:
            channel_state = channelidentifiers_to_channels.get(channel_identifier)

            if channel_state:
                is_valid, _ = channel.handle_unlock(
                    channel_state,
                    state_change,
                )

                if is_valid:
                    withdraw = EventWithdrawSuccess(
                        pair.payee_transfer.identifier,
                        pair.payee_transfer.lock.hashlock,
                    )
                    events.append(withdraw)

                    pair.payer_state = 'payer_balance_proof'

    iteration = TransitionResult(mediator_state, events)
    return iteration


def state_transition2(mediator_state, state_change, channelidentifiers_to_channels, block_number):
    """ State machine for a node mediating a transfer. """
    # pylint: disable=too-many-branches
    # Notes:
    # - A user cannot cancel a mediated transfer after it was initiated, she
    #   may only reject to mediate before hand. This is because the mediator
    #   doesn't control the secret reveal and needs to wait for the lock
    #   expiration before safely discarding the transfer.

    iteration = TransitionResult(mediator_state, list())

    if isinstance(state_change, ActionInitMediator2):
        if mediator_state is None:
            iteration = handle_init(
                state_change,
                channelidentifiers_to_channels,
                block_number,
            )

    elif isinstance(state_change, Block):
        iteration = handle_block2(
            channelidentifiers_to_channels,
            mediator_state,
            state_change,
            block_number,
        )

    elif isinstance(state_change, ReceiveTransferRefund):
        iteration = handle_refundtransfer2(
            mediator_state,
            state_change,
            channelidentifiers_to_channels,
            block_number,
        )

    elif isinstance(state_change, ReceiveSecretReveal):
        iteration = handle_secretreveal2(
            mediator_state,
            state_change,
            channelidentifiers_to_channels,
            block_number,
        )

    elif isinstance(state_change, ContractReceiveChannelWithdraw):
        iteration = handle_contractwithdraw2(
            mediator_state,
            state_change,
            channelidentifiers_to_channels,
            block_number,
        )

    elif isinstance(state_change, ReceiveUnlock):
        iteration = handle_unlock(
            mediator_state,
            state_change,
            channelidentifiers_to_channels,
        )

    # this is the place for paranoia
    if iteration.new_state is not None:
        sanity_check2(iteration.new_state)

    return clear_if_finalized(iteration)
