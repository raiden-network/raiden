# -*- coding: utf-8 -*-
# pylint: disable=invalid-name,too-many-locals,too-many-arguments
from __future__ import division

from raiden.transfer.architecture import StateManager
from raiden.transfer.state import (
    RoutesState,
)
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    LockedTransferState,
    MediationPairState,
    MediatorState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
)
from raiden.transfer.mediated_transfer.events import (
    SendMediatedTransfer,
    SendRefundTransfer,
)
from . import factories


def make_init_statechange(from_transfer,
                          routes,
                          from_route,
                          our_address=factories.ADDR):

    block_number = 1
    init_state_change = ActionInitMediator(
        our_address,
        from_transfer,
        RoutesState(routes),
        from_route,
        block_number,
    )
    return init_state_change


def make_transfer(amount,
                  target,
                  expiration,
                  secret=None,
                  hashlock=factories.UNIT_HASHLOCK,
                  identifier=1):

    if secret is not None:
        assert factories.sha3(secret) == hashlock

    transfer = LockedTransferState(
        identifier,
        amount,
        factories.UNIT_TOKEN_ADDRESS,
        target,
        expiration,
        hashlock=hashlock,
        secret=secret,
    )
    return transfer


def make_from(amount, target, from_expiration):
    from_route = factories.make_route(
        factories.HOP1,
        available_balance=amount,
    )

    from_transfer = make_transfer(
        amount,
        target,
        from_expiration,
        identifier=0,
    )

    return from_route, from_transfer


def make_transfer_pairs(hops,
                        target,
                        amount,
                        secret=None,
                        initial_expiration=None,
                        reveal_timeout=factories.UNIT_REVEAL_TIMEOUT):

    if initial_expiration is None:
        initial_expiration = (1 + len(hops)) * reveal_timeout

    expiration = initial_expiration
    transfers_pair = list()

    for payer, payee in zip(hops[:-1], hops[1:]):
        assert expiration > 0

        # regardless of the secret being known, the payee_state and payer_state
        # need to be in their initial state.
        pair = MediationPairState(
            factories.make_route(payer, amount),
            make_transfer(amount, target, expiration, secret=secret),
            factories.make_route(payee, amount),
            make_transfer(amount, target, expiration, secret=secret),
        )
        transfers_pair.append(pair)

        expiration -= reveal_timeout

    return transfers_pair


def test_is_lock_valid():
    """ A hash time lock is valid up to the expiraiton block. """
    amount = 10
    expiration = 10
    transfer = make_transfer(amount, factories.HOP1, expiration)

    assert mediator.is_lock_valid(5, transfer) is True
    assert mediator.is_lock_valid(10, transfer) is True, 'lock is expired at the next block'
    assert mediator.is_lock_valid(11, transfer) is False


def test_is_safe_to_wait():
    """ It's safe to wait for a secret while there are more than reveal timeout
    blocks until the lock expiration.
    """
    amount = 10
    expiration = 40
    transfer = make_transfer(amount, factories.HOP1, expiration)

    # expiration is in 30 blocks, 19 blocks safe for waiting
    block_number = 10
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is True

    # expiration is in 30 blocks, 09 blocks safe for waiting
    block_number = 20
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is True

    # expiration is in 30 blocks, 1 block safe for waiting
    block_number = 29
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is True

    # at the block 30 it's not safe to wait anymore
    block_number = 30
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is False

    block_number = 40
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is False

    block_number = 50
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(block_number, transfer, reveal_timeout) is False


def test_is_valid_refund():
    target = factories.HOP1
    valid_sender = factories.HOP2

    transfer = LockedTransferState(
        identifier=20,
        amount=30,
        token=factories.UNIT_TOKEN_ADDRESS,
        target=target,
        expiration=50,
        hashlock=factories.UNIT_HASHLOCK,
        secret=None,
    )

    refund_lower_expiration = LockedTransferState(
        identifier=20,
        amount=30,
        token=factories.UNIT_TOKEN_ADDRESS,
        target=target,
        expiration=35,
        hashlock=factories.UNIT_HASHLOCK,
        secret=None,
    )

    assert mediator.is_valid_refund(transfer, valid_sender, refund_lower_expiration) is True

    # target cannot refund
    assert mediator.is_valid_refund(transfer, target, refund_lower_expiration) is False

    refund_same_expiration = LockedTransferState(
        identifier=20,
        amount=30,
        token=factories.UNIT_TOKEN_ADDRESS,
        target=factories.HOP1,
        expiration=50,
        hashlock=factories.UNIT_HASHLOCK,
        secret=None,
    )
    assert mediator.is_valid_refund(transfer, valid_sender, refund_same_expiration) is False


def test_get_timeout_blocks():
    amount = 10
    address = factories.HOP1

    settle_timeout = 30
    block_number = 5

    route = factories.make_route(
        address,
        amount,
        settle_timeout=settle_timeout,
    )

    early_expire = 10
    early_transfer = make_transfer(amount, address, early_expire)
    early_block = mediator.get_timeout_blocks(route, early_transfer, block_number)
    assert early_block == 5 - mediator.TRANSIT_BLOCKS, 'must use the lock expiration'

    equal_expire = 30
    equal_transfer = make_transfer(amount, address, equal_expire)
    equal_block = mediator.get_timeout_blocks(route, equal_transfer, block_number)
    assert equal_block == 25 - mediator.TRANSIT_BLOCKS

    large_expire = 70
    large_transfer = make_transfer(amount, address, large_expire)
    large_block = mediator.get_timeout_blocks(route, large_transfer, block_number)
    assert large_block == 30 - mediator.TRANSIT_BLOCKS, 'must use the settle timeout'

    closed_route = factories.make_route(
        address,
        amount,
        settle_timeout=settle_timeout,
        close_block=2,
    )

    large_block = mediator.get_timeout_blocks(closed_route, large_transfer, block_number)
    assert large_block == 27 - mediator.TRANSIT_BLOCKS, 'must use the close block'

    # the computed timeout may be negative, in which case the calling code must /not/ use it
    negative_block_number = large_expire
    negative_block = mediator.get_timeout_blocks(route, large_transfer, negative_block_number)
    assert negative_block == -mediator.TRANSIT_BLOCKS


def test_next_route_amount():
    """ Routes that dont have enough available_balance must be ignored. """
    amount = 10
    reveal_timeout = 30
    timeout_blocks = reveal_timeout + 10
    routes = [
        factories.make_route(
            factories.HOP2,
            available_balance=amount * 2,
            reveal_timeout=reveal_timeout,
        ),
        factories.make_route(
            factories.HOP1,
            available_balance=amount + 1,
            reveal_timeout=reveal_timeout,
        ),
        factories.make_route(
            factories.HOP3,
            available_balance=amount // 2,
            reveal_timeout=reveal_timeout,
        ),
        factories.make_route(
            factories.HOP4,
            available_balance=amount,
            reveal_timeout=reveal_timeout,
        ),
    ]

    routes_state = RoutesState(list(routes))  # copy because the list will be modified inplace

    route1 = mediator.next_route(routes_state, timeout_blocks, amount)
    assert route1 == routes[0]
    assert routes_state.available_routes == routes[1:]
    assert routes_state.ignored_routes == list()

    route2 = mediator.next_route(routes_state, timeout_blocks, amount)
    assert route2 == routes[1]
    assert routes_state.available_routes == routes[2:]
    assert routes_state.ignored_routes == list()

    route3 = mediator.next_route(routes_state, timeout_blocks, amount)
    assert route3 == routes[3]
    assert routes_state.available_routes == list()
    assert routes_state.ignored_routes == [routes[2]]

    assert mediator.next_route(routes_state, timeout_blocks, amount) is None


def test_next_route_reveal_timeout():
    """ Routes with a larger reveal timeout than timeout_blocks must be ignored. """
    amount = 10
    balance = 20
    timeout_blocks = 10
    routes = [
        factories.make_route(
            factories.HOP1,
            available_balance=balance,
            reveal_timeout=timeout_blocks * 2,
        ),
        factories.make_route(
            factories.HOP2,
            available_balance=balance,
            reveal_timeout=timeout_blocks + 1,
        ),
        factories.make_route(
            factories.HOP3,
            available_balance=balance,
            reveal_timeout=timeout_blocks // 2,
        ),
        factories.make_route(
            factories.HOP4,
            available_balance=balance,
            reveal_timeout=timeout_blocks,
        ),
    ]

    routes_state = RoutesState(list(routes))  # copy because the list will be modified inplace
    route1 = mediator.next_route(routes_state, timeout_blocks, amount)
    assert route1 == routes[2]
    assert routes_state.available_routes == [routes[3], ]
    assert routes_state.ignored_routes == [routes[0], routes[1]]

    assert mediator.next_route(routes_state, timeout_blocks, amount) is None
    assert routes_state.available_routes == list()
    assert routes_state.ignored_routes == [routes[0], routes[1], routes[3]]


def test_next_transfer_pair():
    timeout_blocks = 47
    block_number = 3
    balance = 10

    payer_route = factories.make_route(factories.HOP1, balance)
    payer_transfer = make_transfer(balance, factories.ADDR, expiration=50)

    routes = [
        factories.make_route(factories.HOP2, available_balance=balance),
    ]
    routes_state = RoutesState(list(routes))  # copy because the list will be modified inplace

    pair, events = mediator.next_transfer_pair(
        payer_route,
        payer_transfer,
        routes_state,
        timeout_blocks,
        block_number,
    )

    assert pair.payer_route == payer_route
    assert pair.payer_transfer == payer_transfer
    assert pair.payee_route == routes[0]
    assert pair.payee_transfer.expiration < pair.payer_transfer.expiration

    assert isinstance(events[0], SendMediatedTransfer)
    assert len(routes_state.available_routes) == 0


def test_set_secret():
    amount = 10
    block_number = 7
    routes = []
    routes_state = RoutesState(routes)

    state = MediatorState(
        factories.ADDR,
        routes_state,
        block_number,
        factories.UNIT_HASHLOCK,
    )

    state.transfers_pair = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount,
    )

    mediator.set_secret(state, factories.UNIT_SECRET)
    assert state.secret == factories.UNIT_SECRET

    for pair in state.transfers_pair:
        assert pair.payer_transfer.secret == factories.UNIT_SECRET
        assert pair.payee_transfer.secret == factories.UNIT_SECRET


def test_set_payee():
    transfers_pair = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount=10,
    )

    # assert pre conditions
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_payee_state_and_check_reveal_order(
        transfers_pair,
        factories.HOP1,
        'payee_secret_revealed',
    )

    # payer address was used, no payee state should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_payee_state_and_check_reveal_order(
        transfers_pair,
        factories.HOP2,
        'payee_secret_revealed',
    )

    # only the transfer where the address is a payee should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_secret_revealed'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'


def test_events_for_refund():
    amount = 10
    expiration = 30
    reveal_timeout = 17
    timeout_blocks = expiration
    block_number = 1

    refund_route = factories.make_route(
        factories.HOP1,
        amount,
        reveal_timeout=reveal_timeout,
    )

    refund_transfer = make_transfer(
        amount,
        factories.HOP6,
        expiration,
    )

    small_timeout_blocks = reveal_timeout
    small_refund_events = mediator.events_for_refund_transfer(
        refund_route,
        refund_transfer,
        small_timeout_blocks,
        block_number,
    )
    assert len(small_refund_events) == 0

    refund_events = mediator.events_for_refund_transfer(
        refund_route,
        refund_transfer,
        timeout_blocks,
        block_number,
    )
    assert refund_events[0].expiration < block_number + timeout_blocks
    assert refund_events[0].amount == amount
    assert refund_events[0].hashlock == refund_transfer.hashlock
    assert refund_events[0].node_address == refund_route.node_address


def test_events_for_revealsecret():
    """ The secret is revealed backwards to the payer once the payee sent the
    SecretReveal.
    """
    secret = factories.UNIT_SECRET
    our_address = factories.ADDR

    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount=10,
        secret=secret,
    )

    events = mediator.events_for_revealsecret(
        transfer_pairs,
        our_address,
    )

    # the secret is known by this node, but no other payee is at a secret known
    # state, do nothing
    assert len(events) == 0

    first_pair = transfer_pairs[0]
    last_pair = transfer_pairs[1]

    last_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret(
        transfer_pairs,
        our_address,
    )

    # the last known hop sent a secret reveal message, this node learned the
    # secret and now must reveal to the payer node from the transfer pair
    assert len(events) == 1
    assert events[0].secret == secret
    assert events[0].target == last_pair.payer_route.node_address
    assert last_pair.payer_state == 'payer_secret_revealed'

    events = mediator.events_for_revealsecret(
        transfer_pairs,
        our_address,
    )

    # the payeee from the first_pair did not send a secret reveal message, do
    # nothing
    assert len(events) == 0

    first_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret(
        transfer_pairs,
        our_address,
    )

    assert len(events) == 1
    assert events[0].secret == secret
    assert events[0].target == first_pair.payer_route.node_address
    assert first_pair.payer_state == 'payer_secret_revealed'


def test_events_for_revealsecret_secret_unknown():
    """ When the secret is not know there is nothing to do. """
    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount=10,
    )

    events = mediator.events_for_revealsecret(
        transfer_pairs,
        factories.ADDR,
    )

    assert len(events) == 0


def test_events_for_revealsecret_all_states():
    """ The secret must be revealed backwards to the payer if the payee knows
    the secret.
    """
    secret = factories.UNIT_SECRET
    our_address = factories.ADDR

    payee_secret_known = (
        'payee_secret_revealed',
        'payee_refund_withdraw',
        'payee_contract_withdraw',
        'payee_balance_proof',
    )

    for state in payee_secret_known:
        transfer_pairs = make_transfer_pairs(
            [factories.HOP1, factories.HOP2],
            factories.HOP6,
            amount=10,
            secret=secret,
        )

        pair = transfer_pairs[0]
        pair.payee_state = state

        events = mediator.events_for_revealsecret(
            transfer_pairs,
            our_address,
        )

        assert events[0].secret == secret
        assert events[0].target == factories.HOP1


def test_events_for_balancaproof():
    """ Test the simple case were the last hop has learned the secret and sent
    to the mediator node.
    """
    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2],
        factories.HOP6,
        amount=10,
        secret=factories.UNIT_SECRET,
    )

    last_pair = transfer_pairs[-1]
    last_pair.payee_state = 'payee_secret_revealed'

    # the lock has not expired yet
    block_number = last_pair.payee_transfer.expiration

    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )

    assert len(events) == 1
    assert events[0].target == last_pair.payee_route.node_address


def test_events_for_balanceproof_channel_closed():
    """ Balance proofs are useless if the channel is closed/settled, the payee
    needs to go on-chain and use the latest known balance proof which includes
    this lock in the locksroot.
    """

    for invalid_state in ('closed', 'settled'):
        transfer_pairs = make_transfer_pairs(
            [factories.HOP1, factories.HOP2],
            factories.HOP6,
            amount=10,
            secret=factories.UNIT_SECRET,
        )

        block_number = 5
        last_pair = transfer_pairs[-1]
        last_pair.payee_route.state = invalid_state
        last_pair.payee_route.close_block = block_number
        last_pair.payee_state = 'payee_secret_revealed'

        events = mediator.events_for_balanceproof(
            transfer_pairs,
            block_number,
        )

        assert len(events) == 0


def test_events_for_balanceproof_middle_secret():
    """ Even though the secret should only propagate from the end of the chain
    to the front, if there is a payee node in the middle that knows the secret
    the Balance Proof is sent neverthless.

    This can be done safely because the secret is know to the mediator and
    there is reveal_timeout blocks to withdraw the lock on-chain with the payer.
    """
    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3, factories.HOP4],
        factories.HOP6,
        amount=10,
        secret=factories.UNIT_SECRET,
    )

    block_number = 1
    middle_pair = transfer_pairs[1]
    middle_pair.payee_state = 'payee_secret_revealed'

    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )

    assert len(events) == 1
    assert events[0].target == middle_pair.payee_route.node_address


def test_events_for_balanceproof_secret_unknow():
    """ Nothing to do if the secret is not known. """
    block_number = 1

    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount=10,
    )

    # the secret is not known, so no event should be used
    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )
    assert len(events) == 0

    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3],
        factories.HOP6,
        amount=10,
        secret=factories.UNIT_SECRET,
    )

    # Even though the secret is set, there is not a single transfer pair with a
    # 'secret known' state, so nothing should be done. This state is impossible
    # to reach, in reality someone needs to reveal the secret to the mediator,
    # so at least one other node knows the secret.
    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )
    assert len(events) == 0


def test_events_for_balanceproof_lock_expired():
    """ The balance proof should not be sent if the lock has expird. """
    transfer_pairs = make_transfer_pairs(
        [factories.HOP1, factories.HOP2, factories.HOP3, factories.HOP4],
        factories.HOP6,
        amount=10,
        secret=factories.UNIT_SECRET,
    )

    last_pair = transfer_pairs[-1]
    last_pair.payee_state = 'payee_secret_revealed'
    block_number = last_pair.payee_transfer.expiration + 1

    # the lock has expired, do not send a balance proof
    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )
    assert len(events) == 0

    middle_pair = transfer_pairs[-2]
    middle_pair.payee_state = 'payee_secret_revealed'

    # Even though the last node did not receive the payment we should send the
    # balance proof to the middle node to avoid unnecessarely closing the
    # middle channel. This state should not be reached under normal operation,
    # the last hop needs to choose a proper reveal_timeout and must go on-chain
    # to withdraw the asset before the lock expires.
    events = mediator.events_for_balanceproof(
        transfer_pairs,
        block_number,
    )
    assert len(events) == 1
    assert events[0].target == middle_pair.payee_route.node_address


def test_init_mediator():
    from_route, from_transfer = make_from(
        amount=factories.UNIT_TRANSFER_AMOUNT,
        target=factories.HOP2,
        from_expiration=factories.HOP1_TIMEOUT,
    )

    routes = [
        factories.make_route(factories.HOP2, available_balance=factories.UNIT_TRANSFER_AMOUNT),
    ]

    init_state_change = make_init_statechange(
        from_transfer,
        routes,
        from_route,
    )

    mediator_state_machine = StateManager(
        mediator.state_transition,
        None,
    )

    assert mediator_state_machine.current_state is None

    events = mediator_state_machine.dispatch(
        init_state_change,
    )

    mediator_state = mediator_state_machine.current_state
    assert isinstance(mediator_state, MediatorState)
    assert mediator_state.our_address == factories.ADDR
    assert mediator_state.block_number == init_state_change.block_number
    assert mediator_state.transfers_pair[0].payer_transfer == from_transfer
    assert mediator_state.transfers_pair[0].payer_route == from_route

    assert len(events), 'we have a valid route, the mediated transfer event must be emited'

    mediated_transfers = [
        e for e in events
        if isinstance(e, SendMediatedTransfer)
    ]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    mediated_transfer = mediated_transfers[0]

    assert mediated_transfer.token == from_transfer.token, 'transfer token address mismatch'
    assert mediated_transfer.amount == from_transfer.amount, 'transfer amount mismatch'
    assert mediated_transfer.expiration < from_transfer.expiration, 'transfer expiration mismatch'
    assert mediated_transfer.hashlock == from_transfer.hashlock, 'wrong hashlock'


def test_no_valid_routes():
    from_route, from_transfer = make_from(
        amount=factories.UNIT_TRANSFER_AMOUNT,
        target=factories.HOP2,
        from_expiration=factories.HOP1_TIMEOUT,
    )

    routes = [
        factories.make_route(factories.HOP2, available_balance=factories.UNIT_TRANSFER_AMOUNT - 1),
        factories.make_route(factories.HOP3, available_balance=1),
    ]

    init_state_change = make_init_statechange(
        from_transfer,
        routes,
        from_route,
    )

    mediator_state_machine = StateManager(
        mediator.state_transition,
        None,
    )

    assert mediator_state_machine.current_state is None

    events = mediator_state_machine.dispatch(
        init_state_change,
    )

    assert mediator_state_machine.current_state is None

    assert len(events) == 1
    assert isinstance(events[0], SendRefundTransfer)


def test_lock_timeout_lower_than_previous_channel_settlement_period():
    # For a path A-B-C, B cannot forward a mediated transfer to C with
    # a lock timeout larger than the settlement timeout of the A-B
    # channel.
    #
    # Consider that an attacker controls both nodes A and C:
    #
    # Channels A <-> B and B <-> C have a settlement=10 and B has a
    # reveal_timeout=5
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=20-5]
    # (block=1) A close channel A-B
    # (block=5) C close channel B-C (waited until lock_expiration=settle_timeout)
    # (block=11) A call settle on channel A-B (settle_timeout is over)
    # (block=12) C call unlock on channel B-C (lock is still valid)
    #
    # If B used min(lock.expiration, previous_channel.settlement)
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=min(20,10)-5]
    # (block=1) A close channel A-B
    # (block=4) C close channel B-C (waited all possible blocks)
    # (block=5) C call unlock on channel B-C (C is forced to unlock)
    # (block=6) B learns the secret
    # (block=7) B call unlock on channel A-B (settle_timeout is over)
    pass


def test_do_not_withdraw_an_almost_expiring_lock_if_a_payment_didnt_occur():
    # For a path A1-B-C-A2, an attacker controlling A1 and A2 should not be
    # able to force B-C to close the channel by burning token.
    #
    # The attack would be as follows:
    #
    # - Attacker uses two nodes to open two really cheap channels A1 <-> B and
    #   node A2 <-> C
    # - Attacker sends a mediated message with the lowest possible token
    #   amount from A1 through B and C to A2
    # - Since the attacker controls A1 and A2 it knows the secret, she can choose
    #   when the secret is revealed
    # - The secret is hold back until the hash time lock B->C is almost expiring,
    #   then it's revealed (meaning that the attacker is losing token, that's why
    #   it's using the lowest possible amount)
    # - C wants the token from B, it will reveal the secret and close the channel
    #   (because it must assume the balance proof won't make in time and it needs
    #   to unlock on-chain)
    #
    # Mitigation:
    #
    # - C should only close the channel B-C if he has paid A2, since this may
    #   only happen if the lock for the transfer C-A2 has not yet expired then C
    #   has enough time to follow the protocol without closing the channel B-C.
    pass


def mediate_transfer_payee_timeout_must_be_lower_than_settlement_and_payer_timeout():
    # Test:
    # - the current payer route/transfer is the reference, not the from_route / from_transfer
    # - the lowest value from blocks_until_settlement and lock expiration must be used
    pass


def payee_timeout_must_be_lower_than_payer_timeout_minus_reveal_timeout():
    # The payee could reveal the secret on it's lock expiration block, the
    # mediator node will respond with a balance-proof to the payee since the
    # lock is valid and the mediator can safely get the token from the payer,
    # the secret is know and if there are no additional blocks the mediator
    # will be at risk of not being able to withdraw on-chain, so the channel
    # will be closed to safely withdraw.
    #
    # T2.expiration cannot be equal to T1.expiration - reveal_timeout:
    #
    # T1 |---|
    # T2     |---|
    #        ^- reveal the secret
    #        T1.expiration - reveal_timeout == current_block -> withdraw on chain
    #
    # If T2.expiration canot be equal to T1.expiration - reveal_timeout minus ONE:
    #
    # T1 |---|
    # T2      |---|
    #         ^- reveal the secret
    #
    # Race:
    #  1> Secret is learned
    #  2> balance-proof is sent to payee (payee transfer is payed)
    #  3! New block is mined and Raiden learns about it
    #  4> Now the secret is know, the payee is payed, and the current block is
    #     equal to the payer.expiration - reveal-timeout -> withdraw on chain
    #
    # The race is depending on the handling of 3 before 4.
    #
    pass
