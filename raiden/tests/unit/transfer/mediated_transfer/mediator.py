# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import (
    RoutesState,
)
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    MediatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    InitMediator,
)
from raiden.transfer.mediated_transfer.events import (
    MediatedTransfer,
    RefundTransfer,
)
from . import factories


def make_init_statechange(from_transfer,
                          routes,
                          from_route,
                          our_address=factories.ADDR):

    block_number = 1
    init_state_change = InitMediator(
        our_address,
        from_transfer,
        RoutesState(routes),
        from_route,
        block_number,
    )
    return init_state_change


def make_from(amount, target, from_expiration):
    from_route = factories.make_route(
        factories.HOP1,
        available_balance=amount,
    )

    identifier = 0
    from_transfer = LockedTransferState(
        identifier,
        amount,
        factories.UNIT_TOKEN_ADDRESS,
        target,
        from_expiration,
        hashlock=factories.UNIT_HASHLOCK,
        secret=None,
    )

    return from_route, from_transfer


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
    assert mediator_state.from_transfer == from_transfer
    assert mediator_state.block_number == init_state_change.block_number
    assert mediator_state.from_route == from_route

    assert len(events), 'we have a valid route, the mediated transfer event must be emited'

    mediated_transfers = [
        e for e in events
        if isinstance(e, MediatedTransfer)
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

    mediator_state = mediator_state_machine.current_state

    assert len(mediator_state.routes.available_routes) == 0
    assert len(mediator_state.routes.refunded_routes) == 0
    assert len(mediator_state.routes.canceled_routes) == 0
    assert len(mediator_state.routes.ignored_routes) == 2

    assert mediator_state.route is None
    assert mediator_state.message is None

    assert len(events) == 1
    assert isinstance(events[0], RefundTransfer)


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
