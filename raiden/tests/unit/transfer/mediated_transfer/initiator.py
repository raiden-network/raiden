# -*- coding: utf8 -*-
import pytest

from raiden.utils import sha3
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import (
    RoutesState,
)
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    InitInitiator,
)
from raiden.transfer.mediated_transfer.events import (
    TransferFailed,
    MediatedTransfer,
)
from . import factories


class SequenceGenerator(object):
    """ Return a generator that goes thorugh the alphabet letters. """

    def __init__(self):
        import string
        import itertools

        self.secrets = list()
        self.generator = itertools.cycle(string.letters)

    def __iter__(self):
        return self

    def __next__(self):
        # pad the secret to the correct length by repeating the current character
        new_secret = next(self.generator) * 40
        self.secrets.append(new_secret)
        return new_secret

    next = __next__


def make_hashlock_transfer(amount,
                           target,
                           identifier=0,
                           token=factories.UNIT_TOKEN_ADDRESS):
    """ Helper for creating a hashlocked transfer.

    Args:
        amount (int): Amount of token being transferred.
        target (address): Transfer target.
        expiration (int): Block number
    """

    # the initiator machine populates this values
    secret = None
    hashlock = None
    expiration = None

    transfer = LockedTransferState(
        identifier,
        amount,
        token,
        target,
        expiration,
        hashlock,
        secret,
    )
    return transfer


def make_init_statechange(routes,
                          target,
                          amount=factories.UNIT_TRANSFER_AMOUNT,
                          block_number=1,
                          our_address=factories.ADDR,
                          secret_generator=None):

    if secret_generator is None:
        secret_generator = SequenceGenerator()

    init_state_change = InitInitiator(
        our_address,
        make_hashlock_transfer(amount, target=target),
        RoutesState(routes),
        secret_generator,
        block_number,
    )

    return init_state_change


def make_initiator_state(routes,
                         target,
                         amount=factories.UNIT_TRANSFER_AMOUNT,
                         block_number=1,
                         our_address=factories.ADDR,
                         secret_generator=None):

    init_state_change = make_init_statechange(
        routes,
        target,
        amount,
        block_number,
        our_address,
        secret_generator,
    )

    inital_state = None
    iteration = initiator.state_transition(inital_state, init_state_change)

    return iteration.new_state


def test_next_route():
    target = factories.HOP1
    routes = [
        factories.make_route(factories.HOP2, available_balance=factories.UNIT_TRANSFER_AMOUNT),
        factories.make_route(factories.HOP3, available_balance=factories.UNIT_TRANSFER_AMOUNT - 1),
        factories.make_route(factories.HOP4, available_balance=factories.UNIT_TRANSFER_AMOUNT),
    ]

    state = make_initiator_state(routes, target)

    assert state.route == routes[0], 'a initialized state must be in use and with the first route in use'

    assert state.routes.available_routes == routes[1:]
    assert len(state.routes.ignored_routes) == 0
    assert len(state.routes.refunded_routes) == 0
    assert len(state.routes.canceled_routes) == 0

    with pytest.raises(AssertionError, message='cannot try a new route while one is in use'):
        initiator.try_new_route(state)

    state.routes.canceled_routes.append(state.route)
    state.route = None
    initiator.try_new_route(state)

    # HOP3 should be ignored because it doesnt have enough balance
    assert len(state.routes.ignored_routes) == 1

    assert len(state.routes.available_routes) == 0
    assert len(state.routes.refunded_routes) == 0
    assert len(state.routes.canceled_routes) == 1


def test_init_with_usable_routes():
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR
    secret_generator = SequenceGenerator()

    routes = [factories.make_route(mediator_address, available_balance=amount)]
    init_state_change = make_init_statechange(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=secret_generator,
    )

    expiration = block_number + factories.HOP1_TIMEOUT

    initiator_state_machine = StateManager(
        initiator.state_transition,
        None,
    )

    assert initiator_state_machine.current_state is None

    events = initiator_state_machine.dispatch(
        init_state_change,
    )

    initiator_state = initiator_state_machine.current_state
    assert isinstance(initiator_state, InitiatorState)
    assert initiator_state.our_address == our_address

    transfer = initiator_state.transfer
    assert isinstance(transfer, LockedTransferState)
    assert transfer.amount == amount
    assert transfer.target == target_address
    assert transfer.secret == secret_generator.secrets[0]
    assert transfer.hashlock == sha3(transfer.secret)

    assert len(events), 'we have a valid route, the mediated transfer event must be emited'

    mediated_transfers = [
        e for e in events
        if isinstance(e, MediatedTransfer)
    ]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    mediated_transfer = mediated_transfers[0]

    assert mediated_transfer.token == factories.UNIT_TOKEN_ADDRESS, 'transfer token address mismatch'
    assert mediated_transfer.amount == amount, 'transfer amount mismatch'
    assert mediated_transfer.expiration == expiration, 'transfer expiration mismatch'
    assert mediated_transfer.hashlock == sha3(secret_generator.secrets[0]), 'wrong hashlock'
    assert mediated_transfer.node_address == mediator_address, 'wrong mediator address'

    assert initiator_state.route == routes[0]
    assert len(initiator_state.routes.available_routes) == 0
    assert len(initiator_state.routes.ignored_routes) == 0
    assert len(initiator_state.routes.refunded_routes) == 0
    assert len(initiator_state.routes.canceled_routes) == 0


def test_init_without_routes():
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    our_address, target_address = factories.HOP1, factories.HOP3
    routes = []

    transfer = make_hashlock_transfer(
        amount,
        target=target_address,
    )
    init_state_change = InitInitiator(
        our_address,
        transfer,
        RoutesState(routes),
        SequenceGenerator(),
        block_number,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        None,
    )

    assert initiator_state_machine.current_state is None

    events = initiator_state_machine.dispatch(
        init_state_change,
    )

    assert len(events) == 1
    assert isinstance(events[0], TransferFailed)
    assert initiator_state_machine.current_state is None
