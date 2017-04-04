# -*- coding: utf8 -*-
# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
from copy import deepcopy

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
from raiden.transfer.state_change import (
    ActionCancelTransfer,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveTransferRefund,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
)
from raiden.transfer.mediated_transfer.events import (
    EventTransferCompleted,
    EventTransferFailed,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRevealSecret,
)
from . import factories


class SequenceGenerator(object):
    """ Return a generator that goes through the alphabet letters. """
    def __init__(self):
        self.i = 0
        self.secrets = list()

    def __iter__(self):
        return self

    def __next__(self):
        # pad the secret to the correct length by repeating the current character
        import string
        new_secret = string.letters[self.i % len(string.letters)] * 40
        self.secrets.append(new_secret)
        return new_secret

    next = __next__


def make_init_statechange(
        routes,
        target,
        amount=factories.UNIT_TRANSFER_AMOUNT,
        block_number=1,
        our_address=factories.ADDR,
        secret_generator=None,
        identifier=0,
        token=factories.UNIT_TOKEN_ADDRESS):

    if secret_generator is None:
        secret_generator = SequenceGenerator()

    transfer = factories.make_transfer(
        amount,
        initiator=our_address,
        target=target,
        identifier=identifier,
        token=token,
        secret=None,
        hashlock=None,
        expiration=None,
    )

    init_state_change = ActionInitInitiator(
        our_address,
        transfer,
        RoutesState(routes),
        secret_generator,
        block_number,
    )

    return init_state_change


def make_initiator_state(
        routes,
        target,
        amount=factories.UNIT_TRANSFER_AMOUNT,
        block_number=1,
        our_address=factories.ADDR,
        secret_generator=None,
        identifier=0,
        token=factories.UNIT_TOKEN_ADDRESS):

    init_state_change = make_init_statechange(
        routes,
        target,
        amount,
        block_number,
        our_address,
        secret_generator,
        identifier=identifier,
        token=token,
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

    assert state.route == routes[0], 'a initialized state must use the first valid route'

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
        if isinstance(e, SendMediatedTransfer)
    ]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    mediated_transfer = mediated_transfers[0]

    assert mediated_transfer.token == factories.UNIT_TOKEN_ADDRESS
    assert mediated_transfer.amount == amount, 'transfer amount mismatch'
    assert mediated_transfer.expiration == expiration, 'transfer expiration mismatch'
    assert mediated_transfer.hashlock == sha3(secret_generator.secrets[0]), 'wrong hashlock'
    assert mediated_transfer.receiver == mediator_address, 'wrong mediator address'

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

    transfer = factories.make_transfer(
        amount,
        initiator=our_address,
        target=target_address,
        secret=None,
        hashlock=None,
        expiration=None,
    )
    init_state_change = ActionInitInitiator(
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
    assert isinstance(events[0], EventTransferFailed)
    assert initiator_state_machine.current_state is None


def test_state_wait_secretrequest_valid():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR

    routes = [factories.make_route(mediator_address, available_balance=amount)]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=SequenceGenerator(),
        identifier=identifier,
    )

    hashlock = current_state.transfer.hashlock

    state_change = ReceiveSecretRequest(
        identifier=identifier,
        amount=amount,
        hashlock=hashlock,
        sender=target_address,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )

    events = initiator_state_machine.dispatch(state_change)
    assert all(isinstance(event, SendRevealSecret) for event in events)
    assert len(events) == 1


def test_state_wait_unlock_valid():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR
    secret_generator = SequenceGenerator()
    token = factories.UNIT_TOKEN_ADDRESS

    routes = [factories.make_route(mediator_address, available_balance=amount)]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=secret_generator,
        identifier=identifier,
        token=token,
    )

    secret = secret_generator.secrets[0]
    assert secret is not None

    # setup the state for the wait unlock
    current_state.revealsecret = SendRevealSecret(
        identifier,
        secret,
        token,
        target_address,
        our_address,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )

    state_change = ReceiveSecretReveal(
        secret=secret,
        sender=mediator_address,
    )
    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 2

    # The initiator must send a synchronizing message to its partner
    assert any(isinstance(e, SendBalanceProof) for e in events)
    # Once the transfer is completed a notifying event must be emitted
    assert any(isinstance(e, EventTransferCompleted) for e in events)

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof))
    complete = next(e for e in events if isinstance(e, EventTransferCompleted))

    assert balance_proof.receiver == mediator_address
    assert complete.identifier == identifier
    assert initiator_state_machine.current_state is None, 'state must be cleaned'


def test_state_wait_unlock_invalid():
    identifier = identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR
    secret_generator = SequenceGenerator()
    token = factories.UNIT_TOKEN_ADDRESS

    routes = [factories.make_route(mediator_address, available_balance=amount)]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=secret_generator,
        token=token,
    )

    secret = secret_generator.secrets[0]
    assert secret is not None

    current_state.revealsecret = SendRevealSecret(
        identifier,
        secret,
        token,
        target_address,
        our_address,
    )

    before_state = deepcopy(current_state)

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )

    state_change = ReceiveSecretReveal(
        secret=secret,
        sender=factories.ADDR,
    )
    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 0
    assert initiator_state_machine.current_state.revealsecret is not None
    assert_state_equal(initiator_state_machine.current_state, current_state)
    assert_state_equal(current_state, before_state)


def test_refund_transfer_next_route():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR

    routes = [
        factories.make_route(mediator_address, available_balance=amount),
        factories.make_route(factories.HOP2, available_balance=amount),
    ]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=SequenceGenerator(),
        identifier=identifier,
    )

    transfer = factories.make_transfer(
        amount,
        our_address,
        target_address,
        block_number + factories.UNIT_SETTLE_TIMEOUT,
    )

    state_change = ReceiveTransferRefund(
        sender=mediator_address,
        transfer=transfer,
    )

    prior_state = deepcopy(current_state)

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )
    assert initiator_state_machine.current_state is not None

    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 1
    assert isinstance(events[0], SendMediatedTransfer)
    assert initiator_state_machine.current_state is not None
    assert initiator_state_machine.current_state.routes.canceled_routes[0] == prior_state.route


def test_refund_transfer_no_more_routes():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR

    routes = [
        factories.make_route(mediator_address, available_balance=amount),
    ]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=SequenceGenerator(),
        identifier=identifier,
    )

    transfer = factories.make_transfer(
        amount,
        our_address,
        target_address,
        block_number + factories.UNIT_SETTLE_TIMEOUT,
    )

    state_change = ReceiveTransferRefund(
        sender=mediator_address,
        transfer=transfer,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )
    assert initiator_state_machine.current_state is not None

    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 1
    assert isinstance(events[0], EventTransferFailed)
    assert initiator_state_machine.current_state is None


def test_refund_transfer_invalid_sender():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR

    routes = [
        factories.make_route(mediator_address, available_balance=amount),
    ]
    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=SequenceGenerator(),
        identifier=identifier,
    )

    transfer = factories.make_transfer(
        amount,
        our_address,
        target_address,
        block_number + factories.UNIT_SETTLE_TIMEOUT,
    )

    state_change = ReceiveTransferRefund(
        sender=our_address,
        transfer=transfer,
    )

    prior_state = deepcopy(current_state)

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )
    assert initiator_state_machine.current_state is not None

    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 0
    assert initiator_state_machine.current_state is not None
    assert_state_equal(initiator_state_machine.current_state, prior_state)


def test_cancel_transfer():
    identifier = 1
    amount = factories.UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = factories.HOP1
    target_address = factories.HOP2
    our_address = factories.ADDR

    routes = [
        factories.make_route(mediator_address, available_balance=amount),
    ]

    current_state = make_initiator_state(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=SequenceGenerator(),
        identifier=identifier,
    )

    state_change = ActionCancelTransfer(
        identifier=identifier
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        current_state,
    )
    assert initiator_state_machine.current_state is not None

    events = initiator_state_machine.dispatch(state_change)
    assert len(events) == 1
    assert isinstance(events[0], EventTransferFailed)
    assert initiator_state_machine.current_state is None


def assert_state_equal(state1, state2):
    """ Weak equality check between two InitiatorState instances """
    assert state1.__class__ == state2.__class__
    assert state1.our_address == state2.our_address
    assert state1.block_number == state2.block_number
    assert state1.routes == state2.routes
    assert state1.route == state2.route
    assert state1.transfer == state2.transfer
    assert state1.random_generator.secrets == state2.random_generator.secrets
    assert state1.canceled_transfers == state2.canceled_transfers
