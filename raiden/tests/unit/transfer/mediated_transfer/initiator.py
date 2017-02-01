# -*- coding: utf8 -*-
import pytest

from raiden.utils import sha3
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import RoutesState, RouteState
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state_change import (
    # blockchain events
    Blocknumber,
    RouteChange,
    # user interaction
    CancelTransfer,
)
from raiden.transfer.mediated_transfer.state_change import (
    # machine state
    InitInitiator,
    # protocol messages
    TransferRefundReceived,
    SecretRequestReceived,
    SecretRevealReceived,
)
from raiden.transfer.mediated_transfer.events import (
    TransferFailed,
    MediatedTransfer,
    RevealSecretTo,
)

# prefixing with UNIT_ to differ from the default globals
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TOKEN_ADDRESS = 'tokentokentokentokentokentokentokentoken'

ADDR = 'addraddraddraddraddraddraddraddraddraddr'
HOP1 = '1111111111111111111111111111111111111111'
HOP2 = '2222222222222222222222222222222222222222'
HOP3 = '3333333333333333333333333333333333333333'
HOP4 = '4444444444444444444444444444444444444444'
HOP5 = '5555555555555555555555555555555555555555'
HOP6 = '6666666666666666666666666666666666666666'
UNIT_TRANSFER_AMOUNT = 10

# add the current block number to get the expiration
HOP1_TIMEOUT = UNIT_SETTLE_TIMEOUT - UNIT_REVEAL_TIMEOUT
HOP2_TIMEOUT = HOP1_TIMEOUT - UNIT_REVEAL_TIMEOUT
HOP3_TIMEOUT = HOP2_TIMEOUT - UNIT_REVEAL_TIMEOUT


class SequenceGenerator():
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


def make_route(node_address,
               capacity,
               settle_timeout=UNIT_SETTLE_TIMEOUT,
               reveal_timeout=UNIT_REVEAL_TIMEOUT):
    """ Helper for creating a route.

    Args:
        node_address (address): The node address.
        capacity (int): The available capacity of the route.
        settle_timeout (int): The settle_timeout of the route, as agreed in the netting contract.
        reveal_timeout (int): The configure reveal_timeout of the raiden node.
    """
    state = 'available'
    route = RouteState(
        state,
        node_address,
        capacity,
        settle_timeout,
        reveal_timeout,
    )
    return route


def make_hashlock_transfer(amount,
                           target,
                           identifier=0,
                           token=UNIT_TOKEN_ADDRESS):
    """ Helper for creating a hashlocked transfer.

    Args:
        amount (int): Amount of token being transferred.
        target (address): Transfer target.
        expiration (int): Block number
    """

    secret = None
    """ The corresponding secret to the hashlock that can unlock it. """

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
                          amount=UNIT_TRANSFER_AMOUNT,
                          block_number=1,
                          our_address=ADDR,
                          secret_generator=None):

    our_address = ADDR

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
                         amount=UNIT_TRANSFER_AMOUNT,
                         block_number=1,
                         our_address=ADDR,
                         secret_generator=None):

    init_state_change = make_init_statechange(
        routes,
        target,
        amount,
        block_number,
    )

    inital_state = None
    iteration = initiator.state_transition(inital_state, init_state_change)

    return iteration.new_state


def test_next_route():
    target = HOP1
    routes = [
        make_route(HOP2, capacity=UNIT_TRANSFER_AMOUNT),
        make_route(HOP3, capacity=UNIT_TRANSFER_AMOUNT - 1),
        make_route(HOP4, capacity=UNIT_TRANSFER_AMOUNT),
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

    assert len(state.routes.available_routes) == 0
    assert len(state.routes.ignored_routes) == 1, 'HOP3 should be ignored because it doesnt have enough balance'
    assert len(state.routes.refunded_routes) == 0
    assert len(state.routes.canceled_routes) == 1


def test_init_with_usable_routes():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    mediator_address = HOP1
    target_address = HOP2
    our_address = ADDR
    secret_generator = SequenceGenerator()

    routes = [make_route(mediator_address, capacity=amount)]
    init_state_change = make_init_statechange(
        routes,
        target_address,
        block_number=block_number,
        our_address=our_address,
        secret_generator=secret_generator,
    )

    expiration = block_number + HOP1_TIMEOUT

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

    assert mediated_transfer.token == UNIT_TOKEN_ADDRESS, 'transfer token address mismatch'
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
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    our_address, target_address = HOP1, HOP3
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
