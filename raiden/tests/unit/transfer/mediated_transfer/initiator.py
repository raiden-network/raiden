# -*- coding: utf8 -*-
from raiden.utils import sha3
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import AvailableRoutesState, RouteState
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    HashlockTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    InitInitiator,
)
from raiden.transfer.mediated_transfer.events import (
    MediatedTransfer,
    TransferFailed,
)

# prefixing with UNIT_ to differ from the default globals
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TOKEN_ADDRESS = 'tokentokentokentokentokentokentokentoken'

HOP1 = '1111111111111111111111111111111111111111'
HOP2 = '2222222222222222222222222222222222222222'
HOP3 = '3333333333333333333333333333333333333333'

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
        self.generator = itertools.repeat(string.letters)

    def __iter__(self):
        return self

    def __next__(self):
        # pad the secret to the correct length by repeating the current character
        new_secret = next(self.generator) * 40
        self.secrets.append(new_secret)
        return new_secret


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
                           token=UNIT_TOKEN_ADDRESS):
    """ Helper for creating a hashlocked transfer.

    Args:
        amount (int): Amount of token being transferred.
        target (address): Transfer target.
        expiration (int): Block number
    """

    secret = None
    """ The corresponding secret to the hashlock that can unlock it.

    hashlock = None
    expiration = None
    transfer = HashlockTransferState(
        amount,
        token,
        target,
        expiration,
        hashlock,
        secret,
    )
    return transfer


def test_init_with_usable_routes():
    amount = 10
    block_number = 1
    our_address, mediator_address, target_address = HOP1, HOP2, HOP3
    secret_generator = SequenceGenerator()
    expiration = block_number + HOP1_TIMEOUT
    routes = [make_route(mediator_address, capacity=amount)]

    init_state_change = InitInitiator(
        our_address,
        make_hashlock_transfer(amount, target=target_address),
        AvailableRoutesState(routes),
        secret_generator,
        block_number,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        None,
    )

    assert initiator_state_machine.state is None

    events = initiator_state_machine.dispatch(
        init_state_change,
    )

    initiator_state = initiator_state_machine.state
    assert isinstance(initiator_state, InitiatorState)
    assert initiator_state.our_address == our_address

    transfer = initiator_state.transfer
    assert isinstance(transfer, HashlockTransferState)
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

    assert initiator_state.route.node_address == mediated_transfer.node_address
    assert initiator_state.routes.available_routes == routes
    assert len(initiator_state.routes.ignored_routes) == 0
    assert len(initiator_state.routes.refunded_routes) == 0
    assert len(initiator_state.routes.canceled_routes) == 0


def test_init_without_routes():
    amount = 10
    block_number = 1
    our_address, target_address = HOP1, HOP3
    expiration = block_number + HOP1_TIMEOUT
    routes = []

    init_state_change = InitInitiator(
        our_address,
        make_hashlock_transfer(amount, target=target_address, expiration=expiration),
        AvailableRoutesState(routes),
        SequenceGenerator(),
        block_number,
    )

    initiator_state_machine = StateManager(
        initiator.state_transition,
        None,
    )

    assert initiator_state_machine.state is None

    events = initiator_state_machine.dispatch(
        init_state_change,
    )

    assert len(events) == 1
    assert isinstance(events[0], TransferFailed)
    assert initiator_state_machine.state is None
