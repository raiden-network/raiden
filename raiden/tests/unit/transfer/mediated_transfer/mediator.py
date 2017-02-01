# -*- coding: utf-8 -*-
from raiden.utils import sha3
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import RouteState
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import MediatorState
from raiden.transfer.mediated_transfer.state_change import (
    InitMediator,
)
from raiden.transfer.mediated_transfer.events import (
    MediatedTransfer,
)

UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TOKEN_ADDRESS = 'tokentokentokentokentokentokentokentoken'
UNIT_TRANSFER_AMOUNT = 10
UNIT_SECRET = 'secretsecretsecretsecretsecretsecretsecr'
UNIT_HASHLOCK = sha3(UNIT_SECRET)

ADDR = 'addraddraddraddraddraddraddraddraddraddr'
HOP1 = '1111111111111111111111111111111111111111'
HOP2 = '2222222222222222222222222222222222222222'
HOP3 = '3333333333333333333333333333333333333333'
HOP4 = '4444444444444444444444444444444444444444'
HOP5 = '5555555555555555555555555555555555555555'
HOP6 = '6666666666666666666666666666666666666666'

# add the current block number to get the expiration
HOP1_TIMEOUT = UNIT_SETTLE_TIMEOUT - UNIT_REVEAL_TIMEOUT
HOP2_TIMEOUT = HOP1_TIMEOUT - UNIT_REVEAL_TIMEOUT
HOP3_TIMEOUT = HOP2_TIMEOUT - UNIT_REVEAL_TIMEOUT


def test_init_mediator():
    state = 'available'
    originating_route = RouteState(
        state,
        HOP1,
        UNIT_TRANSFER_AMOUNT,
        UNIT_SETTLE_TIMEOUT,
        UNIT_REVEAL_TIMEOUT,
    )

    identifier = 0
    secret = None
    from_transfer = LockedTransferState(
        identifier,
        UNIT_TRANSFER_AMOUNT,
        UNIT_TOKEN_ADDRESS,
        HOP2_TIMEOUT,
        UNIT_HASHLOCK,
        secret,
    )

    block_number = 1
    init_state_change = InitMediator(
        ADDR,
        originating_route,
        from_transfer,
        block_number,
    )

    state, events = mediator.state_transition(None, init_state_change)

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
    assert mediator_state.our_address == ADDR
    assert mediator_state.from_transfer == from_transfer
    assert mediator_state.block_number == block_number
    assert mediator_state.from_route == originating_route

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
