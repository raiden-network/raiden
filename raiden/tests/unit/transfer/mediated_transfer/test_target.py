# -*- coding: utf-8 -*-
# pylint: disable=invalid-name,too-many-locals
import pytest

from raiden.transfer.architecture import TransitionResult
from raiden.transfer.state_change import Block
from raiden.transfer.mediated_transfer import target
from raiden.transfer.mediated_transfer.state import TargetState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveSecretReveal,
    ReceiveBalanceProof,
)
from raiden.transfer.mediated_transfer.events import (
    ContractSendChannelClose,
    ContractSendWithdraw,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.transfer.state import CHANNEL_STATE_CLOSED
from . import factories


def make_init_state_change(our_address, amount, block_number, initiator, expire=None):
    if expire is None:
        expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    from_route, from_transfer = factories.make_from(
        amount,
        our_address,
        expire,
        initiator,
    )
    init = ActionInitTarget(
        our_address,
        from_route,
        from_transfer,
        block_number,
    )

    return init


def make_target_state(our_address, amount, block_number, initiator, expire=None):
    if expire is None:
        expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    from_route, from_transfer = factories.make_from(
        amount,
        our_address,
        expire,
        initiator,
    )

    state = TargetState(
        our_address,
        from_route,
        from_transfer,
        block_number,
    )

    return state


def test_events_for_close():
    """ Channel must be closed when the unsafe region is reached and the secret is known. """
    amount = 3
    expire = 10
    initiator = factories.HOP1
    secret = factories.UNIT_SECRET

    transfer = factories.make_transfer(
        amount,
        initiator,
        factories.ADDR,
        expire,
        secret=secret,
    )
    route = factories.make_route(
        initiator,
        amount,
    )

    safe_block = expire - route.reveal_timeout - 1
    events = target.events_for_close(
        transfer,
        route,
        safe_block,
    )
    assert len(events) == 0

    unsafe_block = expire - route.reveal_timeout
    events = target.events_for_close(
        transfer,
        route,
        unsafe_block,
    )
    assert isinstance(events[0], ContractSendChannelClose)
    assert transfer.secret is not None
    assert events[0].channel_address == route.channel_address


def test_events_for_close_secret_unknown():
    """ Channel must not be closed when the unsafe region is reached and the
    secret is not known.
    """
    amount = 3
    expire = 10
    initiator = factories.HOP1

    transfer = factories.make_transfer(
        amount,
        initiator,
        factories.ADDR,
        expire,
    )
    route = factories.make_route(
        initiator,
        amount,
    )

    safe_block = expire - route.reveal_timeout - 1
    events = target.events_for_close(
        transfer,
        route,
        safe_block,
    )
    assert len(events) == 0

    unsafe_block = expire - route.reveal_timeout
    events = target.events_for_close(
        transfer,
        route,
        unsafe_block,
    )
    assert len(events) == 0
    assert transfer.secret is None


def test_events_for_withdraw():
    """ On-chain withdraw must be done if the channel is closed, regardless of
    the unsafe region.
    """
    amount = 3
    expire = 10
    initiator = factories.HOP1

    transfer = factories.make_transfer(
        amount,
        initiator,
        factories.ADDR,
        expire,
        secret=factories.UNIT_SECRET,
    )
    route = factories.make_route(
        initiator,
        amount,
    )

    events = target.events_for_withdraw(
        transfer,
        route,
    )
    assert len(events) == 0

    route.state = CHANNEL_STATE_CLOSED
    events = target.events_for_withdraw(
        transfer,
        route,
    )
    assert isinstance(events[0], ContractSendWithdraw)
    assert events[0].channel_address == route.channel_address


def test_handle_inittarget():
    """ Init transfer must send a secret request if the expiration is valid. """
    block_number = 1
    amount = 3
    expire = factories.UNIT_REVEAL_TIMEOUT + block_number + 1
    initiator = factories.HOP1

    from_route, from_transfer = factories.make_from(
        amount,
        factories.ADDR,
        expire,
        initiator,
    )
    state_change = ActionInitTarget(
        factories.ADDR,
        from_route,
        from_transfer,
        block_number,
    )

    iteration = target.handle_inittarget(state_change)

    events = iteration.events
    assert isinstance(events[0], SendSecretRequest)

    assert events[0].identifier == from_transfer.identifier
    assert events[0].amount == from_transfer.amount
    assert events[0].hashlock == from_transfer.hashlock
    assert events[0].receiver == initiator


def test_handle_inittarget_bad_expiration():
    """ Init transfer must do nothing if the expiration is bad. """
    block_number = 1
    amount = 3
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT
    initiator = factories.HOP1

    from_route, from_transfer = factories.make_from(
        amount,
        factories.ADDR,
        expire,
        initiator,
    )
    state_change = ActionInitTarget(
        factories.ADDR,
        from_route,
        from_transfer,
        block_number,
    )

    iteration = target.handle_inittarget(state_change)
    assert len(iteration.events) == 0


def test_handle_secretreveal():
    """ The target node needs to inform the secret to the previous node to
    receive an updated balance proof.
    """
    amount = 3
    block_number = 1
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT
    initiator = factories.HOP1
    our_address = factories.ADDR
    secret = factories.UNIT_SECRET

    state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expire,
    )
    state_change = ReceiveSecretReveal(secret, initiator)

    iteration = target.handle_secretreveal(state, state_change)
    reveal = [
        e
        for e in iteration.events
        if isinstance(e, SendRevealSecret)
    ]

    assert iteration.new_state.state == 'reveal_secret'
    assert reveal[0].identifier == state.from_transfer.identifier
    assert reveal[0].secret == secret
    assert reveal[0].receiver == state.from_route.node_address
    assert reveal[0].sender == our_address


def test_handle_block():
    """ Increase the block number. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expire,
    )

    new_block = Block(block_number + 1)
    iteration = target.state_transition(state, new_block)
    assert iteration.new_state.block_number == block_number + 1


def test_handle_block_equal_block_number():
    """ Nothing changes. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expire,
    )

    new_block = Block(block_number)
    iteration = target.state_transition(state, new_block)
    assert iteration.new_state.block_number == block_number


def test_handle_block_lower_block_number():
    """ Nothing changes. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expire,
    )

    new_block = Block(block_number - 1)
    iteration = target.state_transition(state, new_block)
    assert iteration.new_state.block_number == block_number


def test_clear_if_finalized_payed():
    """ Clear if the transfer is paid with a proof. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expire,
    )
    state.state = 'balance_proof'
    iteration = TransitionResult(state, list())
    iteration = target.clear_if_finalized(iteration)

    assert iteration.new_state is None


def test_clear_if_finalized_expired():
    """ Clear expired locks that we don't know the secret for. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 10
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    from_route, from_transfer = factories.make_from(
        amount,
        our_address,
        expire,
        initiator,
    )

    before_state = TargetState(
        our_address,
        from_route,
        from_transfer,
        block_number=expire,
    )
    before_iteration = TransitionResult(before_state, list())
    before_iteration = target.clear_if_finalized(before_iteration)

    assert before_iteration.new_state.from_transfer.secret is None
    assert before_iteration.new_state is not None

    expired_state = TargetState(
        our_address,
        from_route,
        from_transfer,
        block_number=expire + 1,
    )
    expired_iteration = TransitionResult(expired_state, list())
    expired_iteration = target.clear_if_finalized(expired_iteration)

    assert expired_iteration.new_state is None


def test_state_transition():
    """ Happy case testing. """
    amount = 7
    block_number = 1
    initiator = factories.HOP6
    expire = block_number + factories.UNIT_REVEAL_TIMEOUT

    from_route, from_transfer = factories.make_from(
        amount,
        factories.ADDR,
        expire,
        initiator,
    )
    init = ActionInitTarget(
        factories.ADDR,
        from_route,
        from_transfer,
        block_number,
    )

    init_transition = target.state_transition(None, init)
    assert init_transition.new_state is not None
    assert init_transition.new_state.from_route == from_route
    assert init_transition.new_state.from_transfer == from_transfer

    first_new_block = Block(block_number + 1)
    first_block_iteration = target.state_transition(init_transition.new_state, first_new_block)
    assert first_block_iteration.new_state.block_number == block_number + 1

    secret_reveal = ReceiveSecretReveal(factories.UNIT_SECRET, initiator)
    reveal_iteration = target.state_transition(first_block_iteration.new_state, secret_reveal)
    assert reveal_iteration.new_state.from_transfer.secret == factories.UNIT_SECRET

    second_new_block = Block(block_number + 2)
    second_block_iteration = target.state_transition(init_transition.new_state, second_new_block)
    assert second_block_iteration.new_state.block_number == block_number + 2

    balance_proof = ReceiveBalanceProof(
        from_transfer.identifier,
        from_route.channel_address,
        from_route.node_address,
    )
    proof_iteration = target.state_transition(init_transition.new_state, balance_proof)
    assert proof_iteration.new_state is None


@pytest.mark.xfail(reason='Not implemented #522')
def test_transfer_succesful_after_secret_learned():
    # TransferCompleted event must be used only after the secret is learned and
    # there is enough time to unlock the lock on chain.
    #
    # A mediated transfer might be received during the settlement period of the
    # current channel, the secret request is sent to the initiator and at time
    # the secret is revealed there might not be enough time to safely unlock
    # the token on-chain.
    raise NotImplementedError()
