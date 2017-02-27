# -*- coding: utf-8 -*-
# pylint: disable=invalid-name
import pytest

from raiden.transfer.mediated_transfer import target
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
)
from raiden.transfer.mediated_transfer.events import (
    ContractSendChannelClose,
    ContractSendWithdraw,
    SendSecretRequest,
)
from . import factories


def test_events_for_close():
    """ Channel must be closed when the unsafe region is reached. """
    amount = 3
    expire = 10

    transfer = factories.make_transfer(
        amount,
        factories.ADDR,
        expire,
    )
    route = factories.make_route(
        factories.HOP1,
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
    assert events[0].channel_address == route.channel_address


def test_events_for_withdraw():
    """ On-chain withdraw must be done if the channel is closed, regardless of
    the unsafe region.
    """
    amount = 3
    expire = 10

    transfer = factories.make_transfer(
        amount,
        factories.ADDR,
        expire,
        secret=factories.UNIT_SECRET,
    )
    route = factories.make_route(
        factories.HOP1,
        amount,
    )

    events = target.events_for_withdraw(
        transfer,
        route,
    )
    assert len(events) == 0

    route.state = 'closed'
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

    from_transfer = factories.make_transfer(
        amount,
        factories.ADDR,
        expire,
    )
    from_route = factories.make_route(
        factories.HOP1,
        amount,
    )
    state_change = ActionInitTarget(
        factories.ADDR,
        from_route,
        from_transfer,
        factories.UNIT_HASHLOCK,
        block_number,
    )

    iteration = target.handle_inittarget(state_change)

    events = iteration.events
    assert isinstance(events[0], SendSecretRequest)
    assert events[0].identifier == from_transfer.identifier
    assert events[0].amount == from_transfer.amount
    assert events[0].hashlock == from_transfer.hashlock


def test_handle_inittarget_bad_expiration():
    """ Init transfer must do nothing if the expiration is bad. """
    block_number = 1
    amount = 3
    expire = factories.UNIT_REVEAL_TIMEOUT + block_number

    from_transfer = factories.make_transfer(
        amount,
        factories.ADDR,
        expire,
    )
    from_route = factories.make_route(
        factories.HOP1,
        amount,
    )
    state_change = ActionInitTarget(
        factories.ADDR,
        from_route,
        from_transfer,
        factories.UNIT_HASHLOCK,
        block_number,
    )

    iteration = target.handle_inittarget(state_change)
    assert len(iteration.events) == 0


@pytest.mark.xfail(reason='Not implemented')
def test_transfer_succesful_after_secret_learned():
    # TransferCompleted event must be used only after the secret is learned and
    # there is enough time to unlock the lock on chain.
    #
    # A mediated transfer might be received during the settlement period of the
    # current channel, the secret request is sent to the initiator and at time
    # the secret is revealed there might not be enough time to safely unlock
    # the asset on-chain.
    raise NotImplementedError()
