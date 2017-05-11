# -*- coding: utf-8 -*-
import pytest

from raiden.utils import sha3
from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer,
)
from raiden.transfer.state_change import Block, RouteState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveSecretRequest,
    ReceiveSecretReveal
)
from raiden.messages import DirectTransfer


@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('deposit', [2 ** 20])
def test_fullnetwork(raiden_chain, settle_timeout, reveal_timeout):
    app0, app1, app2, app3 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = app0.raiden.chain.default_registry.token_addresses()[0]
    channel_0_1 = channel(app0, app1, token_address)
    channel_1_2 = channel(app1, app2, token_address)
    channel_3_2 = channel(app3, app2, token_address)
    channel_0_3 = channel(app0, app3, token_address)

    amount = 80
    direct_transfer(app0, app1, token_address, amount)
    last_transfer = get_sent_transfer(channel_0_1, 0)
    assert last_transfer.transferred_amount == 80

    amount = 50
    direct_transfer(app1, app2, token_address, amount)
    last_transfer = get_sent_transfer(channel_1_2, 0)
    assert last_transfer.transferred_amount == 50

    amount = 30
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount
    )
    last_transfer = get_sent_transfer(channel_0_1, 0)
    assert isinstance(last_transfer, DirectTransfer)

    initiator_transfer = get_sent_transfer(channel_0_3, 0)
    mediator_transfer = get_sent_transfer(channel_3_2, 0)
    assert initiator_transfer.identifier == mediator_transfer.identifier
    assert initiator_transfer.lock.amount == amount
    assert mediator_transfer.lock.amount == amount

    # Now let's query the WAL to see if the state changes were logged as expected
    app0_state_changes = [
        change[1] for change in app0.raiden.transaction_log.get_all_state_changes()
        if not isinstance(change[1], Block)
    ]
    app1_state_changes = [
        change[1] for change in app1.raiden.transaction_log.get_all_state_changes()
        if not isinstance(change[1], Block)
    ]
    app2_state_changes = [
        change[1] for change in app2.raiden.transaction_log.get_all_state_changes()
        if not isinstance(change[1], Block)
    ]
    app3_state_changes = [
        change[1] for change in app3.raiden.transaction_log.get_all_state_changes()
        if not isinstance(change[1], Block)
    ]

    # app1 does not take part in the mediated transfer.
    assert app1_state_changes == list()

    # app0 initiates the mediated_transfer
    assert len(app0_state_changes) == 3
    assert isinstance(app0_state_changes[0], ActionInitInitiator)
    assert app0_state_changes[0].our_address == app0.raiden.address
    assert app0_state_changes[0].transfer.amount == amount
    assert app0_state_changes[0].transfer.token == token_address
    assert app0_state_changes[0].transfer.initiator == app0.raiden.address
    assert app0_state_changes[0].transfer.target == app2.raiden.address
    # The ActionInitInitiator state change does not have the following fields populated.
    # They get populated via an event during the processing of the state change inside
    # this function: mediated_transfer.mediated_transfer.initiator.try_new_route()
    assert app0_state_changes[0].transfer.expiration is None
    assert app0_state_changes[0].transfer.hashlock is None
    assert app0_state_changes[0].transfer.secret is None
    # We should have two available routes
    assert len(app0_state_changes[0].routes.available_routes) == 2
    assert len(app0_state_changes[0].routes.ignored_routes) == 0
    assert len(app0_state_changes[0].routes.refunded_routes) == 0
    assert len(app0_state_changes[0].routes.canceled_routes) == 0
    # Of these 2 the state machine will in the future choose the one with the most
    # available balance
    not_taken_route = RouteState(
        state='opened',
        node_address=app1.raiden.address,
        channel_address=channel_0_1.channel_address,
        available_balance=1048496,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    taken_route = RouteState(
        state='opened',
        node_address=app3.raiden.address,
        channel_address=channel_0_3.channel_address,
        available_balance=1048576,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    assert taken_route in app0_state_changes[0].routes.available_routes
    assert not_taken_route in app0_state_changes[0].routes.available_routes

    # app0 will also receive a secret request from the target
    assert isinstance(app0_state_changes[1], ReceiveSecretRequest)
    assert app0_state_changes[1].amount == amount
    assert app0_state_changes[1].sender == app2.raiden.address
    hashlock = app0_state_changes[1].hashlock

    # app0 will also receive a secret reveal from the immediate neighbour
    assert isinstance(app0_state_changes[2], ReceiveSecretReveal)
    assert app0_state_changes[2].sender == app3.raiden.address
    secret = app0_state_changes[2].secret
    assert sha3(secret) == hashlock

    # app3 is the mediator
    assert isinstance(app3_state_changes[0], ActionInitMediator)
    assert app3_state_changes[0].our_address == app3.raiden.address
    # We should have only 1 available route from mediator to target
    from_route = RouteState(
        state='opened',
        node_address=app0.raiden.address,
        channel_address=channel_0_3.channel_address,
        available_balance=1048576,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    to_route = RouteState(
        state='opened',
        node_address=app2.raiden.address,
        channel_address=channel_3_2.channel_address,
        available_balance=1048576,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    assert app3_state_changes[0].from_route == from_route
    assert len(app3_state_changes[0].routes.available_routes) == 1
    assert len(app3_state_changes[0].routes.ignored_routes) == 0
    assert len(app3_state_changes[0].routes.refunded_routes) == 0
    assert len(app3_state_changes[0].routes.canceled_routes) == 0
    assert app3_state_changes[0].routes.available_routes[0] == to_route
    # check the from_transfer is correct
    assert app3_state_changes[0].from_transfer.amount == amount
    assert app3_state_changes[0].from_transfer.hashlock == hashlock
    assert app3_state_changes[0].from_transfer.token == token_address
    assert app3_state_changes[0].from_transfer.initiator == app0.raiden.address
    assert app3_state_changes[0].from_transfer.target == app2.raiden.address

    # The mediator should have also received a SecretReveal from the target
    assert isinstance(app3_state_changes[1], ReceiveSecretReveal)
    assert app3_state_changes[1].sender == app2.raiden.address
    assert app3_state_changes[1].secret == secret

    # If the mediator received any more it is from the initiator
    # TODO: Figure out why we may get two times the secret reveal from the initiator
    for state_change in app3_state_changes[2:]:
        assert isinstance(state_change, ReceiveSecretReveal)
        assert state_change.sender == app0.raiden.address
        assert state_change.secret == secret

    # app2 is the target of the mediated transfer
    assert len(app2_state_changes) == 4  # We get 2 secret reveals from the mediator. WHY?
    assert isinstance(app2_state_changes[0], ActionInitTarget)
    assert app2_state_changes[0].our_address == app2.raiden.address
    # check the route the transfer came from
    from_route = RouteState(
        state='opened',
        node_address=app3.raiden.address,
        channel_address=channel_3_2.channel_address,
        available_balance=1048576,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    assert app2_state_changes[0].from_route == from_route
    # check the from_transfer is correct
    assert app2_state_changes[0].from_transfer.amount == amount
    assert app2_state_changes[0].from_transfer.hashlock == hashlock
    assert app2_state_changes[0].from_transfer.token == token_address
    assert app2_state_changes[0].from_transfer.initiator == app0.raiden.address
    assert app2_state_changes[0].from_transfer.target == app2.raiden.address

    # We also get secret reveals from the initiator and the mediator.
    assert isinstance(app2_state_changes[1], ReceiveSecretReveal)
    assert app2_state_changes[1].sender == app0.raiden.address
    assert app2_state_changes[1].secret == secret

    # TODO: Figure out why we get two times the Secret Reveal from the mediator
    assert isinstance(app2_state_changes[2], ReceiveSecretReveal)
    assert app2_state_changes[2].sender == app3.raiden.address
    assert app2_state_changes[2].secret == secret
    assert isinstance(app2_state_changes[3], ReceiveSecretReveal)
    assert app2_state_changes[3].sender == app3.raiden.address
    assert app2_state_changes[3].secret == secret
