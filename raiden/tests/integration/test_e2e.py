# -*- coding: utf-8 -*-
import pytest

from raiden.utils import sha3
from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer,
)
from raiden.tests.utils.log import get_all_state_changes, get_all_state_events
from raiden.transfer.state_change import (
    Block,
    RouteState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveSecretRequest,
    ReceiveSecretReveal
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.messages import MediatedTransfer


def mediated_transfer_almost_equal(first, second):
    assert first.identifier == second.identifier, "identifier doesn't match"
    assert first.token == second.token, "token address doesn't match"
    assert first.lock.amount == second.lock.amount, "lock amount doesn't match"
    assert first.lock.hashlock == second.lock.hashlock, "lock hashlock doesn't match"
    assert first.target == second.target, "target doesn't match"
    assert first.initiator == second.initiator, "initiator doesn't match"


def assert_path_mediated_transfer(*transfers):
    assert all(
        isinstance(t, MediatedTransfer)
        for t in transfers
    ), 'all transfers must be of type MediatedTransfer'

    for first, second in zip(transfers[:-1], transfers[1:]):
        mediated_transfer_almost_equal(first, second)

        assert first.recipient == second.sender, 'transfers are out-of-order'
        assert first.lock.expiration > second.lock.expiration, 'lock expiration is not decreasing'


@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('settle_timeout', [50])
def test_fullnetwork(
        raiden_chain,
        token_addresses,
        deposit,
        settle_timeout,
        reveal_timeout):

    # The network has the following topology:
    #
    #   App0 <---> App1
    #    ^          ^
    #    |          |
    #    v          v
    #   App3 <---> App2

    token_address = token_addresses[0]

    app0, app1, app2, app3 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    channel_0_1 = channel(app0, app1, token_address)
    channel_3_2 = channel(app3, app2, token_address)
    channel_0_3 = channel(app0, app3, token_address)

    # Exhaust the channel deposit (to force the mediated transfer to go backwards)
    amount = deposit
    direct_transfer(app0, app1, token_address, amount)
    assert get_sent_transfer(channel_0_1, 0).transferred_amount == amount

    amount = int(deposit / 2.)
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount
    )

    # This is the only possible path, the transfer must go backwards
    assert_path_mediated_transfer(
        get_sent_transfer(channel_0_3, 0),
        get_sent_transfer(channel_3_2, 0),
    )

    # Now let's query the WAL to see if the state changes were logged as expected
    app0_state_changes = [
        change[1] for change in get_all_state_changes(app0.raiden.transaction_log)
        if not isinstance(change[1], Block)
    ]
    app0_events = [
        event[3] for event in get_all_state_events(app0.raiden.transaction_log)
    ]
    app1_state_changes = [
        change[1] for change in get_all_state_changes(app1.raiden.transaction_log)
        if not isinstance(change[1], Block)
    ]
    app1_events = [
        event[3] for event in get_all_state_events(app1.raiden.transaction_log)
    ]
    app2_state_changes = [
        change[1] for change in get_all_state_changes(app2.raiden.transaction_log)
        if not isinstance(change[1], Block)
    ]
    app2_events = [
        event[3] for event in get_all_state_events(app2.raiden.transaction_log)
    ]
    app3_state_changes = [
        change[1] for change in get_all_state_changes(app3.raiden.transaction_log)
        if not isinstance(change[1], Block)
    ]
    app3_events = [
        event[3] for event in get_all_state_events(app3.raiden.transaction_log)
    ]

    # app1 received one direct transfers
    assert len(app1_state_changes) == 1
    assert len(app1_events) == 1

    # app0 initiates the direct transfer and mediated_transfer
    assert len(app0_state_changes) == 4
    assert isinstance(app0_state_changes[1], ActionInitInitiator)
    assert app0_state_changes[1].our_address == app0.raiden.address
    assert app0_state_changes[1].transfer.amount == amount
    assert app0_state_changes[1].transfer.token == token_address
    assert app0_state_changes[1].transfer.initiator == app0.raiden.address
    assert app0_state_changes[1].transfer.target == app2.raiden.address
    # The ActionInitInitiator state change does not have the following fields populated.
    # They get populated via an event during the processing of the state change inside
    # this function: mediated_transfer.mediated_transfer.initiator.try_new_route()
    assert app0_state_changes[1].transfer.expiration is None
    assert app0_state_changes[1].transfer.hashlock is None
    assert app0_state_changes[1].transfer.secret is None
    # We should have one available route
    assert len(app0_state_changes[1].routes.available_routes) == 1
    assert len(app0_state_changes[1].routes.ignored_routes) == 0
    assert len(app0_state_changes[1].routes.refunded_routes) == 0
    assert len(app0_state_changes[1].routes.canceled_routes) == 0
    # Of these 2 the state machine will in the future choose the one with the most
    # available balance
    not_taken_route = RouteState(
        state='opened',
        node_address=app1.raiden.address,
        channel_address=channel_0_1.channel_address,
        available_balance=deposit,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    taken_route = RouteState(
        state='opened',
        node_address=app3.raiden.address,
        channel_address=channel_0_3.channel_address,
        available_balance=deposit,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    assert taken_route in app0_state_changes[1].routes.available_routes
    assert not_taken_route not in app0_state_changes[1].routes.available_routes

    # app0 will also receive a secret request from the target
    assert isinstance(app0_state_changes[2], ReceiveSecretRequest)
    assert app0_state_changes[2].amount == amount
    assert app0_state_changes[2].sender == app2.raiden.address
    hashlock = app0_state_changes[2].hashlock

    # app0 will also receive a secret reveal from the immediate neighbour
    assert isinstance(app0_state_changes[3], ReceiveSecretReveal)
    assert app0_state_changes[3].sender == app3.raiden.address
    secret = app0_state_changes[3].secret
    assert sha3(secret) == hashlock

    assert len(app0_events) == 6

    # Direct transfer
    assert isinstance(app0_events[0], EventTransferSentSuccess)

    # not checking the expiration and identifier
    assert isinstance(app0_events[1], SendMediatedTransfer)
    assert app0_events[1].token == token_address
    assert app0_events[1].amount == amount
    assert app0_events[1].hashlock == hashlock
    assert app0_events[1].initiator == app0.raiden.address
    assert app0_events[1].target == app2.raiden.address
    assert app0_events[1].receiver == app3.raiden.address

    #  not checking the identifier
    assert isinstance(app0_events[2], SendRevealSecret)
    assert app0_events[2].secret == secret
    assert app0_events[2].token == token_address
    assert app0_events[2].receiver == app2.raiden.address
    assert app0_events[2].sender == app0.raiden.address

    # not checking the identifier
    assert isinstance(app0_events[3], SendBalanceProof)
    assert app0_events[3].token == token_address
    assert app0_events[3].channel_address == channel_0_3.channel_address
    assert app0_events[3].receiver == app3.raiden.address
    assert app0_events[3].secret == secret

    assert isinstance(app0_events[4], EventTransferSentSuccess)

    # EventUnlockSuccess, not checking the identifier
    assert isinstance(app0_events[5], EventUnlockSuccess)
    assert app0_events[5].hashlock == hashlock

    # app3 is the mediator
    assert isinstance(app3_state_changes[0], ActionInitMediator)
    assert app3_state_changes[0].our_address == app3.raiden.address
    # We should have only 1 available route from mediator to target
    from_route = RouteState(
        state='opened',
        node_address=app0.raiden.address,
        channel_address=channel_0_3.channel_address,
        available_balance=deposit,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=None,
    )
    to_route = RouteState(
        state='opened',
        node_address=app2.raiden.address,
        channel_address=channel_3_2.channel_address,
        available_balance=deposit,
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

    # check app3 state events
    assert len(app3_events) == 4
    assert isinstance(app3_events[0], SendMediatedTransfer)
    assert app3_events[0].token == token_address
    assert app3_events[0].amount == amount
    assert app3_events[0].hashlock == hashlock
    assert app3_events[0].initiator == app0.raiden.address
    assert app3_events[0].target == app2.raiden.address
    assert app3_events[0].receiver == app2.raiden.address

    assert isinstance(app3_events[1], SendRevealSecret)
    assert app3_events[1].secret == secret
    assert app3_events[1].token == token_address
    assert app3_events[1].receiver == app0.raiden.address
    assert app3_events[1].sender == app3.raiden.address

    assert isinstance(app3_events[2], SendBalanceProof)
    assert app3_events[2].token == token_address
    assert app3_events[2].channel_address == channel_3_2.channel_address
    assert app3_events[2].receiver == app2.raiden.address
    assert app3_events[2].secret == secret

    assert isinstance(app3_events[3], EventUnlockSuccess)

    # app2 is the target of the mediated transfer
    assert len(app2_state_changes) == 4  # We get 2 secret reveals from the mediator. WHY?
    assert isinstance(app2_state_changes[0], ActionInitTarget)
    assert app2_state_changes[0].our_address == app2.raiden.address
    # check the route the transfer came from
    from_route = RouteState(
        state='opened',
        node_address=app3.raiden.address,
        channel_address=channel_3_2.channel_address,
        available_balance=deposit,
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

    # check app2 state events
    assert len(app2_events) == 2
    assert isinstance(app2_events[0], SendSecretRequest)
    assert app2_events[0].amount == amount
    assert app2_events[0].hashlock == hashlock
    assert app2_events[0].receiver == app0.raiden.address
    assert isinstance(app2_events[1], SendRevealSecret)
    assert app2_events[1].token == token_address
    assert app2_events[1].secret == secret
    assert app2_events[1].receiver == app3.raiden.address
    assert app2_events[1].sender == app2.raiden.address
