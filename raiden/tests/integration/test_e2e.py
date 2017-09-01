# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.utils import sha3
from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer,
)
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.log import get_all_state_changes, get_all_state_events
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.state_change import (
    RouteState,
    ReceiveTransferDirect,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveBalanceProof,
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
    EventWithdrawSuccess,
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


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('settle_timeout', [50])
def test_mediation(raiden_network, token_addresses, settle_timeout):
    # The network has the following topology:
    #
    # App1 <--> App0 <--> App2

    token_address = token_addresses[0]
    app0, app1, app2 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    identifier = 1
    amount = 1
    async_result = app1.raiden.mediated_transfer_async(
        token_address,
        amount,
        app2.raiden.address,
        identifier,
    )
    assert async_result.wait()

    mediator_chain = app0.raiden.chain
    settle_expiration = mediator_chain.block_number() + settle_timeout + 1
    wait_until_block(mediator_chain, settle_expiration)

    # context switch needed for tester to process the EventWithdrawSuccess
    gevent.sleep(1)

    app0_events = [
        event.event_object
        for event in get_all_state_events(app0.raiden.transaction_log)
    ]
    assert must_contain_entry(app0_events, EventWithdrawSuccess, {})


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
    # pylint: disable=too-many-locals,too-many-statements

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
    direct_transfer(app0, app1, token_address, amount, identifier=1)
    assert get_sent_transfer(channel_0_1, 0).transferred_amount == amount

    amount = int(deposit / 2.)
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount
    )

    gevent.sleep(0.5)

    # This is the only possible path, the transfer must go backwards
    assert_path_mediated_transfer(
        get_sent_transfer(channel_0_3, 0),
        get_sent_transfer(channel_3_2, 0),
    )

    app0_state_changes = [
        change[1]
        for change in get_all_state_changes(app0.raiden.transaction_log)
    ]

    app0_events = [
        event.event_object
        for event in get_all_state_events(app0.raiden.transaction_log)
    ]

    secret = None
    for event in app0_events:
        if isinstance(event, SendRevealSecret):
            secret = event.secret

    assert secret is not None
    hashlock = sha3(secret)

    # app0 initiates the direct transfer and mediated_transfer
    assert must_contain_entry(app0_state_changes, ActionInitInitiator, {
        'our_address': app0.raiden.address,
        'transfer': {
            'amount': amount,
            'token': token_address,
            'initiator': app0.raiden.address,
            'target': app2.raiden.address,
            'expiration': None,
            'hashlock': None,
            'secret': None,
        }
    })

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

    for state_change in app0_state_changes:
        if isinstance(state_change, ActionInitMediator):
            assert taken_route in state_change.routes.available_routes
            assert not_taken_route not in state_change.routes.available_routes

    # app1 received one direct transfers
    app1_state_changes = [
        change[1]
        for change in get_all_state_changes(app1.raiden.transaction_log)
    ]
    assert must_contain_entry(app1_state_changes, ReceiveBalanceProof, {})
    assert must_contain_entry(app1_state_changes, ReceiveTransferDirect, {})

    app2_state_changes = [
        change[1]
        for change in get_all_state_changes(app2.raiden.transaction_log)
    ]

    assert must_contain_entry(app2_state_changes, ActionInitTarget, {
        'our_address': app2.raiden.address,
        'from_route': {
            'state': 'opened',
            'node_address': app3.raiden.address,
            'channel_address': channel_3_2.channel_address,
            'available_balance': deposit,
            'settle_timeout': settle_timeout,
            'reveal_timeout': reveal_timeout,
            'closed_block': None
        },
        'from_transfer': {
            'amount': amount,
            'hashlock': hashlock,
            'token': token_address,
            'initiator': app0.raiden.address,
            'target': app2.raiden.address,
        }
    })

    assert must_contain_entry(app2_state_changes, ReceiveSecretReveal, {
        'sender': app0.raiden.address,
        'secret': secret,
    })

    assert must_contain_entry(app2_state_changes, ReceiveSecretReveal, {
        'sender': app3.raiden.address,
        'secret': secret,
    })

    app2_events = [
        event.event_object
        for event in get_all_state_events(app2.raiden.transaction_log)
    ]

    assert must_contain_entry(app2_events, SendSecretRequest, {
        'amount': amount,
        'hashlock': hashlock,
        'receiver': app0.raiden.address,
    })

    assert must_contain_entry(app2_events, SendRevealSecret, {
        'token': token_address,
        'secret': secret,
        'receiver': app3.raiden.address,
        'sender': app2.raiden.address,
    })

    assert must_contain_entry(app0_state_changes, ReceiveSecretRequest, {
        'amount': amount,
        'sender': app2.raiden.address,
        'hashlock': hashlock,
    })

    assert must_contain_entry(app0_state_changes, ReceiveSecretReveal, {
        'sender': app3.raiden.address,
        'secret': secret,
    })

    assert must_contain_entry(app0_events, EventTransferSentSuccess, {})

    assert must_contain_entry(app0_events, SendMediatedTransfer, {
        'token': token_address,
        'amount': amount,
        'hashlock': hashlock,
        'initiator': app0.raiden.address,
        'target': app2.raiden.address,
        'receiver': app3.raiden.address,
    })

    assert must_contain_entry(app0_events, SendRevealSecret, {
        'secret': secret,
        'token': token_address,
        'receiver': app2.raiden.address,
        'sender': app0.raiden.address,
    })

    assert must_contain_entry(app0_events, SendBalanceProof, {
        'token': token_address,
        'channel_address': channel_0_3.channel_address,
        'receiver': app3.raiden.address,
        'secret': secret,
    })

    assert must_contain_entry(app0_events, EventTransferSentSuccess, {})
    assert must_contain_entry(app0_events, EventUnlockSuccess, {
        'hashlock': hashlock,
    })

    app3_state_changes = [
        change[1]
        for change in get_all_state_changes(app3.raiden.transaction_log)
    ]

    assert must_contain_entry(app3_state_changes, ActionInitMediator, {
        'our_address': app3.raiden.address,
        'from_route': {
            'state': 'opened',
            'node_address': app0.raiden.address,
            'channel_address': channel_0_3.channel_address,
            'available_balance': deposit,
            'settle_timeout': settle_timeout,
            'reveal_timeout': reveal_timeout,
            'closed_block': None,
        },
        'from_transfer': {
            'amount': amount,
            'hashlock': hashlock,
            'token': token_address,
            'initiator': app0.raiden.address,
            'target': app2.raiden.address,
        }
    })

    assert must_contain_entry(app3_state_changes, ReceiveSecretReveal, {
        'sender': app2.raiden.address,
        'secret': secret,
    })

    assert must_contain_entry(app3_state_changes, ReceiveSecretReveal, {
        'sender': app2.raiden.address,
        'secret': secret,
    })

    app3_events = [
        event.event_object
        for event in get_all_state_events(app3.raiden.transaction_log)
    ]

    assert must_contain_entry(app3_events, SendMediatedTransfer, {
        'token': token_address,
        'amount': amount,
        'hashlock': hashlock,
        'initiator': app0.raiden.address,
        'target': app2.raiden.address,
        'receiver': app2.raiden.address,
    })

    assert must_contain_entry(app3_events, SendRevealSecret, {
        'secret': secret,
        'token': token_address,
        'receiver': app0.raiden.address,
        'sender': app3.raiden.address,
    })

    assert must_contain_entry(app3_events, SendBalanceProof, {
        'token': token_address,
        'channel_address': channel_3_2.channel_address,
        'receiver': app2.raiden.address,
        'secret': secret,
    })
    assert must_contain_entry(app3_events, EventUnlockSuccess, {})
