# -*- coding: utf8 -*-
# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
from copy import deepcopy

from raiden.utils import random_secret
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    UNIT_HASHLOCK,
    UNIT_SECRET,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_TARGET,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
)
from raiden.transfer.mediated_transfer import initiator_manager
from raiden.transfer.mediated_transfer.state import InitiatorPaymentState
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute2,
    ActionInitInitiator2,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof2,
    SendMediatedTransfer2,
    SendRevealSecret2,
)
from raiden.transfer.mediated_transfer.mediator import TRANSIT_BLOCKS
from raiden.transfer.state_change import ActionCancelPayment


def make_initiator_state(
        routes,
        transfer_description,
        channelmap,
        block_number,
        payment_network_identifier=None):

    if payment_network_identifier is None:
        payment_network_identifier = factories.make_address()

    init_state_change = ActionInitInitiator2(
        payment_network_identifier,
        transfer_description,
        routes,
    )

    inital_state = None
    iteration = initiator_manager.state_transition(
        inital_state,
        init_state_change,
        channelmap,
        block_number,
    )

    return iteration.new_state


def test_next_route():
    amount = UNIT_TRANSFER_AMOUNT
    channel1 = factories.make_channel(our_balance=amount, token_address=UNIT_TOKEN_ADDRESS)
    channel2 = factories.make_channel(our_balance=0, token_address=UNIT_TOKEN_ADDRESS)
    channel3 = factories.make_channel(our_balance=amount, token_address=UNIT_TOKEN_ADDRESS)

    channelmap = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
        channel3.identifier: channel3,
    }

    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
        factories.route_from_channel(channel3),
    ]

    block_number = 10
    state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    msg = 'an initialized state must use the first valid route'
    assert state.initiator.channel_identifier == channel1.identifier, msg
    assert not state.cancelled_channels

    state_change = ActionCancelRoute2(
        channel1.identifier,
        available_routes,
    )
    iteration = initiator_manager.state_transition(
        state,
        state_change,
        channelmap,
        block_number,
    )

    # HOP3 should be ignored because it doesnt have enough balance
    assert iteration.new_state.cancelled_channels == [channel1.identifier]


def test_init_with_usable_routes():
    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitInitiator2(
        payment_network_identifier,
        factories.UNIT_TRANSFER_DESCRIPTION,
        available_routes,
    )

    block_number = 1
    transition = initiator_manager.state_transition(
        None,
        init_state_change,
        channelmap,
        block_number,
    )

    assert isinstance(transition.new_state, InitiatorPaymentState)
    assert transition.events, 'we have a valid route, the mediated transfer event must be emited'

    payment_state = transition.new_state
    assert payment_state.initiator.transfer_description == factories.UNIT_TRANSFER_DESCRIPTION

    mediated_transfers = [e for e in transition.events if isinstance(e, SendMediatedTransfer2)]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'

    send_mediated_transfer = mediated_transfers[0]
    transfer = send_mediated_transfer.transfer
    expiration = block_number + channel1.settle_timeout

    assert transfer.token == factories.UNIT_TRANSFER_DESCRIPTION.token
    assert transfer.lock.amount == factories.UNIT_TRANSFER_DESCRIPTION.amount
    assert transfer.lock.expiration == expiration
    assert transfer.lock.hashlock == factories.UNIT_TRANSFER_DESCRIPTION.hashlock
    assert send_mediated_transfer.recipient == channel1.partner_state.address


def test_init_without_routes():
    block_number = 1
    routes = []
    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitInitiator2(
        payment_network_identifier,
        factories.UNIT_TRANSFER_DESCRIPTION,
        routes,
    )

    channelmap = dict()
    iteration = initiator_manager.state_transition(
        None,
        init_state_change,
        channelmap,
        block_number,
    )

    assert iteration.new_state is None

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], EventTransferSentFailed)
    assert iteration.new_state is None


def test_state_wait_secretrequest_valid():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1

    channel1 = factories.make_channel(our_balance=amount, token_address=UNIT_TOKEN_ADDRESS)
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    state_change = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        UNIT_TRANSFER_AMOUNT,
        UNIT_HASHLOCK,
        UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], SendRevealSecret2)


def test_state_wait_unlock_valid():
    block_number = 1

    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    # setup the state for the wait unlock
    current_state.initiator.revealsecret = SendRevealSecret2(
        UNIT_TRANSFER_IDENTIFIER,
        UNIT_SECRET,
        UNIT_TOKEN_ADDRESS,
        UNIT_TRANSFER_TARGET,
    )

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=channel1.partner_state.address,
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )

    assert len(iteration.events) == 3
    assert any(isinstance(e, SendBalanceProof2) for e in iteration.events)
    assert any(isinstance(e, EventTransferSentSuccess) for e in iteration.events)
    assert any(isinstance(e, EventUnlockSuccess) for e in iteration.events)

    balance_proof = next(e for e in iteration.events if isinstance(e, SendBalanceProof2))
    complete = next(e for e in iteration.events if isinstance(e, EventTransferSentSuccess))

    assert balance_proof.receiver == channel1.partner_state.address
    assert complete.identifier == UNIT_TRANSFER_IDENTIFIER
    assert iteration.new_state is None, 'state must be cleaned'


def test_state_wait_unlock_invalid():
    identifier = identifier = 1
    block_number = 1
    target_address = factories.HOP2
    token = factories.UNIT_TOKEN_ADDRESS

    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    # setup the state for the wait unlock
    current_state.initiator.revealsecret = SendRevealSecret2(
        identifier,
        UNIT_SECRET,
        token,
        target_address,
    )

    before_state = deepcopy(current_state)

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=factories.ADDR,
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )

    assert not iteration.events
    assert iteration.new_state == before_state


def test_refund_transfer_next_route():
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=our_address,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channel3 = factories.make_channel(
        our_balance=amount,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
    )

    channelmap = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
        channel3.identifier: channel3,
    }

    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
        factories.route_from_channel(channel3),
    ]

    block_number = 10
    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    original_transfer = current_state.initiator.transfer
    channel_identifier = current_state.initiator.channel_identifier
    channel_state = channelmap[channel_identifier]

    expiration = original_transfer.lock.expiration - channel_state.reveal_timeout - TRANSIT_BLOCKS
    refund_transfer = factories.make_signed_transfer(
        amount,
        our_address,
        original_transfer.target,
        expiration,
        UNIT_SECRET,
        identifier=original_transfer.identifier,
        channel_identifier=channel1.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )
    assert channel_state.partner_state.address == refund_address

    state_change = ReceiveTransferRefundCancelRoute(
        sender=refund_address,
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )
    assert iteration.new_state is not None

    assert len(iteration.events) == 2

    route_cancelled = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    new_transfer = next(e for e in iteration.events if isinstance(e, SendMediatedTransfer2))

    assert route_cancelled, 'The previous transfer must be cancelled'
    assert new_transfer, 'No mediated transfer event emitted, should have tried a new route'
    msg = 'the new transfer must use a new secret / hashlock'
    assert new_transfer.transfer.lock.hashlock != refund_transfer.lock.hashlock, msg
    assert iteration.new_state.initiator is not None


def test_refund_transfer_no_more_routes():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    refund_pkey, refund_address = factories.make_privkey_address()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    original_transfer = current_state.initiator.transfer
    channel_identifier = current_state.initiator.channel_identifier
    channel_state = channelmap[channel_identifier]

    expiration = original_transfer.lock.expiration - channel_state.reveal_timeout - TRANSIT_BLOCKS
    refund_transfer = factories.make_signed_transfer(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        expiration,
        UNIT_SECRET,
        identifier=original_transfer.identifier,
        channel_identifier=channel1.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )

    state_change = ReceiveTransferRefundCancelRoute(
        sender=channel_state.partner_state.address,
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )
    assert iteration.new_state is None
    assert len(iteration.events) == 2

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventTransferSentFailed))

    assert unlocked_failed
    assert sent_failed


def test_refund_transfer_invalid_sender():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1

    channel1 = factories.make_channel(
        our_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    original_transfer = current_state.initiator.transfer
    channel_identifier = current_state.initiator.channel_identifier
    channel_state = channelmap[channel_identifier]

    expiration = original_transfer.lock.expiration - channel_state.reveal_timeout - TRANSIT_BLOCKS
    refund_transfer = factories.make_signed_transfer(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        expiration,
        UNIT_SECRET,
    )

    wrong_sender_address = factories.HOP3
    state_change = ReceiveTransferRefundCancelRoute(
        sender=wrong_sender_address,
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    before_state = deepcopy(current_state)
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )
    assert iteration.new_state is not None
    assert not iteration.events
    assert iteration.new_state == before_state


def test_cancel_transfer():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1

    channel1 = factories.make_channel(
        our_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channelmap,
        block_number,
    )

    state_change = ActionCancelPayment(
        identifier=UNIT_TRANSFER_IDENTIFIER,
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channelmap,
        block_number,
    )
    assert iteration.new_state is None
    assert len(iteration.events) == 2

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventTransferSentFailed))

    assert unlocked_failed
    assert sent_failed
