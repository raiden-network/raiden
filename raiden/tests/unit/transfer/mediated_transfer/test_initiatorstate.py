# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
import random
from copy import deepcopy
from typing import NamedTuple

import pytest

from raiden.constants import EMPTY_HASH, EMPTY_MERKLE_ROOT, MAXIMUM_PENDING_TRANSFERS
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    EMPTY,
    UNIT_SECRET,
    UNIT_TOKEN_ADDRESS,
    UNIT_TOKEN_NETWORK_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_TARGET,
    make_transfer_description,
)
from raiden.transfer import channel
from raiden.transfer.architecture import State
from raiden.transfer.events import (
    EventInvalidReceivedLockExpired,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    SendProcessed,
)
from raiden.transfer.mediated_transfer import initiator, initiator_manager
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.state import InitiatorPaymentState, InitiatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state import (
    HashTimeLockState,
    NettingChannelState,
    RouteState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionCancelPayment,
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveSecretReveal,
)
from raiden.utils import random_secret, typing


def get_transfer_at_index(
        payment_state: InitiatorPaymentState,
        index: int,
) -> InitiatorTransferState:
    key = list(payment_state.initiator_transfers.keys())[index]
    return payment_state.initiator_transfers[key]


def make_initiator_manager_state(
        routes,
        transfer_description,
        channel_map,
        pseudo_random_generator,
        block_number,
):

    init_state_change = ActionInitInitiator(
        transfer_description,
        routes,
    )

    inital_state = None
    iteration = initiator_manager.state_transition(
        inital_state,
        init_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    return iteration.new_state


class InitiatorSetup(NamedTuple):
    current_state: State
    block_number: typing.BlockNumber
    channel: NettingChannelState
    channel_map: typing.ChannelMap
    available_routes: typing.List[RouteState]
    prng: random.Random
    lock: HashTimeLockState


def setup_initiator_tests(
        amount=UNIT_TRANSFER_AMOUNT,
        partner_balance=EMPTY,
        our_address=EMPTY,
        partner_address=EMPTY,
        block_number=1,
) -> InitiatorSetup:
    """Commonly used setup code for initiator manager and channel"""
    prng = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=partner_balance,
        our_address=our_address,
        partner_address=partner_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        prng,
        block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    lock = channel.get_lock(
        channel1.our_state,
        initiator_state.transfer_description.secrethash,
    )
    setup = InitiatorSetup(
        current_state=current_state,
        block_number=block_number,
        channel=channel1,
        channel_map=channel_map,
        available_routes=available_routes,
        prng=prng,
        lock=lock,
    )
    return setup


def test_next_route():
    amount = UNIT_TRANSFER_AMOUNT
    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel3 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    pseudo_random_generator = random.Random()

    channel_map = {
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
    state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    msg = 'an initialized state must use the first valid route'
    initiator_state = get_transfer_at_index(state, 0)
    assert initiator_state.channel_identifier == channel1.identifier, msg
    assert not state.cancelled_channels

    iteration = initiator_manager.maybe_try_new_route(
        payment_state=state,
        initiator_state=initiator_state,
        transfer_description=initiator_state.transfer_description,
        available_routes=available_routes,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # HOP3 should be ignored because it doesnt have enough balance
    assert iteration.new_state.cancelled_channels == [channel1.identifier]


def test_init_with_usable_routes():
    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    pseudo_random_generator = random.Random()

    init_state_change = ActionInitInitiator(
        factories.UNIT_TRANSFER_DESCRIPTION,
        available_routes,
    )

    block_number = 1
    transition = initiator_manager.state_transition(
        None,
        init_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    assert isinstance(transition.new_state, InitiatorPaymentState)
    assert transition.events, 'we have a valid route, the mediated transfer event must be emitted'

    payment_state = transition.new_state
    initiator_state = get_transfer_at_index(payment_state, 0)
    assert initiator_state.transfer_description == factories.UNIT_TRANSFER_DESCRIPTION

    mediated_transfers = [e for e in transition.events if isinstance(e, SendLockedTransfer)]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'

    send_mediated_transfer = mediated_transfers[0]
    transfer = send_mediated_transfer.transfer
    expiration = initiator.get_initial_lock_expiration(block_number, channel1.reveal_timeout)

    assert transfer.balance_proof.token_network_identifier == channel1.token_network_identifier
    assert transfer.lock.amount == factories.UNIT_TRANSFER_DESCRIPTION.amount
    assert transfer.lock.expiration == expiration
    assert transfer.lock.secrethash == factories.UNIT_TRANSFER_DESCRIPTION.secrethash
    assert send_mediated_transfer.recipient == channel1.partner_state.address


def test_init_without_routes():
    block_number = 1
    routes = []
    pseudo_random_generator = random.Random()

    init_state_change = ActionInitInitiator(
        factories.UNIT_TRANSFER_DESCRIPTION,
        routes,
    )

    channel_map = dict()
    iteration = initiator_manager.state_transition(
        None,
        init_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    assert iteration.new_state is None

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], EventPaymentSentFailed)
    assert iteration.new_state is None


def test_state_wait_secretrequest_valid():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], SendSecretReveal)

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is True

    state_change_2 = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        iteration.new_state,
        state_change_2,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert not iteration2.events


def test_state_wait_secretrequest_invalid_amount():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount + 1,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    msg = 'The payment event now is emitted when the lock expires'
    assert search_for_item(iteration.events, EventPaymentSentFailed, {}) is None, msg

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is True

    state_change_2 = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        iteration.new_state,
        state_change_2,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert len(iteration2.events) == 0


def test_state_wait_secretrequest_invalid_amount_and_sender():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount + 1,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_INITIATOR,
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert len(iteration.events) == 0
    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is False

    # Now the proper target sends the message, this should be applied
    state_change_2 = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        iteration.new_state,
        state_change_2,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    initiator_state = get_transfer_at_index(iteration2.new_state, 0)
    assert initiator_state.received_secret_request is True
    assert isinstance(iteration2.events[0], SendSecretReveal)


def test_state_wait_unlock_valid():
    setup = setup_initiator_tests()

    # setup the state for the wait unlock
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    initiator_state.revealsecret = SendSecretReveal(
        recipient=UNIT_TRANSFER_TARGET,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
        message_identifier=UNIT_TRANSFER_IDENTIFIER,
        secret=UNIT_SECRET,
    )

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=setup.channel.partner_state.address,
    )
    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert len(iteration.events) == 3
    assert any(isinstance(e, SendBalanceProof) for e in iteration.events)
    assert any(isinstance(e, EventPaymentSentSuccess) for e in iteration.events)
    assert any(isinstance(e, EventUnlockSuccess) for e in iteration.events)

    balance_proof = next(e for e in iteration.events if isinstance(e, SendBalanceProof))
    complete = next(e for e in iteration.events if isinstance(e, EventPaymentSentSuccess))

    assert balance_proof.recipient == setup.channel.partner_state.address
    assert complete.identifier == UNIT_TRANSFER_IDENTIFIER
    assert iteration.new_state is None, 'state must be cleaned'


def test_state_wait_unlock_invalid():
    setup = setup_initiator_tests()
    identifier = setup.channel.identifier
    target_address = factories.HOP2

    # setup the state for the wait unlock
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    initiator_state.revealsecret = SendSecretReveal(
        recipient=target_address,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
        message_identifier=identifier,
        secret=UNIT_SECRET,
    )

    before_state = deepcopy(setup.current_state)

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=factories.ADDR,
    )
    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    assert not iteration.events
    assert iteration.new_state == before_state


def test_refund_transfer_next_route():
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=our_address,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel3 = factories.make_channel(
        our_balance=amount,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )

    channel_map = {
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
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.make_signed_transfer_state(
        amount,
        our_address,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
        channel_identifier=channel1.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )
    assert channel1.partner_state.address == refund_address

    state_change = ReceiveTransferRefundCancelRoute(
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    assert iteration.new_state is not None

    route_cancelled = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    new_transfer = next(e for e in iteration.events if isinstance(e, SendLockedTransfer))

    assert route_cancelled, 'The previous transfer must be cancelled'
    assert new_transfer, 'No mediated transfer event emitted, should have tried a new route'
    msg = 'the new transfer must use a new secret / secrethash'
    assert new_transfer.transfer.lock.secrethash != refund_transfer.lock.secrethash, msg

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state is not None


def test_refund_transfer_no_more_routes():
    amount = UNIT_TRANSFER_AMOUNT
    refund_pkey, refund_address = factories.make_privkey_address()
    setup = setup_initiator_tests(
        amount=amount,
        partner_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        partner_address=refund_address,
    )

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    original_transfer = initiator_state.transfer
    refund_transfer = factories.make_signed_transfer_state(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
        channel_identifier=setup.channel.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )

    state_change = ReceiveTransferRefundCancelRoute(
        routes=setup.available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )
    current_state = iteration.new_state
    # As per the description of the issue here:
    # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
    # We can fail the payment but can't delete the payment task if there are no
    # more routes, but we have to wait for the lock expiration
    assert iteration.new_state is not None

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventPaymentSentFailed))

    assert unlocked_failed
    assert sent_failed

    invalid_balance_proof = factories.make_signed_balance_proof(
        nonce=2,
        transferred_amount=original_transfer.balance_proof.transferred_amount,
        locked_amount=0,
        token_network_address=original_transfer.balance_proof.token_network_identifier,
        channel_identifier=setup.channel.identifier,
        locksroot=EMPTY_MERKLE_ROOT,
        extra_hash=original_transfer.lock.secrethash,
        sender_address=refund_address,
    )
    balance_proof = factories.make_signed_balance_proof(
        nonce=2,
        transferred_amount=original_transfer.balance_proof.transferred_amount,
        locked_amount=0,
        token_network_address=original_transfer.balance_proof.token_network_identifier,
        channel_identifier=setup.channel.identifier,
        locksroot=EMPTY_MERKLE_ROOT,
        extra_hash=original_transfer.lock.secrethash,
        sender_address=refund_address,
        private_key=refund_pkey,
    )
    invalid_lock_expired_state_change = ReceiveLockExpired(
        invalid_balance_proof,
        secrethash=original_transfer.lock.secrethash,
        message_identifier=5,
    )
    lock_expired_state_change = ReceiveLockExpired(
        balance_proof,
        secrethash=original_transfer.lock.secrethash,
        message_identifier=5,
    )
    before_expiry_block = original_transfer.lock.expiration - 1
    expiry_block = channel.get_sender_expiration_threshold(original_transfer.lock)

    # a block before lock expiration, no events should be emitted
    current_state = iteration.new_state
    state_change = Block(
        block_number=before_expiry_block,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        expiry_block,
    )
    assert not iteration.events
    assert iteration.new_state, 'payment task should not be deleted at this block'

    # process an invalid lock expired message before lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        current_state,
        invalid_lock_expired_state_change,
        setup.channel_map,
        setup.prng,
        before_expiry_block,
    )
    assert iteration.new_state, 'payment task should not be deleted at this lock expired'
    # should not be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is None
    assert search_for_item(iteration.events, EventInvalidReceivedLockExpired, {}) is not None

    # process a valid lock expired message before lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        current_state,
        lock_expired_state_change,
        setup.channel_map,
        setup.prng,
        before_expiry_block,
    )
    assert iteration.new_state, 'payment task should not be deleted at this lock expired'
    # should not be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is None

    # now we get to the lock expiration block
    current_state = iteration.new_state
    state_change = Block(
        block_number=expiry_block,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        expiry_block,
    )
    assert search_for_item(iteration.events, SendLockExpired, {}) is not None
    # Since there was a refund transfer the payment task must not have been deleted
    assert iteration.new_state is not None

    # process the lock expired message after lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        current_state,
        lock_expired_state_change,
        setup.channel_map,
        setup.prng,
        expiry_block,
    )
    # should be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is not None
    assert iteration.new_state, 'payment task should be there waiting for next block'

    # process the the block after lock expiration
    current_state = iteration.new_state
    state_change = Block(
        block_number=expiry_block + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        expiry_block + 1,
    )
    assert iteration.new_state is None, 'from this point on the payment task should go'


def test_cancel_transfer():
    setup = setup_initiator_tests()
    state_change = ActionCancelPayment(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    assert iteration.new_state is not None
    assert len(iteration.events) == 2

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventPaymentSentFailed))

    assert unlocked_failed
    assert sent_failed


def test_cancelpayment():
    """ A payment can be cancelled as long as the secret has not been revealed. """
    setup = setup_initiator_tests(
        amount=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT,
    )
    assert isinstance(setup.current_state, InitiatorPaymentState)

    state_change = ActionCancelPayment(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    msg = 'The secret has not been revealed yet, the payment can be cancelled'
    assert iteration.new_state is not None, msg

    transfer_state = get_transfer_at_index(iteration.new_state, 0)
    assert transfer_state.transfer_state == 'transfer_cancelled'

    transfer = transfer_state.transfer

    expiry_block = channel.get_sender_expiration_threshold(transfer.lock)
    expiry_block_state_change = Block(
        block_number=expiry_block,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=expiry_block_state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=expiry_block,
    )
    assert not iteration.new_state, 'payment task should be deleted at this block'


def test_invalid_cancelpayment():
    """ A payment can *NOT* be cancelled if a secret for any transfer has been
    revealed.
    """
    setup = setup_initiator_tests(
        amount=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT,
    )
    receive_secret_request = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )
    secret_transition = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=receive_secret_request,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=1,
    )

    iteration = initiator_manager.handle_cancelpayment(
        payment_state=secret_transition.new_state,
        channelidentifiers_to_channels=setup.channel_map,
    )
    msg = 'The secret *has* been revealed, the payment must not be cancelled'
    assert iteration.new_state is not None, msg
    assert not iteration.events, msg


def test_init_with_maximum_pending_transfers_exceeded():
    channel1 = factories.make_channel(
        our_balance=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    pseudo_random_generator = random.Random()

    transitions = list()
    block_number = 1
    for _ in range(MAXIMUM_PENDING_TRANSFERS + 1):
        init_state_change = ActionInitInitiator(make_transfer_description(), available_routes)
        transitions.append(initiator_manager.state_transition(
            None,
            init_state_change,
            channel_map,
            pseudo_random_generator,
            block_number,
        ))

    failed_transition = transitions.pop()
    assert all(
        isinstance(transition.new_state, InitiatorPaymentState)
        for transition in transitions
    )

    assert failed_transition.new_state is None
    assert len(failed_transition.events) == 1
    assert isinstance(failed_transition.events[0], EventPaymentSentFailed)


def test_handle_offchain_secretreveal():
    setup = setup_initiator_tests()

    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=setup.channel.partner_state.address,
    )
    message_identifier = message_identifier_from_prng(deepcopy(setup.prng))
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=initiator_state,
        state_change=secret_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.prng,
    )

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    payment_identifier = initiator_state.transfer_description.payment_identifier
    balance_proof = search_for_item(iteration.events, SendBalanceProof, {
        'message_identifier': message_identifier,
        'payment_identifier': payment_identifier,
    })
    assert balance_proof is not None


def test_handle_offchain_emptyhash_secret():
    setup = setup_initiator_tests(block_number=10)

    secret_reveal = ReceiveSecretReveal(
        secret=EMPTY_HASH,
        sender=setup.channel.partner_state.address,
    )
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=get_transfer_at_index(setup.current_state, 0),
        state_change=secret_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.prng,
    )
    secrethash = factories.UNIT_TRANSFER_DESCRIPTION.secrethash
    assert len(iteration.events) == 0
    # make sure the lock has not moved
    assert secrethash in setup.channel.our_state.secrethashes_to_lockedlocks


def test_initiator_lock_expired():
    amount = UNIT_TRANSFER_AMOUNT * 2

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    pseudo_random_generator = random.Random()

    channel_map = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
    }

    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
    ]

    block_number = 10
    transfer_description = factories.make_transfer_description(
        secret=UNIT_SECRET,
        payment_network_identifier=channel1.payment_network_identifier,
    )
    current_state = make_initiator_manager_state(
        available_routes,
        transfer_description,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    transfer = initiator_state.transfer

    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    # Trigger lock expiry
    state_change = Block(
        block_number=channel.get_sender_expiration_threshold(transfer.lock),
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    lock_expired = search_for_item(iteration.events, SendLockExpired, {
        'balance_proof': {
            'nonce': 2,
            'transferred_amount': 0,
            'locked_amount': 0,
        },
        'secrethash': transfer.lock.secrethash,
        'recipient': channel1.partner_state.address,
    })
    assert lock_expired is not None

    assert search_for_item(iteration.events, EventUnlockFailed, {})

    # Since the lock expired make sure we also get the payment sent failed event
    payment_failed = search_for_item(iteration.events, EventPaymentSentFailed, {
        'payment_network_identifier': channel1.payment_network_identifier,
        'token_network_identifier': channel1.token_network_identifier,
        'identifier': UNIT_TRANSFER_IDENTIFIER,
        'target': transfer.target,
        'reason': 'lock expired',
    })
    assert payment_failed is not None

    assert transfer.lock.secrethash not in channel1.our_state.secrethashes_to_lockedlocks
    msg = 'the initiator payment task must be deleted at block of the lock expiration'
    assert not iteration.new_state, msg

    # Create 2 other transfers
    transfer2_state = make_initiator_manager_state(
        available_routes,
        make_transfer_description('transfer2'),
        channel_map,
        pseudo_random_generator,
        30,
    )
    initiator2_state = get_transfer_at_index(transfer2_state, 0)
    transfer2_lock = initiator2_state.transfer.lock

    transfer3_state = make_initiator_manager_state(
        available_routes,
        make_transfer_description('transfer3'),
        channel_map,
        pseudo_random_generator,
        32,
    )

    initiator3_state = get_transfer_at_index(transfer3_state, 0)
    transfer3_lock = initiator3_state.transfer.lock

    assert len(channel1.our_state.secrethashes_to_lockedlocks) == 2

    assert transfer2_lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    expiration_block_number = channel.get_sender_expiration_threshold(transfer2_lock)

    block = Block(
        block_number=expiration_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = initiator_manager.state_transition(
        transfer2_state,
        block,
        channel_map,
        pseudo_random_generator,
        expiration_block_number,
    )

    # Transfer 2 expired
    assert transfer2_lock.secrethash not in channel1.our_state.secrethashes_to_lockedlocks

    # Transfer 3 is still there
    assert transfer3_lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks


def test_initiator_lock_expired_must_not_be_sent_if_channel_is_closed():
    """ If the channel is closed there is no rason to send balance proofs
    off-chain, so a remove expired lock must not be sent when the channel is
    closed.
    """
    block_number = 10
    block_hash = factories.make_block_hash()
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=block_number)

    channel_closed = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=factories.make_address(),
        token_network_identifier=setup.channel.token_network_identifier,
        channel_identifier=setup.channel.identifier,
        block_number=block_number,
        block_hash=block_hash,
    )
    channel_close_transition = channel.state_transition(
        channel_state=setup.channel,
        state_change=channel_closed,
        block_number=block_number,
        block_hash=block_hash,
    )
    channel_state = channel_close_transition.new_state

    expiration_block_number = channel.get_sender_expiration_threshold(setup.lock)
    block = Block(
        block_number=expiration_block_number,
        gas_limit=1,
        block_hash=factories.make_block_hash(),
    )
    channel_map = {channel_state.identifier: channel_state}
    iteration = initiator_manager.state_transition(
        setup.current_state,
        block,
        channel_map,
        setup.prng,
        expiration_block_number,
    )
    assert search_for_item(iteration.events, SendLockExpired, {}) is None


def test_initiator_handle_contract_receive_secret_reveal():
    """ Initiator must unlock off-chain if the secret is revealed on-chain and
    the channel is open.
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
        block_number=transfer.lock.expiration,
        block_hash=factories.make_block_hash(),
    )

    message_identifier = message_identifier_from_prng(deepcopy(setup.prng))

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=transfer.lock.expiration,
    )

    payment_identifier = initiator_state.transfer_description.payment_identifier
    balance_proof = search_for_item(iteration.events, SendBalanceProof, {
        'message_identifier': message_identifier,
        'payment_identifier': payment_identifier,
    })
    assert balance_proof is not None


def test_initiator_handle_contract_receive_emptyhash_secret_reveal():
    """ Initiator must not accept contract receive secret reveal with emptyhash
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=EMPTY_HASH,
        block_number=transfer.lock.expiration,
        block_hash=factories.make_block_hash(),
    )

    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=transfer.lock.expiration,
    )
    assert len(iteration.events) == 0
    # make sure the original lock wasn't moved
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks


def test_initiator_handle_contract_receive_secret_reveal_expired():
    """ Initiator must *not* unlock off-chain if the secret is revealed
    on-chain *after* the lock expiration.
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
        block_number=transfer.lock.expiration + 1,
        block_hash=factories.make_block_hash(),
    )

    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=transfer.lock.expiration + 1,
    )

    assert search_for_item(iteration.events, SendBalanceProof, {}) is None


def test_initiator_handle_contract_receive_after_channel_closed():
    """ Initiator must accept on-chain secret reveal if the channel is closed.
    However, the off-chain unlock must not be done!

    This will happen because secrets are registered after a channel is closed,
    during the settlement window.
    """
    block_number = 10
    block_hash = factories.make_block_hash()
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=block_number)

    initiator_task = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_task.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    channel_closed = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=factories.make_address(),
        token_network_identifier=setup.channel.token_network_identifier,
        channel_identifier=setup.channel.identifier,
        block_number=block_number,
        block_hash=block_hash,
    )

    channel_close_transition = channel.state_transition(
        channel_state=setup.channel,
        state_change=channel_closed,
        block_number=block_number,
        block_hash=block_hash,
    )
    channel_state = channel_close_transition.new_state

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
        block_number=transfer.lock.expiration,
        block_hash=factories.make_block_hash(),
    )

    channel_map = {
        channel_state.identifier: channel_state,
    }
    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=setup.prng,
        block_number=transfer.lock.expiration + 1,
    )
    initiator_task = get_transfer_at_index(setup.current_state, 0)
    secrethash = initiator_task.transfer_description.secrethash
    assert secrethash in channel_state.our_state.secrethashes_to_onchain_unlockedlocks

    msg = 'The channel is closed already, the balance proof must not be sent off-chain'
    assert search_for_item(iteration.events, SendBalanceProof, {}) is None, msg


def test_lock_expiry_updates_balance_proof():
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    nonce_before_lock_expiry = setup.channel.our_state.balance_proof.nonce

    # Trigger lock expiry
    state_change = Block(
        block_number=channel.get_sender_expiration_threshold(transfer.lock),
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )

    balance_proof = setup.channel.our_state.balance_proof
    assert balance_proof.nonce == nonce_before_lock_expiry + 1
    assert balance_proof.transferred_amount == 0
    assert balance_proof.locked_amount == 0


def test_secret_reveal_cancel_other_transfers():
    """ Once an initiator manager receives a secretreveal
    on one of the pending transfers, all other pending
    transfers should be cancelled. Any secret requests / reveals
    for any of the other now-cancelled requests should be rejected.
    """
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=our_address,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel3 = factories.make_channel(
        our_balance=amount,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )

    channel_map = {
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
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.make_signed_transfer_state(
        amount,
        our_address,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
        channel_identifier=channel1.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )
    assert channel1.partner_state.address == refund_address

    state_change = ReceiveTransferRefundCancelRoute(
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert iteration.new_state is not None

    initial_transfer = get_transfer_at_index(iteration.new_state, 0)
    assert initial_transfer is not None
    assert initial_transfer.transfer_state == 'transfer_pending'

    rerouted_transfer = get_transfer_at_index(iteration.new_state, 1)
    assert rerouted_transfer is not None
    assert rerouted_transfer.transfer_state == 'transfer_pending'

    # A secretreveal for a pending transfer should succeed
    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=channel1.partner_state.address,
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert search_for_item(iteration.events, SendBalanceProof, {}) is not None
    # An unlock should only be sent to the intended transfer that we received
    # a secret reveal for. So there should only be 1 balance proof to be sent
    assert len(list(filter(lambda e: isinstance(e, SendBalanceProof), iteration.events))) == 1

    rerouted_transfer = get_transfer_at_index(iteration.new_state, 0)
    assert rerouted_transfer.transfer_state == 'transfer_cancelled'

    secret_reveal = ReceiveSecretReveal(
        secret=rerouted_transfer.transfer_description.secret,
        sender=channel1.partner_state.address,
    )

    # An existing transfer was already unlocked,
    # so subsequent secretreveals for other transfers are ignored
    with pytest.raises(AssertionError):
        iteration = initiator_manager.state_transition(
            payment_state=iteration.new_state,
            state_change=secret_reveal,
            channelidentifiers_to_channels=channel_map,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )


def test_refund_after_secret_request():
    """ A refund transfer after the original transfer's secret
    is requested should fail to be cancelled.
    """
    amount = UNIT_TRANSFER_AMOUNT
    refund_pkey, refund_address = factories.make_privkey_address()
    setup = setup_initiator_tests(
        amount=amount,
        partner_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        partner_address=refund_address,
    )

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    original_transfer = initiator_state.transfer

    secret_request = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        setup.lock.amount,
        setup.lock.expiration,
        setup.lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=secret_request,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    current_state = iteration.new_state
    assert current_state is not None

    refund_transfer = factories.make_signed_transfer_state(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
        channel_identifier=setup.channel.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )

    state_change = ReceiveTransferRefundCancelRoute(
        routes=setup.available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )
    current_state = iteration.new_state
    assert current_state is not None
    assert search_for_item(iteration.events, EventUnlockFailed, {}) is None


def test_clearing_payment_state_on_lock_expires_with_refunded_transfers():
    """ Create an initiator manager state where we have nodes with channels:
    A - > B
    |
    ---> C
    A sends B a transfer and B refunds.
    A reroutes the transfer to C.
    Now A has 2 transfers and B has 1.
    The initiator manager state should be cleared if all
    transfers have been removed (in the case of A that's 2)
    But it also waits for the refund transfer from B to be expired.
    """
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=our_address,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=amount,
        our_address=our_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )

    channel_map = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
    }

    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
    ]

    block_number = 10
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.make_signed_transfer_state(
        amount,
        our_address,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
        channel_identifier=channel1.identifier,
        pkey=refund_pkey,
        sender=refund_address,
    )

    state_change = ReceiveTransferRefundCancelRoute(
        routes=available_routes,
        transfer=refund_transfer,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 10,
    )
    assert iteration.new_state is not None

    initial_transfer_state = get_transfer_at_index(iteration.new_state, 0)
    initial_transfer = initial_transfer_state.transfer

    assert initial_transfer_state is not None
    assert initial_transfer_state.channel_identifier == channel1.identifier

    rerouted_transfer_state = get_transfer_at_index(iteration.new_state, 1)
    rerouted_transfer = rerouted_transfer_state.transfer
    assert rerouted_transfer_state is not None
    assert rerouted_transfer_state.channel_identifier == channel2.identifier

    ##
    # Expire both locks of the initial transfer and it's refund
    ##
    balance_proof = factories.make_signed_balance_proof(
        nonce=2,
        transferred_amount=initial_transfer.balance_proof.transferred_amount,
        locked_amount=0,
        token_network_address=initial_transfer.balance_proof.token_network_identifier,
        channel_identifier=channel1.identifier,
        locksroot=EMPTY_MERKLE_ROOT,
        extra_hash=initial_transfer.lock.secrethash,
        sender_address=refund_address,
        private_key=refund_pkey,
    )
    lock_expired_state_change = ReceiveLockExpired(
        balance_proof,
        secrethash=initial_transfer.lock.secrethash,
        message_identifier=5,
    )

    expiry_block = channel.get_sender_expiration_threshold(initial_transfer.lock)
    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert iteration.new_state, 'payment task should not be deleted at this block'

    initial_transfer_expiry_block_state_change = Block(
        block_number=expiry_block,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=initial_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert iteration.new_state, 'payment task should not be deleted at this block'

    ##
    # The initiator manager state still has pending transfer, so we expire
    # the rerouted transfer and it's refund to check if the payment state
    # is cleared as expected.
    ##
    expiry_block = channel.get_sender_expiration_threshold(rerouted_transfer.lock)
    rerouted_transfer_expiry_block_state_change = Block(
        block_number=expiry_block,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=rerouted_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert not iteration.new_state, 'payment task should be deleted at this block'
