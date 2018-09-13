# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
import random
from copy import deepcopy

from raiden.constants import MAXIMUM_PENDING_TRANSFERS
from raiden.settings import DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK
from raiden.tests.utils import events, factories
from raiden.tests.utils.factories import (
    ADDR,
    UNIT_REGISTRY_IDENTIFIER,
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
from raiden.transfer.events import EventPaymentSentFailed, EventPaymentSentSuccess
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
from raiden.transfer.mediated_transfer.state import InitiatorPaymentState
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute,
    ActionInitInitiator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state import RouteState, message_identifier_from_prng
from raiden.transfer.state_change import ActionCancelPayment, Block, ContractReceiveSecretReveal
from raiden.utils import random_secret


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
    assert state.initiator.channel_identifier == channel1.identifier, msg
    assert not state.cancelled_channels

    state_change = ActionCancelRoute(
        UNIT_REGISTRY_IDENTIFIER,
        channel1.identifier,
        available_routes,
    )
    iteration = initiator_manager.state_transition(
        state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
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
    assert payment_state.initiator.transfer_description == factories.UNIT_TRANSFER_DESCRIPTION

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
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    lock = channel.get_lock(
        channel1.our_state,
        current_state.initiator.transfer_description.secrethash,
    )

    state_change = ReceiveSecretRequest(
        UNIT_TRANSFER_IDENTIFIER,
        lock.amount,
        lock.expiration,
        lock.secrethash,
        UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], SendSecretReveal)


def test_state_wait_unlock_valid():
    block_number = 1
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    # setup the state for the wait unlock
    current_state.initiator.revealsecret = SendSecretReveal(
        recipient=UNIT_TRANSFER_TARGET,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
        message_identifier=UNIT_TRANSFER_IDENTIFIER,
        secret=UNIT_SECRET,
    )

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=channel1.partner_state.address,
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    assert len(iteration.events) == 3
    assert any(isinstance(e, SendBalanceProof) for e in iteration.events)
    assert any(isinstance(e, EventPaymentSentSuccess) for e in iteration.events)
    assert any(isinstance(e, EventUnlockSuccess) for e in iteration.events)

    balance_proof = next(e for e in iteration.events if isinstance(e, SendBalanceProof))
    complete = next(e for e in iteration.events if isinstance(e, EventPaymentSentSuccess))

    assert balance_proof.recipient == channel1.partner_state.address
    assert complete.identifier == UNIT_TRANSFER_IDENTIFIER
    assert iteration.new_state is None, 'state must be cleaned'


def test_state_wait_unlock_invalid():
    identifier = 1
    block_number = 1
    target_address = factories.HOP2
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    # setup the state for the wait unlock
    current_state.initiator.revealsecret = SendSecretReveal(
        recipient=target_address,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
        message_identifier=identifier,
        secret=UNIT_SECRET,
    )

    before_state = deepcopy(current_state)

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=factories.ADDR,
    )
    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
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

    original_transfer = current_state.initiator.transfer
    channel_identifier = current_state.initiator.channel_identifier
    channel_state = channel_map[channel_identifier]

    refund_transfer = factories.make_signed_transfer(
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
    assert iteration.new_state.initiator is not None


def test_refund_transfer_no_more_routes():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        partner_address=refund_address,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    original_transfer = current_state.initiator.transfer
    channel_identifier = current_state.initiator.channel_identifier
    channel_state = channel_map[channel_identifier]

    refund_transfer = factories.make_signed_transfer(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        original_transfer.lock.expiration,
        UNIT_SECRET,
        payment_identifier=original_transfer.payment_identifier,
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
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    assert iteration.new_state is None

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventPaymentSentFailed))

    assert unlocked_failed
    assert sent_failed


def test_refund_transfer_invalid_sender():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    original_transfer = current_state.initiator.transfer
    refund_transfer = factories.make_signed_transfer(
        amount,
        original_transfer.initiator,
        original_transfer.target,
        original_transfer.lock.expiration,
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
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    assert iteration.new_state is not None
    assert not iteration.events
    assert iteration.new_state == before_state


def test_cancel_transfer():
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    state_change = ActionCancelPayment(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
    )

    iteration = initiator_manager.state_transition(
        current_state,
        state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    assert iteration.new_state is None
    assert len(iteration.events) == 2

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventPaymentSentFailed))

    assert unlocked_failed
    assert sent_failed


def test_action_cancel_route_comparison():
    """There was a bug in ActionCancelRoute comparison function which we check for"""
    routes1 = []
    routes2 = [RouteState(ADDR, ADDR)]
    a = ActionCancelRoute(UNIT_TRANSFER_INITIATOR, 5, routes1)
    b = ActionCancelRoute(UNIT_TRANSFER_TARGET, 5, routes1)
    c = ActionCancelRoute(UNIT_TRANSFER_TARGET, 3, routes2)
    d = ActionCancelRoute(UNIT_TRANSFER_TARGET, 3, routes2)

    assert a != b
    assert a != c
    assert c == d


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


def test_handle_secretreveal():
    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    channel_map = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]
    pseudo_random_generator = random.Random()
    block_number = 10

    manager_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=channel1.partner_state.address,
    )

    message_identifier = message_identifier_from_prng(deepcopy(pseudo_random_generator))

    iteration = initiator.handle_secretreveal(
        initiator_state=manager_state.initiator,
        state_change=secret_reveal,
        channel_state=channel1,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert events.must_contain_entry(iteration.events, SendBalanceProof, {
        'message_identifier': message_identifier,
        'payment_identifier': manager_state.initiator.transfer_description.payment_identifier,
    })


def test_initiator_lock_expired():
    amount = UNIT_TRANSFER_AMOUNT * 2
    block_number = 1
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

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
    current_state = make_initiator_manager_state(
        available_routes,
        factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    transfer = current_state.initiator.transfer

    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    # Trigger lock expiry
    state_change = Block(
        block_number=transfer.lock.expiration + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK,
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

    assert events.must_contain_entry(iteration.events, SendLockExpired, {
        'balance_proof': {
            'nonce': 2,
            'transferred_amount': 0,
            'locked_amount': 0,
        },
        'secrethash': transfer.lock.secrethash,
        'recipient': channel1.partner_state.address,
    })

    assert transfer.lock.secrethash not in channel1.our_state.secrethashes_to_lockedlocks

    # Create 2 other transfers
    transfer2_state = make_initiator_manager_state(
        available_routes,
        make_transfer_description('transfer2'),
        channel_map,
        pseudo_random_generator,
        30,
    )
    transfer2_lock = transfer2_state.initiator.transfer.lock

    transfer3_state = make_initiator_manager_state(
        available_routes,
        make_transfer_description('transfer3'),
        channel_map,
        pseudo_random_generator,
        32,
    )

    transfer3_lock = transfer3_state.initiator.transfer.lock

    assert len(channel1.our_state.secrethashes_to_lockedlocks) == 2

    assert transfer2_lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    expiration_block_number = transfer2_lock.expiration + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK

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


def test_initiator_handle_contract_receive_secret_reveal():
    """ Make sure the initiator handles ContractReceiveSecretReveal
    and checks the existence of the transfer's secrethash in
    secrethashes_to_lockedlocks and secrethashes_to_onchain_unlockedlocks. """
    amount = UNIT_TRANSFER_AMOUNT * 2
    block_number = 1
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    )
    pseudo_random_generator = random.Random()

    channel_map = {
        channel1.identifier: channel1,
    }

    available_routes = [
        factories.route_from_channel(channel1),
    ]

    block_number = 10
    current_state = make_initiator_manager_state(
        routes=available_routes,
        transfer_description=factories.UNIT_TRANSFER_DESCRIPTION,
        channel_map=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    transfer = current_state.initiator.transfer

    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
    )

    initiator_manager.handle_onchain_secretreveal(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks
    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_onchain_unlockedlocks
