# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
import random
from copy import deepcopy
from typing import NamedTuple

from raiden.constants import EMPTY_HASH, MAXIMUM_PENDING_TRANSFERS
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import events, factories
from raiden.tests.utils.factories import (
    ADDR,
    EMPTY,
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
from raiden.transfer.architecture import State
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
from raiden.transfer.state import (
    HashTimeLockState,
    NettingChannelState,
    RouteState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import ActionCancelPayment, Block, ContractReceiveSecretReveal
from raiden.utils import random_secret, typing


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

    lock = channel.get_lock(
        channel1.our_state,
        current_state.initiator.transfer_description.secrethash,
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
    assert iteration.new_state.initiator.received_secret_request is True

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

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], EventPaymentSentFailed)
    assert iteration.new_state.initiator.received_secret_request is True

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
    assert iteration.new_state.initiator.received_secret_request is False

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

    assert iteration2.new_state.initiator.received_secret_request is True
    assert isinstance(iteration2.events[0], SendSecretReveal)


def test_state_wait_unlock_valid():
    setup = setup_initiator_tests()

    # setup the state for the wait unlock
    setup.current_state.initiator.revealsecret = SendSecretReveal(
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
    setup.current_state.initiator.revealsecret = SendSecretReveal(
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

    original_transfer = current_state.initiator.transfer

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
    assert iteration.new_state.initiator is not None


def test_refund_transfer_no_more_routes():
    amount = UNIT_TRANSFER_AMOUNT
    refund_pkey, refund_address = factories.make_privkey_address()
    setup = setup_initiator_tests(
        amount=amount,
        partner_balance=amount,
        our_address=UNIT_TRANSFER_INITIATOR,
        partner_address=refund_address,
    )

    original_transfer = setup.current_state.initiator.transfer
    refund_transfer = factories.make_signed_transfer(
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
    assert iteration.new_state is None

    unlocked_failed = next(e for e in iteration.events if isinstance(e, EventUnlockFailed))
    sent_failed = next(e for e in iteration.events if isinstance(e, EventPaymentSentFailed))

    assert unlocked_failed
    assert sent_failed


def test_cancel_transfer():
    setup = setup_initiator_tests()
    state_change = ActionCancelPayment(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
    )

    iteration = initiator_manager.state_transition(
        setup.current_state,
        state_change,
        setup.channel_map,
        setup.prng,
        setup.block_number,
    )
    assert iteration.new_state is None
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

    iteration = initiator_manager.handle_cancelpayment(
        payment_state=setup.current_state,
        channel_state=setup.channel,
    )
    msg = 'The secret has not been revealed yet, the payment can be cancelled'
    assert iteration.new_state is None, msg


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
        channel_state=setup.channel,
    )
    msg = 'The secret *has* been revealed, the payment must not be cancelled'
    assert iteration.new_state is not None, msg
    assert not iteration.events, msg


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


def test_handle_offchain_secretreveal():
    setup = setup_initiator_tests()

    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=setup.channel.partner_state.address,
    )
    message_identifier = message_identifier_from_prng(deepcopy(setup.prng))
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=setup.current_state.initiator,
        state_change=secret_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.prng,
    )

    payment_identifier = setup.current_state.initiator.transfer_description.payment_identifier
    assert events.must_contain_entry(iteration.events, SendBalanceProof, {
        'message_identifier': message_identifier,
        'payment_identifier': payment_identifier,
    })


def test_handle_offchain_emptyhash_secret():
    setup = setup_initiator_tests(block_number=10)

    secret_reveal = ReceiveSecretReveal(
        secret=EMPTY_HASH,
        sender=setup.channel.partner_state.address,
    )
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=setup.current_state.initiator,
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

    transfer = current_state.initiator.transfer

    assert transfer.lock.secrethash in channel1.our_state.secrethashes_to_lockedlocks

    # Trigger lock expiry
    state_change = Block(
        block_number=transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2,
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
    # Since the lock expired make sure we also get the payment sent failed event
    assert events.must_contain_entry(iteration.events, EventPaymentSentFailed, {
        'payment_network_identifier': channel1.payment_network_identifier,
        'token_network_identifier': channel1.token_network_identifier,
        'identifier': UNIT_TRANSFER_IDENTIFIER,
        'target': transfer.target,
        'reason': "transfer's lock has expired",
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

    expiration_block_number = transfer2_lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2

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
    """ Initiator must unlock off-chain if the secret is revealed on-chain and
    the channel is open.
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    transfer = setup.current_state.initiator.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
        block_number=transfer.lock.expiration,
    )

    message_identifier = message_identifier_from_prng(deepcopy(setup.prng))

    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
    )

    payment_identifier = setup.current_state.initiator.transfer_description.payment_identifier
    assert events.must_contain_entry(iteration.events, SendBalanceProof, {
        'message_identifier': message_identifier,
        'payment_identifier': payment_identifier,
    })


def test_initiator_handle_contract_receive_emptyhash_secret_reveal():
    """ Initiator must not accept contract receive secret reveal with emptyhash
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    transfer = setup.current_state.initiator.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=EMPTY_HASH,
        block_number=transfer.lock.expiration,
    )

    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
    )
    assert len(iteration.events) == 0
    # make sure the original lock wasn't moved
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks


def test_initiator_handle_contract_receive_secret_reveal_expired():
    """ Initiator must *not* unlock off-chain if the secret is revealed
    on-chain *after* the lock expiration.
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    transfer = setup.current_state.initiator.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    state_change = ContractReceiveSecretReveal(
        transaction_hash=factories.make_transaction_hash(),
        secret_registry_address=factories.make_address(),
        secrethash=transfer.lock.secrethash,
        secret=UNIT_SECRET,
        block_number=transfer.lock.expiration + 1,
    )

    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        pseudo_random_generator=setup.prng,
    )

    assert events.must_contain_entry(iteration.events, SendBalanceProof, {}) is None


def test_lock_expiry_updates_balance_proof():
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    transfer = setup.current_state.initiator.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    nonce_before_lock_expiry = setup.channel.our_state.balance_proof.nonce

    # Trigger lock expiry
    state_change = Block(
        block_number=transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2,
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
