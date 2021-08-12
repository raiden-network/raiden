# pylint: disable=invalid-name,too-few-public-methods,too-many-arguments,too-many-locals
import random
import uuid
from typing import NamedTuple
from unittest.mock import patch

import pytest
from eth_utils import keccak

from raiden.constants import EMPTY_HASH, MAXIMUM_PENDING_TRANSFERS
from raiden.raiden_service import initiator_init
from raiden.settings import DEFAULT_MEDIATION_FEE_MARGIN, MAX_MEDIATION_FEE_PERC
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    EMPTY,
    UNIT_SECRET,
    UNIT_TOKEN_NETWORK_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_TARGET,
    ChannelSet,
    TransferDescriptionProperties,
    create,
)
from raiden.tests.utils.mocks import MockRaidenService
from raiden.tests.utils.transfer import assert_dropped
from raiden.transfer import channel
from raiden.transfer.architecture import State
from raiden.transfer.events import (
    EventInvalidReceivedLockExpired,
    EventInvalidSecretRequest,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    SendProcessed,
)
from raiden.transfer.mediated_transfer import initiator, initiator_manager
from raiden.transfer.mediated_transfer.events import (
    EventRouteFailed,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendLockedTransfer,
    SendLockExpired,
    SendSecretReveal,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.initiator import (
    calculate_fee_margin,
    calculate_safe_amount_with_fee,
)
from raiden.transfer.mediated_transfer.state import InitiatorPaymentState, InitiatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionTransferReroute,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferCancelRoute,
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
from raiden.utils import typing
from raiden.utils.copy import deepcopy
from raiden.utils.transfers import random_secret
from raiden.utils.typing import Address, BlockNumber, FeeAmount, PaymentAmount, TokenAmount


def get_transfer_at_index(
    payment_state: InitiatorPaymentState, index: int
) -> InitiatorTransferState:
    key = list(payment_state.initiator_transfers.keys())[index]
    return payment_state.initiator_transfers[key]


def make_initiator_manager_state(
    channels: factories.ChannelSet,
    pseudo_random_generator: random.Random,
    transfer_description: factories.TransferDescriptionWithSecretState = None,
    block_number: BlockNumber = BlockNumber(1),  # noqa: B008
    estimated_fee: FeeAmount = FeeAmount(0),  # noqa: B008
):
    init = ActionInitInitiator(
        transfer=transfer_description or factories.UNIT_TRANSFER_DESCRIPTION,
        routes=channels.get_routes(estimated_fee=estimated_fee),
    )
    initial_state = None
    iteration = initiator_manager.state_transition(
        payment_state=initial_state,
        state_change=init,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    return iteration.new_state


class InitiatorSetup(NamedTuple):
    current_state: State
    block_number: typing.BlockNumber
    channel: NettingChannelState
    channel_map: typing.Dict[typing.ChannelID, NettingChannelState]
    channels: ChannelSet
    available_routes: typing.List[RouteState]
    prng: random.Random
    lock: HashTimeLockState


def setup_initiator_tests(
    amount=UNIT_TRANSFER_AMOUNT,
    partner_balance=EMPTY,
    our_address=EMPTY,
    partner_address=EMPTY,
    block_number=1,
    allocated_fee=0,
) -> InitiatorSetup:
    """Commonly used setup code for initiator manager and channel"""
    prng = random.Random()

    fee_margin = calculate_fee_margin(amount, allocated_fee)
    properties = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties(
            balance=amount + allocated_fee + fee_margin, address=our_address
        ),
        partner_state=factories.NettingChannelEndStateProperties(
            balance=partner_balance, address=partner_address
        ),
    )
    channels = factories.make_channel_set([properties])
    transfer_description = factories.create(
        factories.TransferDescriptionProperties(secret=UNIT_SECRET)
    )
    current_state = make_initiator_manager_state(
        channels=channels,
        transfer_description=transfer_description,
        pseudo_random_generator=prng,
        block_number=block_number,
        estimated_fee=allocated_fee,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    assert initiator_state, "There should be an initial initiator state"
    lock = channel.get_lock(channels[0].our_state, initiator_state.transfer_description.secrethash)
    assert lock
    available_routes = channels.get_routes(estimated_fee=allocated_fee)
    setup = InitiatorSetup(
        current_state=current_state,
        block_number=block_number,
        channel=channels[0],
        channel_map=channels.channel_map,
        channels=channels,
        available_routes=available_routes,
        prng=prng,
        lock=lock,
    )
    return setup


def test_next_route():
    amount = UNIT_TRANSFER_AMOUNT
    channels = factories.make_channel_set_from_amounts([amount, 0, amount])
    prng = random.Random()

    block_number = 10
    state = make_initiator_manager_state(
        channels=channels, pseudo_random_generator=prng, block_number=block_number
    )

    msg = "an initialized state must use the first valid route"
    initiator_state = get_transfer_at_index(state, 0)
    assert initiator_state.channel_identifier == channels[0].identifier, msg
    assert not state.cancelled_channels

    initiator_manager.cancel_current_route(payment_state=state, initiator_state=initiator_state)
    assert state.cancelled_channels == [channels[0].identifier]


def test_init_with_usable_routes():
    transfer_amount = TokenAmount(1000)
    flat_fee = FeeAmount(20)
    expected_balance = calculate_safe_amount_with_fee(transfer_amount, flat_fee)
    properties = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties(balance=TokenAmount(expected_balance))
    )
    channels = factories.make_channel_set([properties])
    pseudo_random_generator = random.Random()

    transfer_description = create(
        TransferDescriptionProperties(secret=UNIT_SECRET, amount=transfer_amount)
    )
    routes = channels.get_routes(estimated_fee=flat_fee)
    init_state_change = ActionInitInitiator(transfer=transfer_description, routes=routes)

    block_number = BlockNumber(1)
    transition = initiator_manager.state_transition(
        payment_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert isinstance(transition.new_state, InitiatorPaymentState)
    assert transition.events, "we have a valid route, the mediated transfer event must be emitted"

    payment_state = transition.new_state
    assert len(payment_state.routes) == 1

    initiator_state = get_transfer_at_index(payment_state, 0)
    assert initiator_state.transfer_description == transfer_description

    mediated_transfers = [e for e in transition.events if isinstance(e, SendLockedTransfer)]
    assert len(mediated_transfers) == 1, "mediated_transfer should /not/ split the transfer"

    send_mediated_transfer = mediated_transfers[0]
    transfer = send_mediated_transfer.transfer
    expiration = channel.get_safe_initial_expiration(block_number, channels[0].reveal_timeout)

    assert transfer.balance_proof.token_network_address == channels[0].token_network_address
    assert transfer.balance_proof.locked_amount == expected_balance
    assert transfer.lock.amount == expected_balance
    assert transfer.lock.expiration == expiration
    assert transfer.lock.secrethash == transfer_description.secrethash
    # pylint: disable=E1101
    assert send_mediated_transfer.recipient == channels[0].partner_state.address


def test_init_with_fees_more_than_max_limit():
    transfer_amount = TokenAmount(100)
    flat_fee = FeeAmount(int(transfer_amount + MAX_MEDIATION_FEE_PERC * transfer_amount))
    expected_fee_margin = int(flat_fee * DEFAULT_MEDIATION_FEE_MARGIN)
    properties = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties(
            balance=TokenAmount(transfer_amount + flat_fee + expected_fee_margin)
        )
    )
    channels = factories.make_channel_set([properties])
    pseudo_random_generator = random.Random()

    transfer_description = create(
        TransferDescriptionProperties(secret=UNIT_SECRET, amount=transfer_amount)
    )
    routes = channels.get_routes(estimated_fee=flat_fee)
    init_state_change = ActionInitInitiator(transfer=transfer_description, routes=routes)

    block_number = BlockNumber(1)
    transition = initiator_manager.state_transition(
        payment_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert transition.new_state is None
    assert isinstance(transition.events[0], EventPaymentSentFailed)
    reason_msg = (
        "none of the available routes could be used and at least one of them "
        "exceeded the maximum fee limit "
        "(see https://raiden-network.readthedocs.io/en/stable/using-raiden-on-mainnet/overview.html#frequently-asked-questions)"  # noqa
    )
    assert transition.events[0].reason == reason_msg


def test_init_without_routes():
    block_number = BlockNumber(1)
    routes = []
    pseudo_random_generator = random.Random()

    init_state_change = ActionInitInitiator(factories.UNIT_TRANSFER_DESCRIPTION, routes)

    channel_map = {}
    iteration = initiator_manager.state_transition(
        payment_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channel_map,
        addresses_to_channel={},
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert iteration.new_state is None

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], EventPaymentSentFailed)
    assert iteration.new_state is None


def test_state_wait_secretrequest_valid():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], SendSecretReveal)

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is True

    state_change_2 = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=state_change_2,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert not iteration2.events


def test_state_wait_secretrequest_invalid_amount():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount + 1,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    msg = "The payment event now is emitted when the lock expires"
    assert search_for_item(iteration.events, EventPaymentSentFailed, {}) is None, msg

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is True

    state_change_2 = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=state_change_2,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert len(iteration2.events) == 0


def test_state_wait_secretrequest_invalid_amount_and_sender():
    setup = setup_initiator_tests()

    state_change = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount + 1,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_INITIATOR,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert len(iteration.events) == 0
    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is False

    # Now the proper target sends the message, this should be applied
    state_change_2 = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=state_change_2,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    initiator_state = get_transfer_at_index(iteration2.new_state, 0)
    assert initiator_state.received_secret_request is True
    assert isinstance(iteration2.events[0], SendSecretReveal)


def test_state_wait_unlock_valid():
    setup = setup_initiator_tests()

    # setup the state for the wait unlock
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    initiator_state.transfer_state = "transfer_secret_revealed"

    state_change = ReceiveSecretReveal(
        secret=UNIT_SECRET, sender=setup.channel.partner_state.address
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert len(iteration.events) == 3

    balance_proof = search_for_item(iteration.events, SendUnlock, {})
    complete = search_for_item(iteration.events, EventPaymentSentSuccess, {})
    assert search_for_item(iteration.events, EventUnlockSuccess, {})
    assert balance_proof
    assert complete
    assert len(complete.route) == 2
    assert complete.route[1] == balance_proof.recipient

    assert balance_proof.recipient == setup.channel.partner_state.address
    assert complete.identifier == UNIT_TRANSFER_IDENTIFIER
    assert iteration.new_state is None, "state must be cleaned"


def test_state_wait_unlock_invalid():
    setup = setup_initiator_tests()

    # setup the state for the wait unlock
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    initiator_state.transfer_state = "transfer_secret_revealed"

    before_state = deepcopy(setup.current_state)

    state_change = ReceiveSecretReveal(secret=UNIT_SECRET, sender=factories.ADDR)
    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert not iteration.events
    assert iteration.new_state == before_state


def channels_setup(
    amount: TokenAmount, our_address: Address, refund_address: Address
) -> ChannelSet:
    funded = factories.NettingChannelEndStateProperties(balance=amount, address=our_address)
    broke = factories.replace(funded, balance=0)
    funded_partner = factories.replace(funded, address=refund_address)

    properties = [
        factories.NettingChannelStateProperties(our_state=funded, partner_state=funded_partner),
        factories.NettingChannelStateProperties(our_state=broke),
        factories.NettingChannelStateProperties(our_state=funded),
    ]

    return factories.make_channel_set(properties)


def test_refund_transfer_with_reroute():
    transfer_amount = TokenAmount(1000)
    block_number = BlockNumber(10)
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    prng = random.Random()

    transfer_description = create(
        TransferDescriptionProperties(secret=UNIT_SECRET, amount=transfer_amount)
    )
    channels = channels_setup(TokenAmount(transfer_amount * 2), our_address, refund_address)

    fee_1 = 20
    fee_3 = 40

    routes = channels.get_routes()
    routes[0].estimated_fee = fee_1  # this one will be tried first and fail
    routes[1].estimated_fee = 30  # this one is not funded
    routes[2].estimated_fee = fee_3  # this one will be tried after the first fail

    init = ActionInitInitiator(transfer=transfer_description, routes=routes)
    initial_state = None
    iteration = initiator_manager.state_transition(
        payment_state=initial_state,
        state_change=init,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )
    current_state = iteration.new_state

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    # Check that fees for route 1 have been set correctly
    amount_with_fee_and_margin1 = calculate_safe_amount_with_fee(transfer_amount, fee_1)
    assert original_transfer.balance_proof.locked_amount == amount_with_fee_and_margin1
    assert original_transfer.lock.amount == amount_with_fee_and_margin1

    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=original_transfer.balance_proof.locked_amount,
            initiator=our_address,
            target=original_transfer.target,
            expiration=original_transfer.lock.expiration,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=channels[0].canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )

    assert channels[0].partner_state.address == refund_address

    state_change = ReceiveTransferCancelRoute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )
    assert iteration.new_state is not None

    route_cancelled = search_for_item(iteration.events, EventUnlockFailed, {})
    route_failed = search_for_item(iteration.events, EventRouteFailed, {})
    assert route_cancelled, "The previous transfer must be cancelled"
    assert route_failed, "Must emit event that the first route failed"

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,
        secret=random_secret(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )

    new_transfer = search_for_item(iteration.events, SendLockedTransfer, {})
    assert new_transfer, "No mediated transfer event emitted, should have tried a new route"
    msg = "the new transfer must use a new secret / secrethash"
    assert new_transfer.transfer.lock.secrethash != refund_transfer.lock.secrethash, msg

    # Check that fees for route 3 have been set correctly
    amount_with_fee_and_margin3 = calculate_safe_amount_with_fee(transfer_amount, fee_3)
    assert new_transfer.transfer.balance_proof.locked_amount == amount_with_fee_and_margin3
    assert new_transfer.transfer.lock.amount == amount_with_fee_and_margin3

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
    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=amount,
            initiator=original_transfer.initiator,
            target=original_transfer.target,
            expiration=original_transfer.lock.expiration,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=setup.channel.canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
            message_identifier=factories.make_message_identifier(),
        )
    )

    state_change = ReceiveTransferCancelRoute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    unlocked_failed = search_for_item(iteration.events, EventUnlockFailed, {})
    route_failed = search_for_item(iteration.events, EventRouteFailed, {})

    assert unlocked_failed
    assert route_failed, "Must emit event that the first route failed"

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        secret=random_secret(),
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    # As per the description of the issue here:
    # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
    # We can fail the payment but can't delete the payment task if there are no
    # more routes, but we have to wait for the lock expiration
    assert iteration.new_state is not None

    sent_failed = search_for_item(iteration.events, EventPaymentSentFailed, {})

    assert sent_failed

    missing_pkey = factories.create_properties(
        factories.BalanceProofSignedStateProperties(
            nonce=2,
            transferred_amount=original_transfer.balance_proof.transferred_amount,
            canonical_identifier=setup.channel.canonical_identifier,
            message_hash=original_transfer.lock.secrethash,
            sender=refund_address,
        )
    )
    complete = factories.create_properties(
        factories.BalanceProofSignedStateProperties(pkey=refund_pkey), defaults=missing_pkey
    )
    invalid_balance_proof = factories.create(missing_pkey)
    balance_proof = factories.create(complete)
    invalid_lock_expired_state_change = ReceiveLockExpired(
        sender=invalid_balance_proof.sender,  # pylint: disable=no-member
        balance_proof=invalid_balance_proof,
        secrethash=original_transfer.lock.secrethash,
        message_identifier=5,
    )
    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        sender=balance_proof.sender,  # pylint: disable=no-member
        secrethash=original_transfer.lock.secrethash,
        message_identifier=5,
    )
    before_expiry_block = original_transfer.lock.expiration - 1
    expiry_block = channel.get_sender_expiration_threshold(original_transfer.lock.expiration)

    # a block before lock expiration, no events should be emitted
    current_state = iteration.new_state
    state_change = Block(
        block_number=before_expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiry_block,
    )
    assert not iteration.events
    assert iteration.new_state, "payment task should not be deleted at this block"

    # process an invalid lock expired message before lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=invalid_lock_expired_state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=before_expiry_block,
    )
    assert iteration.new_state, "payment task should not be deleted at this lock expired"
    # should not be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is None
    assert search_for_item(iteration.events, EventInvalidReceivedLockExpired, {}) is not None

    # process a valid lock expired message before lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=before_expiry_block,
    )
    assert iteration.new_state, "payment task should not be deleted at this lock expired"
    # should not be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is None
    assert search_for_item(iteration.events, SendLockExpired, {}) is None

    # now we get to the lock expiration block
    current_state = iteration.new_state
    state_change = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiry_block,
    )
    assert search_for_item(iteration.events, SendLockExpired, {}) is not None
    # The lock expired, so the route failed
    assert search_for_item(iteration.events, EventRouteFailed, {}) is not None
    # # Since there was a refund transfer the payment task must not have been deleted
    assert iteration.new_state is not None

    # process the lock expired message after lock expiration
    current_state = iteration.new_state
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiry_block,
    )
    # should be accepted
    assert search_for_item(iteration.events, SendProcessed, {}) is not None
    assert iteration.new_state, "payment task should be there waiting for next block"

    # process the block after lock expiration
    current_state = iteration.new_state
    state_change = Block(
        block_number=expiry_block + 1, gas_limit=1, block_hash=factories.make_transaction_hash()
    )
    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiry_block + 1,
    )
    assert iteration.new_state is None, "from this point on the payment task should go"


def test_cancel_transfer():
    setup = setup_initiator_tests()
    state_change = ActionCancelPayment(payment_identifier=UNIT_TRANSFER_IDENTIFIER)

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    assert iteration.new_state is not None
    assert len(iteration.events) == 3

    assert search_for_item(iteration.events, EventUnlockFailed, {})
    assert search_for_item(iteration.events, EventPaymentSentFailed, {})
    assert search_for_item(iteration.events, EventRouteFailed, {})


def test_cancelpayment():
    """A payment can be cancelled as long as the secret has not been revealed."""
    setup = setup_initiator_tests(amount=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT)
    assert isinstance(setup.current_state, InitiatorPaymentState)

    state_change = ActionCancelPayment(payment_identifier=UNIT_TRANSFER_IDENTIFIER)

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    msg = "The secret has not been revealed yet, the payment can be cancelled"
    assert iteration.new_state is not None, msg

    transfer_state = get_transfer_at_index(iteration.new_state, 0)
    assert transfer_state.transfer_state == "transfer_cancelled"

    transfer = transfer_state.transfer

    expiry_block = channel.get_sender_expiration_threshold(transfer.lock.expiration)
    expiry_block_state_change = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=expiry_block_state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiry_block,
    )
    # The lock expired, so the route failed
    assert search_for_item(iteration.events, EventRouteFailed, {}) is not None
    assert not iteration.new_state, "payment task should be deleted at this block"


def test_invalid_cancelpayment():
    """A payment can *NOT* be cancelled if a secret for any transfer has been
    revealed.
    """
    setup = setup_initiator_tests(amount=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT)
    receive_secret_request = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )
    secret_transition = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=receive_secret_request,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=1,
    )

    iteration = initiator_manager.handle_cancelpayment(
        payment_state=secret_transition.new_state, channelidentifiers_to_channels=setup.channel_map
    )
    msg = "The secret *has* been revealed, the payment must not be cancelled"
    assert iteration.new_state is not None, msg
    assert not iteration.events, msg


def test_init_with_maximum_pending_transfers_exceeded():
    channel1 = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(
                balance=2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT
            )
        )
    )
    channel_map = {channel1.identifier: channel1}
    addresses_to_channel = {
        (UNIT_TOKEN_NETWORK_ADDRESS, channel1.partner_state.address): channel1,
    }
    available_routes = [
        RouteState(route=[channel1.our_state.address, channel1.partner_state.address])
    ]

    pseudo_random_generator = random.Random()

    transitions = []
    block_number = 1
    for _ in range(MAXIMUM_PENDING_TRANSFERS + 1):
        transfer_description = factories.create(factories.TransferDescriptionProperties())
        init_state_change = ActionInitInitiator(transfer_description, available_routes)
        transitions.append(
            initiator_manager.state_transition(
                payment_state=None,
                state_change=init_state_change,
                channelidentifiers_to_channels=channel_map,
                addresses_to_channel=addresses_to_channel,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
            )
        )

    failed_transition = transitions.pop()
    assert all(
        isinstance(transition.new_state, InitiatorPaymentState) for transition in transitions
    )

    assert failed_transition.new_state is None
    assert len(failed_transition.events) == 1
    assert isinstance(failed_transition.events[0], EventPaymentSentFailed)


def test_handle_offchain_secretreveal():
    setup = setup_initiator_tests()
    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET, sender=setup.channel.partner_state.address
    )
    message_identifier = message_identifier_from_prng(deepcopy(setup.prng))
    initiator_state = get_transfer_at_index(setup.current_state, 0)
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=initiator_state,
        state_change=secret_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    payment_identifier = initiator_state.transfer_description.payment_identifier
    balance_proof = search_for_item(
        iteration.events,
        SendUnlock,
        {"message_identifier": message_identifier, "payment_identifier": payment_identifier},
    )
    assert balance_proof is not None


def test_handle_offchain_emptyhash_secret():
    setup = setup_initiator_tests(block_number=10)

    secret_reveal = ReceiveSecretReveal(
        secret=EMPTY_HASH, sender=setup.channel.partner_state.address
    )
    iteration = initiator.handle_offchain_secretreveal(
        initiator_state=get_transfer_at_index(setup.current_state, 0),
        state_change=secret_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    secrethash = factories.UNIT_TRANSFER_DESCRIPTION.secrethash
    assert len(iteration.events) == 0
    # make sure the lock has not moved
    assert secrethash in setup.channel.our_state.secrethashes_to_lockedlocks


def test_initiator_lock_expired():
    amount = UNIT_TRANSFER_AMOUNT * 2
    pseudo_random_generator = random.Random()
    channels = factories.make_channel_set_from_amounts([amount, 0])

    block_number = 10
    transfer_description = factories.create(
        factories.TransferDescriptionProperties(
            secret=UNIT_SECRET,
            token_network_registry_address=channels[0].token_network_registry_address,
        )
    )
    current_state = make_initiator_manager_state(
        channels=channels,
        transfer_description=transfer_description,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    transfer = initiator_state.transfer

    # pylint: disable=E1101
    assert transfer.lock.secrethash in channels[0].our_state.secrethashes_to_lockedlocks

    # Trigger lock expiry
    state_change = Block(
        block_number=channel.get_sender_expiration_threshold(transfer.lock.expiration),
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    lock_expired = search_for_item(
        iteration.events,
        SendLockExpired,
        {
            "balance_proof": {"nonce": 2, "transferred_amount": 0, "locked_amount": 0},
            "secrethash": transfer.lock.secrethash,
            # pylint: disable=E1101
            "recipient": channels[0].partner_state.address,
        },
    )
    assert lock_expired is not None
    # The lock expired, so the route failed
    assert search_for_item(iteration.events, EventRouteFailed, {}) is not None

    assert search_for_item(iteration.events, EventUnlockFailed, {})

    # Since the lock expired make sure we also get the payment sent failed event
    payment_failed = search_for_item(
        iteration.events,
        EventPaymentSentFailed,
        {
            "token_network_registry_address": channels[0].token_network_registry_address,
            "token_network_address": channels[0].token_network_address,
            "identifier": UNIT_TRANSFER_IDENTIFIER,
            "target": transfer.target,
            "reason": "lock expired",
        },
    )
    assert payment_failed is not None

    assert transfer.lock.secrethash not in channels[0].our_state.secrethashes_to_lockedlocks
    msg = "the initiator payment task must be deleted at block of the lock expiration"
    assert not iteration.new_state, msg

    # Create 2 other transfers
    transfer2_state = make_initiator_manager_state(
        channels=channels,
        transfer_description=factories.create(
            factories.TransferDescriptionProperties(payment_identifier="transfer2")
        ),
        pseudo_random_generator=pseudo_random_generator,
        block_number=30,
    )
    initiator2_state = get_transfer_at_index(transfer2_state, 0)
    transfer2_lock = initiator2_state.transfer.lock

    transfer3_state = make_initiator_manager_state(
        channels=channels,
        transfer_description=factories.create(
            factories.TransferDescriptionProperties(payment_identifier="transfer3")
        ),
        pseudo_random_generator=pseudo_random_generator,
        block_number=32,
    )

    initiator3_state = get_transfer_at_index(transfer3_state, 0)
    transfer3_lock = initiator3_state.transfer.lock

    assert len(channels[0].our_state.secrethashes_to_lockedlocks) == 2

    assert transfer2_lock.secrethash in channels[0].our_state.secrethashes_to_lockedlocks

    expiration_block_number = channel.get_sender_expiration_threshold(transfer2_lock.expiration)

    block = Block(
        block_number=expiration_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = initiator_manager.state_transition(
        payment_state=transfer2_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiration_block_number,
    )

    # Transfer 2 expired
    assert transfer2_lock.secrethash not in channels[0].our_state.secrethashes_to_lockedlocks

    # Transfer 3 is still there
    assert transfer3_lock.secrethash in channels[0].our_state.secrethashes_to_lockedlocks


def test_initiator_lock_expired_must_not_be_sent_if_channel_is_closed():
    """If the channel is closed there is no rason to send balance proofs
    off-chain, so a remove expired lock must not be sent when the channel is
    closed.
    """
    block_number = 10
    block_hash = factories.make_block_hash()
    pseudo_random_generator = random.Random()
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=block_number)

    channel_closed = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=factories.make_address(),
        canonical_identifier=factories.make_canonical_identifier(
            chain_identifier=setup.channel.chain_id,
            token_network_address=setup.channel.token_network_address,
            channel_identifier=setup.channel.identifier,
        ),
        block_number=block_number,
        block_hash=block_hash,
    )
    channel_close_transition = channel.state_transition(
        channel_state=setup.channel,
        state_change=channel_closed,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    channel_state = channel_close_transition.new_state

    expiration_block_number = channel.get_sender_expiration_threshold(setup.lock.expiration)
    block = Block(
        block_number=expiration_block_number, gas_limit=1, block_hash=factories.make_block_hash()
    )
    channel_map = {channel_state.identifier: channel_state}
    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=block,
        channelidentifiers_to_channels=channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=expiration_block_number,
    )
    assert search_for_item(iteration.events, SendLockExpired, {}) is None
    # The lock expired, so the route failed
    assert search_for_item(iteration.events, EventRouteFailed, {}) is not None


def test_initiator_handle_contract_receive_secret_reveal():
    """Initiator must unlock off-chain if the secret is revealed on-chain and
    the channel is open.
    """
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    # pylint: disable=E1101
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
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=transfer.lock.expiration,
    )

    payment_identifier = initiator_state.transfer_description.payment_identifier
    balance_proof = search_for_item(
        iteration.events,
        SendUnlock,
        {"message_identifier": message_identifier, "payment_identifier": payment_identifier},
    )
    assert balance_proof is not None


def test_initiator_handle_contract_receive_emptyhash_secret_reveal():
    """Initiator must accept contract receive secret reveal with emptyhash"""
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
        block_number=setup.block_number,
    )

    assert len(iteration.events) == 3
    assert search_for_item(iteration.events, EventUnlockSuccess, {})
    assert transfer.lock.secrethash not in setup.channel.our_state.secrethashes_to_lockedlocks


def test_initiator_handle_contract_receive_secret_reveal_expired():
    """Initiator must *not* unlock off-chain if the secret is revealed
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
        block_number=setup.block_number,
    )

    assert search_for_item(iteration.events, SendUnlock, {}) is None


def test_initiator_handle_contract_receive_after_channel_closed():
    """Initiator must accept on-chain secret reveal if the channel is closed.
    However, the off-chain unlock must not be done!

    This will happen because secrets are registered after a channel is closed,
    during the settlement window.
    """
    block_number = 10
    block_hash = factories.make_block_hash()
    pseudo_random_generator = random.Random()
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=block_number)

    initiator_task = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_task.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    channel_closed = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=factories.make_address(),
        canonical_identifier=factories.make_canonical_identifier(
            chain_identifier=setup.channel.chain_id,
            token_network_address=setup.channel.token_network_address,
            channel_identifier=setup.channel.identifier,
        ),
        block_number=block_number,
        block_hash=block_hash,
    )

    channel_close_transition = channel.state_transition(
        channel_state=setup.channel,
        state_change=channel_closed,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
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

    channel_map = {channel_state.identifier: channel_state}
    iteration = initiator_manager.handle_onchain_secretreveal(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    initiator_task = get_transfer_at_index(setup.current_state, 0)
    secrethash = initiator_task.transfer_description.secrethash
    assert secrethash in channel_state.our_state.secrethashes_to_onchain_unlockedlocks

    msg = "The channel is closed already, the balance proof must not be sent off-chain"
    assert search_for_item(iteration.events, SendUnlock, {}) is None, msg


def test_lock_expiry_updates_balance_proof():
    setup = setup_initiator_tests(amount=UNIT_TRANSFER_AMOUNT * 2, block_number=10)

    initiator_state = get_transfer_at_index(setup.current_state, 0)
    transfer = initiator_state.transfer
    assert transfer.lock.secrethash in setup.channel.our_state.secrethashes_to_lockedlocks

    nonce_before_lock_expiry = setup.channel.our_state.balance_proof.nonce

    # Trigger lock expiry
    state_change = Block(
        block_number=channel.get_sender_expiration_threshold(transfer.lock.expiration),
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    balance_proof = setup.channel.our_state.balance_proof
    assert balance_proof.nonce == nonce_before_lock_expiry + 1
    assert balance_proof.transferred_amount == 0
    assert balance_proof.locked_amount == 0


def test_secret_reveal_cancel_other_transfers():
    """Once an initiator manager receives a secretreveal
    on one of the pending transfers, all other pending
    transfers should be cancelled. Any secret requests / reveals
    for any of the other now-cancelled requests should be rejected.
    """
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    prng = random.Random()

    channels = channels_setup(amount, our_address, refund_address)

    block_number = 10
    current_state = make_initiator_manager_state(
        channels=channels, pseudo_random_generator=prng, block_number=block_number
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=amount,
            initiator=our_address,
            target=original_transfer.target,
            expiration=original_transfer.lock.expiration,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=channels[0].canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )
    # pylint: disable=E1101
    assert channels[0].partner_state.address == refund_address

    state_change = ReceiveTransferCancelRoute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        secret=random_secret(),
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )
    assert iteration.new_state is not None

    initial_transfer = get_transfer_at_index(iteration.new_state, 0)
    assert initial_transfer is not None
    assert initial_transfer.transfer_state == "transfer_pending"

    rerouted_transfer = get_transfer_at_index(iteration.new_state, 1)
    assert rerouted_transfer is not None
    assert rerouted_transfer.transfer_state == "transfer_pending"

    # A secretreveal for a pending transfer should succeed
    secret_reveal = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        # pylint: disable=E1101
        sender=channels[0].partner_state.address,
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=block_number,
    )

    assert search_for_item(iteration.events, SendUnlock, {}) is not None
    # An unlock should only be sent to the intended transfer that we received
    # a secret reveal for. So there should only be 1 balance proof to be sent
    assert len(list(filter(lambda e: isinstance(e, SendUnlock), iteration.events))) == 1

    rerouted_transfer = get_transfer_at_index(iteration.new_state, 0)
    assert rerouted_transfer.transfer_state == "transfer_cancelled"

    secret_reveal = ReceiveSecretReveal(
        secret=rerouted_transfer.transfer_description.secret,
        # pylint: disable=E1101
        sender=channels[0].partner_state.address,
    )

    # An existing transfer was already unlocked,
    # so subsequent secretreveals for other transfers are ignored
    with pytest.raises(AssertionError):
        iteration = initiator_manager.state_transition(
            payment_state=iteration.new_state,
            state_change=secret_reveal,
            channelidentifiers_to_channels=channels.channel_map,
            addresses_to_channel=channels.addresses_to_channel(),
            pseudo_random_generator=prng,
            block_number=block_number,
        )


def test_refund_after_secret_request():
    """A refund transfer after the original transfer's secret
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
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    current_state = iteration.new_state
    assert current_state is not None

    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=amount,
            initiator=original_transfer.initiator,
            target=original_transfer.target,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=setup.channel.canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        secret=random_secret(),
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )
    current_state = iteration.new_state
    assert current_state is not None
    assert search_for_item(iteration.events, EventUnlockFailed, {}) is None


def test_clearing_payment_state_on_lock_expires_with_refunded_transfers():
    """Create an initiator manager state where we have nodes with channels:
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

    our_state = factories.NettingChannelEndStateProperties(balance=amount, address=our_address)
    partner_state = factories.replace(our_state, address=refund_address)

    properties = [
        factories.NettingChannelStateProperties(our_state=our_state, partner_state=partner_state),
        factories.NettingChannelStateProperties(our_state=our_state),
    ]
    channels = factories.make_channel_set(properties)

    block_number = 10
    current_state = make_initiator_manager_state(
        channels, pseudo_random_generator=pseudo_random_generator, block_number=block_number
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=amount,
            initiator=our_address,
            target=original_transfer.target,
            expiration=original_transfer.lock.expiration,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=channels[0].canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )

    state_change = ReceiveTransferCancelRoute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 10,
    )

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        secret=random_secret(),
        balance_proof=refund_transfer.balance_proof,
        sender=refund_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 10,
    )
    assert iteration.new_state is not None

    initial_transfer_state = get_transfer_at_index(iteration.new_state, 0)
    initial_transfer = initial_transfer_state.transfer

    assert initial_transfer_state is not None
    assert initial_transfer_state.channel_identifier == channels[0].identifier

    rerouted_transfer_state = get_transfer_at_index(iteration.new_state, 1)
    rerouted_transfer = rerouted_transfer_state.transfer
    assert rerouted_transfer_state is not None
    assert rerouted_transfer_state.channel_identifier == channels[1].identifier

    ##
    # Expire both locks of the initial transfer and it's refund
    ##
    balance_proof = factories.create(
        factories.BalanceProofSignedStateProperties(
            nonce=2,
            transferred_amount=initial_transfer.balance_proof.transferred_amount,
            canonical_identifier=channels[0].canonical_identifier,
            message_hash=initial_transfer.lock.secrethash,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )
    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        sender=balance_proof.sender,  # pylint: disable=no-member
        secrethash=initial_transfer.lock.secrethash,
        message_identifier=5,
    )

    expiry_block = channel.get_sender_expiration_threshold(initial_transfer.lock.expiration)
    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert iteration.new_state, "payment task should not be deleted at this block"

    initial_transfer_expiry_block_state_change = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=initial_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert iteration.new_state, "payment task should not be deleted at this block"

    ##
    # The initiator manager state still has pending transfer, so we expire
    # the rerouted transfer and it's refund to check if the payment state
    # is cleared as expected.
    ##
    expiry_block = channel.get_sender_expiration_threshold(rerouted_transfer.lock.expiration)
    rerouted_transfer_expiry_block_state_change = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=rerouted_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert not iteration.new_state, "payment task should be deleted at this block"


def test_state_wait_secretrequest_valid_amount_and_fee():
    fee_amount = 5

    setup = setup_initiator_tests(allocated_fee=fee_amount)

    state_change = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount - fee_amount,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration = initiator_manager.state_transition(
        payment_state=setup.current_state,
        state_change=state_change,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert search_for_item(iteration.events, SendSecretReveal, {}) is not None

    initiator_state = get_transfer_at_index(iteration.new_state, 0)
    assert initiator_state.received_secret_request is True

    initiator_state.received_secret_request = False

    # Now make the amount so small that the SecretRequest becomes invalid. We
    # need to subtract two tokens because one is covered by the fee margin.
    state_change_2 = ReceiveSecretRequest(
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=setup.lock.amount - fee_amount - 2,
        expiration=setup.lock.expiration,
        secrethash=setup.lock.secrethash,
        sender=UNIT_TRANSFER_TARGET,
    )

    iteration2 = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=state_change_2,
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=setup.prng,
        block_number=setup.block_number,
    )

    assert len(iteration2.events) == 1
    assert search_for_item(iteration2.events, EventInvalidSecretRequest, {}) is not None


def test_initiator_manager_drops_invalid_state_changes():
    channels = factories.make_channel_set_from_amounts([10])
    transfer = factories.create(factories.LockedTransferSignedStateProperties())
    secret = factories.UNIT_SECRET

    balance_proof = factories.create(factories.BalanceProofSignedStateProperties())
    lock_expired = ReceiveLockExpired(
        balance_proof=balance_proof,
        sender=balance_proof.sender,
        secrethash=factories.UNIT_SECRETHASH,
        message_identifier=1,
    )

    prng = random.Random()

    state = InitiatorPaymentState(routes=[], initiator_transfers={})
    iteration = initiator_manager.state_transition(
        payment_state=state,
        state_change=lock_expired,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=1,
    )
    assert_dropped(iteration, state, "no matching initiator_state")

    initiator_state = InitiatorTransferState(
        route=factories.make_route_from_channel(channels[0]),
        transfer_description=factories.UNIT_TRANSFER_DESCRIPTION,
        channel_identifier=channels[0].canonical_identifier.channel_identifier,
        transfer=transfer,
    )
    state = InitiatorPaymentState(
        routes=[], initiator_transfers={factories.UNIT_SECRETHASH: initiator_state}
    )

    iteration = initiator_manager.state_transition(
        payment_state=state,
        state_change=lock_expired,
        channelidentifiers_to_channels={},
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=1,
    )
    assert_dropped(iteration, state, "unknown channel identifier")

    transfer2 = factories.create(factories.LockedTransferSignedStateProperties(amount=2))
    cancel_route2 = ActionTransferReroute(
        transfer=transfer2,
        balance_proof=transfer2.balance_proof,
        # pylint: disable=no-member
        sender=transfer2.balance_proof.sender,
        secret=secret,
    )
    iteration = initiator_manager.state_transition(
        payment_state=state,
        state_change=cancel_route2,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=prng,
        block_number=1,
    )
    assert_dropped(iteration, state, "invalid lock")


def test_regression_payment_unlock_failed_event_must_be_emitted_only_once():
    amount = UNIT_TRANSFER_AMOUNT
    our_address = factories.ADDR
    refund_pkey, refund_address = factories.make_privkey_address()
    pseudo_random_generator = random.Random()

    our_state = factories.NettingChannelEndStateProperties(balance=amount, address=our_address)
    partner_state = factories.replace(our_state, address=refund_address)

    properties = [
        factories.NettingChannelStateProperties(our_state=our_state, partner_state=partner_state),
        factories.NettingChannelStateProperties(our_state=our_state),
    ]
    channels = factories.make_channel_set(properties)

    block_number = 10
    current_state = make_initiator_manager_state(
        channels=channels,
        transfer_description=factories.UNIT_TRANSFER_DESCRIPTION,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    initiator_state = get_transfer_at_index(current_state, 0)
    original_transfer = initiator_state.transfer

    refund_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=amount,
            initiator=our_address,
            target=original_transfer.target,
            expiration=original_transfer.lock.expiration,
            payment_identifier=original_transfer.payment_identifier,
            canonical_identifier=channels.channels[0].canonical_identifier,
            sender=refund_address,
            pkey=refund_pkey,
        )
    )

    state_change = ReceiveTransferCancelRoute(
        transfer=refund_transfer,
        balance_proof=refund_transfer.balance_proof,
        # pylint: disable=no-member
        sender=refund_transfer.balance_proof.sender,
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 10,
    )

    state_change = ActionTransferReroute(
        transfer=refund_transfer,
        secret=random_secret(),
        balance_proof=refund_transfer.balance_proof,
        # pylint: disable=no-member
        sender=refund_transfer.balance_proof.sender,
    )

    iteration = initiator_manager.state_transition(
        payment_state=current_state,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 10,
    )
    assert iteration.new_state is not None

    initial_transfer_state = get_transfer_at_index(iteration.new_state, 0)
    initial_transfer = initial_transfer_state.transfer
    expiry_block = channel.get_sender_expiration_threshold(initial_transfer.lock.expiration)

    initial_transfer_expiry_block_state_change = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )

    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=initial_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expiry_block,
    )
    assert search_for_item(iteration.events, EventPaymentSentFailed, {})
    assert search_for_item(iteration.events, EventUnlockFailed, {})

    next_block_after_expiry = Block(
        block_number=expiry_block, gas_limit=1, block_hash=factories.make_transaction_hash()
    )
    iteration = initiator_manager.state_transition(
        payment_state=iteration.new_state,
        state_change=initial_transfer_expiry_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=next_block_after_expiry,
    )
    msg = "failed event must not be emitted twice"
    assert search_for_item(iteration.events, EventPaymentSentFailed, {}) is None, msg
    assert search_for_item(iteration.events, EventUnlockFailed, {}) is None, msg


def test_initiator_init():
    secret = factories.make_secret()
    service = MockRaidenService()

    route_states = [
        RouteState(
            route=[factories.make_address(), factories.make_address()],
            estimated_fee=FeeAmount(123),
        )
    ]
    feedback_token = uuid.uuid4()

    with patch(
        "raiden.routing.get_best_routes", return_value=(None, route_states, feedback_token)
    ) as best_routes:
        assert len(service.route_to_feedback_token) == 0

        _, init_state_change = initiator_init(
            raiden=service,
            transfer_identifier=1,
            transfer_amount=PaymentAmount(100),
            transfer_secret=secret,
            transfer_secrethash=keccak(secret),
            token_network_address=factories.make_token_network_address(),
            target_address=factories.make_address(),
        )

        assert best_routes.called
        assert len(service.route_to_feedback_token) == 1
        assert service.route_to_feedback_token[tuple(route_states[0].route)] == feedback_token

        assert init_state_change.routes == route_states


def test_calculate_safe_amount_with_fee():
    assert calculate_safe_amount_with_fee(1, 0) == 1
    assert calculate_safe_amount_with_fee(1000, 0) == 1000
    assert 1000 <= calculate_safe_amount_with_fee(1000, 1) < 1005
    assert 2000 < calculate_safe_amount_with_fee(1000, 1000) < 2100
