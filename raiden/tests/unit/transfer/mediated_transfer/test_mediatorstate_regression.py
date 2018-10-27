# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random

from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    HOP1,
    HOP2,
    HOP2_KEY,
    HOP3_KEY,
    HOP4,
    HOP4_KEY,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
)
from raiden.transfer import channel
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import (
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
)
from raiden.transfer.mediated_transfer.state import MediatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state_change import Block


def test_payer_enter_danger_zone_with_transfer_payed():
    """ A mediator may have paid the next hop (payee), and didn't get paid by
    the previous hop (payer).

    When this happens, an assertion must not be hit, because it means the
    transfer must be unlocked on-chain.

    Issue: https://github.com/raiden-network/raiden/issues/1013
    """
    amount = 10
    block_number = 5
    target = HOP2
    expiration = 30
    pseudo_random_generator = random.Random()

    payer_channel = factories.make_channel(
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    payer_route = factories.route_from_channel(payer_channel)

    payer_transfer = factories.make_signed_transfer_for(
        payer_channel,
        amount,
        HOP1,
        target,
        expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channel_map = {
        channel1.identifier: channel1,
        payer_channel.identifier: payer_channel,
    }
    possible_routes = [factories.route_from_channel(channel1)]

    init_state_change = ActionInitMediator(
        possible_routes,
        payer_route,
        payer_transfer,
    )
    initial_state = None
    initial_iteration = mediator.state_transition(
        initial_state,
        init_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    send_transfer = must_contain_entry(initial_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    lock_expiration = send_transfer.transfer.lock.expiration

    new_state = initial_iteration.new_state
    for block_number in range(block_number, lock_expiration - channel1.reveal_timeout):
        block_state_change = Block(
            block_number=block_number,
            gas_limit=1,
            block_hash=factories.make_transaction_hash(),
        )

        block_iteration = mediator.handle_block(
            new_state,
            block_state_change,
            channel_map,
            pseudo_random_generator,
        )
        new_state = block_iteration.new_state

    # send the balance proof, transitioning the payee state to paid
    assert new_state.transfers_pair[0].payee_state == 'payee_pending'
    receive_secret = ReceiveSecretReveal(
        UNIT_SECRET,
        channel1.partner_state.address,
    )
    paid_iteration = mediator.state_transition(
        new_state,
        receive_secret,
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    paid_state = paid_iteration.new_state
    assert paid_state.transfers_pair[0].payee_state == 'payee_balance_proof'

    # move to the block in which the payee lock expires. This must not raise an
    # assertion
    expired_block_number = lock_expiration + 1
    expired_block_state_change = Block(
        block_number=expired_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    block_iteration = mediator.handle_block(
        paid_state,
        expired_block_state_change,
        channel_map,
        pseudo_random_generator,
    )


def test_regression_send_refund():
    """Regression test for discarded refund transfer.

    The handle_refundtransfer used to discard events from the channel state
    machine, which led to the state being updated but the message to the
    partner was never sent.
    """
    amount = 10
    privatekeys = [HOP2_KEY, HOP3_KEY, HOP4_KEY]
    pseudo_random_generator = random.Random()
    block_number = 5

    channel_map, transfers_pair = factories.make_transfers_pair(
        privatekeys,
        amount,
        block_number,
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    mediator_state.transfers_pair = transfers_pair

    last_pair = transfers_pair[-1]
    channel_identifier = last_pair.payee_transfer.balance_proof.channel_identifier
    lock_expiration = last_pair.payee_transfer.lock.expiration

    received_transfer = factories.make_signed_transfer(
        amount=amount,
        initiator=UNIT_TRANSFER_INITIATOR,
        target=UNIT_TRANSFER_TARGET,
        expiration=lock_expiration,
        secret=UNIT_SECRET,
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        channel_identifier=channel_identifier,
        pkey=HOP4_KEY,
        sender=HOP4,
    )

    # All three channels have been used
    routes = []

    refund_state_change = ReceiveTransferRefund(
        HOP4,
        received_transfer,
        routes,
    )

    iteration = mediator.handle_refundtransfer(
        mediator_state,
        refund_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )

    first_pair = transfers_pair[0]
    first_payer_transfer = first_pair.payer_transfer
    payer_channel = mediator.get_payer_channel(channel_map, first_pair)
    lock = channel.get_lock(
        end_state=payer_channel.partner_state,
        secrethash=UNIT_SECRETHASH,
    )
    token_network_identifier = first_payer_transfer.balance_proof.token_network_identifier
    assert must_contain_entry(iteration.events, SendRefundTransfer, {
        'recipient': HOP2,
        'queue_identifier': {
            'recipient': HOP2,
            'channel_identifier': first_payer_transfer.balance_proof.channel_identifier,
        },
        'payment_identifier': UNIT_TRANSFER_IDENTIFIER,
        'token': UNIT_TOKEN_ADDRESS,
        'balance_proof': {
            # 'nonce': ,
            'transferred_amount': 0,
            'locked_amount': 10,
            'locksroot': lock.lockhash,
            'token_network_identifier': token_network_identifier,
            'channel_identifier': first_payer_transfer.balance_proof.channel_identifier,
            'chain_id': first_payer_transfer.balance_proof.chain_id,
        },
        'lock': {
            'amount': lock.amount,
            'expiration': lock.expiration,
            'secrethash': lock.secrethash,
        },
        'initiator': UNIT_TRANSFER_INITIATOR,
        'target': UNIT_TRANSFER_TARGET,
    })


def test_regression_mediator_send_lock_expired_with_new_block():
    """ The mediator must send the lock expired, but it must **not** clear
    itself if it has not **received** the corresponding message.
    """
    amount = 10
    block_number = 5
    target = HOP2
    expiration = 30
    pseudo_random_generator = random.Random()

    payer_channel = factories.make_channel(
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    payer_route = factories.route_from_channel(payer_channel)

    payer_transfer = factories.make_signed_transfer_for(
        payer_channel,
        amount,
        HOP1,
        target,
        expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    available_routes = [factories.route_from_channel(channel1)]
    channel_map = {
        channel1.identifier: channel1,
        payer_channel.identifier: payer_channel,
    }

    init_state_change = ActionInitMediator(
        available_routes,
        payer_route,
        payer_transfer,
    )
    initial_state = None
    init_iteration = mediator.state_transition(
        initial_state,
        init_state_change,
        channel_map,
        pseudo_random_generator,
        block_number,
    )
    assert init_iteration.new_state is not None
    send_transfer = must_contain_entry(init_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer

    block_expiration_number = transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2
    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = mediator.state_transition(
        init_iteration.new_state,
        block,
        channel_map,
        pseudo_random_generator,
        block_expiration_number,
    )

    msg = (
        "The payer's lock has also expired, "
        "but it must not be removed locally (without an Expired lock)"
    )
    assert transfer.lock.secrethash in payer_channel.partner_state.secrethashes_to_lockedlocks, msg

    msg = 'The payer has not yet sent an expired lock, the task can not be cleared yet'
    assert iteration.new_state is not None, msg

    assert must_contain_entry(iteration.events, SendLockExpired, {
        'secrethash': transfer.lock.secrethash,
    })
    assert transfer.lock.secrethash not in channel1.our_state.secrethashes_to_lockedlocks
