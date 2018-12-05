# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random

from raiden.messages import message_from_sendevent
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    HOP1,
    HOP1_KEY,
    HOP2,
    HOP2_KEY,
    HOP3,
    HOP3_KEY,
    HOP4,
    HOP4_KEY,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_TARGET,
)
from raiden.transfer import channel
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
)
from raiden.transfer.mediated_transfer.state import MediatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveLockExpired,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state import balanceproof_from_envelope, message_identifier_from_prng
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal


def test_payer_enter_danger_zone_with_transfer_payed():
    """ A mediator may have paid the next hop (payee), and didn't get paid by
    the previous hop (payer).

    When this happens, an assertion must not be hit, because it means the
    transfer must be unlocked on-chain.

    Issue: https://github.com/raiden-network/raiden/issues/1013
    """
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = factories.mediator_make_channel_pair()

    payer_transfer = factories.make_default_signed_transfer_for(
        channels[0],
        initiator=HOP1,
        expiration=30,
    )

    initial_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=factories.mediator_make_init_action(channels, payer_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    send_transfer = must_contain_entry(initial_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    lock_expiration = send_transfer.transfer.lock.expiration

    new_state = initial_iteration.new_state
    for block_number in range(block_number, lock_expiration - channels[1].reveal_timeout):
        block_state_change = Block(
            block_number=block_number,
            gas_limit=1,
            block_hash=factories.make_transaction_hash(),
        )

        block_iteration = mediator.handle_block(
            new_state,
            block_state_change,
            channels.channel_map,
            pseudo_random_generator,
        )
        new_state = block_iteration.new_state

    # send the balance proof, transitioning the payee state to paid
    assert new_state.transfers_pair[0].payee_state == 'payee_pending'
    receive_secret = ReceiveSecretReveal(
        UNIT_SECRET,
        channels[1].partner_state.address,
    )
    paid_iteration = mediator.state_transition(
        mediator_state=new_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
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
        mediator_state=paid_state,
        state_change=expired_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
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
        transfer=received_transfer,
        routes=routes,
    )

    iteration = mediator.handle_refundtransfer(
        mediator_state=mediator_state,
        mediator_state_change=refund_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
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
        'transfer': {
            'payment_identifier': UNIT_TRANSFER_IDENTIFIER,
            'token': UNIT_TOKEN_ADDRESS,
            'balance_proof': {
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
        },
    })


def test_regression_mediator_send_lock_expired_with_new_block():
    """ The mediator must send the lock expired, but it must **not** clear
    itself if it has not **received** the corresponding message.
    """
    pseudo_random_generator = random.Random()

    channels = factories.mediator_make_channel_pair()
    payer_transfer = factories.make_default_signed_transfer_for(
        channels[0],
        initiator=HOP1,
        expiration=30,
    )

    init_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=factories.mediator_make_init_action(channels, payer_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
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
        mediator_state=init_iteration.new_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
    )

    msg = (
        "The payer's lock has also expired, "
        "but it must not be removed locally (without an Expired lock)"
    )
    assert transfer.lock.secrethash in channels[0].partner_state.secrethashes_to_lockedlocks, msg

    msg = 'The payer has not yet sent an expired lock, the task can not be cleared yet'
    assert iteration.new_state is not None, msg

    assert must_contain_entry(iteration.events, SendLockExpired, {
        'secrethash': transfer.lock.secrethash,
    })
    assert transfer.lock.secrethash not in channels[1].our_state.secrethashes_to_lockedlocks


def test_regression_mediator_task_no_routes():
    """ The mediator must only be cleared after the waiting transfer's lock has
    been handled.

    If a node receives a transfer to mediate, but there is no route available
    (because there is no sufficient capacity or the partner nodes are offline),
    and a refund is not possible, the mediator task must not be cleared,
    otherwise followup remove expired lock messages wont be processed and the
    nodes will get out of sync.
    """
    pseudo_random_generator = random.Random()

    channels = factories.make_channel_set([
        {
            'our_state': {'balance': 0},
            'partner_state': {'balance': 10, 'address': HOP2},
            'open_transaction': factories.make_transaction_execution_status(
                finished_block_number=10,
            ),
        },
    ])

    payer_transfer = factories.make_default_signed_transfer_for(
        channels[0],
        initiator=HOP1,
        expiration=30,
        pkey=HOP2_KEY,
        sender=HOP2,
    )

    init_state_change = ActionInitMediator(
        channels.get_routes(),
        channels.get_route(0),
        payer_transfer,
    )
    init_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
    )

    msg = 'The task must not be cleared, even if there is no route to forward the transfer'
    assert init_iteration.new_state is not None, msg
    assert init_iteration.new_state.waiting_transfer.transfer == payer_transfer
    assert must_contain_entry(init_iteration.events, SendLockedTransfer, {}) is None
    assert must_contain_entry(init_iteration.events, SendRefundTransfer, {}) is None

    secrethash = UNIT_SECRETHASH
    lock = channels[0].partner_state.secrethashes_to_lockedlocks[secrethash]

    # Creates a transfer as it was from the *partner*
    send_lock_expired, _ = channel.create_sendexpiredlock(
        sender_end_state=channels[0].partner_state,
        locked_lock=lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=channels[0].chain_id,
        token_network_identifier=channels[0].token_network_identifier,
        channel_identifier=channels[0].identifier,
        recipient=channels[0].our_state.address,
    )
    assert send_lock_expired
    lock_expired_message = message_from_sendevent(send_lock_expired, HOP1)
    lock_expired_message.sign(HOP2_KEY)
    balance_proof = balanceproof_from_envelope(lock_expired_message)

    message_identifier = message_identifier_from_prng(pseudo_random_generator)
    expired_block_number = lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2

    # Regression: The mediator must still be able to process the block which
    # expires the lock
    expire_block_iteration = mediator.state_transition(
        mediator_state=init_iteration.new_state,
        state_change=Block(
            block_number=expired_block_number,
            gas_limit=0,
            block_hash=None,
        ),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
    )
    assert expire_block_iteration.new_state is not None

    receive_expired_iteration = mediator.state_transition(
        mediator_state=expire_block_iteration.new_state,
        state_change=ReceiveLockExpired(
            balance_proof=balance_proof,
            secrethash=secrethash,
            message_identifier=message_identifier,
        ),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
    )

    msg = 'The only used channel had the lock cleared, the task must be cleared'
    assert receive_expired_iteration.new_state is None, msg
    assert secrethash not in channels[0].partner_state.secrethashes_to_lockedlocks


def test_regression_mediator_not_update_payer_state_twice():
    """ Regression Test for https://github.com/raiden-network/raiden/issues/3086
    Make sure that after a lock expired the mediator doesn't update the pair
    twice causing EventUnlockClaimFailed to be generated at every block.
    """
    amount = 10
    block_number = 5
    initiator = HOP1
    initiator_key = HOP1_KEY
    mediator_address = HOP2
    target = HOP3
    expiration = 30
    pseudo_random_generator = random.Random()

    payer_channel = factories.make_channel(
        partner_balance=amount,
        our_balance=amount,
        our_address=mediator_address,
        partner_address=initiator,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    payer_route = factories.route_from_channel(payer_channel)

    payer_transfer = factories.make_signed_transfer_for(
        channel_state=payer_channel,
        amount=amount,
        initiator=initiator,
        target=target,
        expiration=expiration,
        secret=UNIT_SECRET,
        sender=initiator,
        pkey=initiator_key,
    )

    payee_channel = factories.make_channel(
        our_balance=amount,
        our_address=mediator_address,
        partner_address=target,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    available_routes = [factories.route_from_channel(payee_channel)]
    channel_map = {
        payee_channel.identifier: payee_channel,
        payer_channel.identifier: payer_channel,
    }

    init_state_change = ActionInitMediator(
        routes=available_routes,
        from_route=payer_route,
        from_transfer=payer_transfer,
    )
    initial_state = None
    iteration = mediator.state_transition(
        mediator_state=initial_state,
        state_change=init_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert iteration.new_state is not None

    current_state = iteration.new_state
    send_transfer = must_contain_entry(iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer
    block_expiration_number = transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2

    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=block,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
    )

    msg = 'At the expiration block we should get an EventUnlockClaimFailed'
    assert must_contain_entry(iteration.events, EventUnlockClaimFailed, {}), msg

    current_state = iteration.new_state
    next_block = Block(
        block_number=block_expiration_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    # Initiator receives the secret reveal after the lock expired
    receive_secret = ReceiveSecretReveal(
        secret=UNIT_SECRET,
        sender=payee_channel.partner_state.address,
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=next_block.block_number,
    )
    current_state = iteration.new_state
    lock = payer_transfer.lock
    secrethash = lock.secrethash
    assert secrethash in payer_channel.partner_state.secrethashes_to_lockedlocks
    assert current_state.transfers_pair[0].payee_state == 'payee_expired'
    assert not channel.is_secret_known(payer_channel.partner_state, secrethash)

    safe_to_wait, _ = mediator.is_safe_to_wait(
        lock_expiration=lock.expiration,
        reveal_timeout=payer_channel.reveal_timeout,
        block_number=lock.expiration + 10,
    )

    assert not safe_to_wait

    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=next_block,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
    )
    msg = 'At the next block we should not get the same event'
    assert not must_contain_entry(iteration.events, EventUnlockClaimFailed, {}), msg


def test_regression_onchain_secret_reveal_must_update_channel_state():
    """ If a secret is learned off-chain and then on-chain, the state of the
    lock must be updated in the channel.
    """
    amount = 10
    block_number = 10
    pseudo_random_generator = random.Random()

    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
        block_number,
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    mediator_state.transfers_pair = transfers_pair

    secret = UNIT_SECRET
    secrethash = UNIT_SECRETHASH
    payer_channelid = transfers_pair[0].payer_transfer.balance_proof.channel_identifier
    payee_channelid = transfers_pair[0].payee_transfer.balance_proof.channel_identifier
    payer_channel = channel_map[payer_channelid]
    payee_channel = channel_map[payee_channelid]
    lock = payer_channel.partner_state.secrethashes_to_lockedlocks[secrethash]

    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ReceiveSecretReveal(secret, payee_channel.partner_state.address),
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_unlockedlocks

    secret_registry_address = factories.make_address()
    transaction_hash = factories.make_address()
    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ContractReceiveSecretReveal(
            transaction_hash,
            secret_registry_address,
            secrethash,
            secret,
            block_number,
        ),
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_onchain_unlockedlocks

    # Creates a transfer as it was from the *partner*
    send_lock_expired, _ = channel.create_sendexpiredlock(
        sender_end_state=payer_channel.partner_state,
        locked_lock=lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=payer_channel.chain_id,
        token_network_identifier=payer_channel.token_network_identifier,
        channel_identifier=payer_channel.identifier,
        recipient=payer_channel.our_state.address,
    )
    assert send_lock_expired
    lock_expired_message = message_from_sendevent(send_lock_expired, HOP1)
    lock_expired_message.sign(HOP2_KEY)
    balance_proof = balanceproof_from_envelope(lock_expired_message)

    message_identifier = message_identifier_from_prng(pseudo_random_generator)
    expired_block_number = lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2
    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ReceiveLockExpired(
            balance_proof=balance_proof,
            secrethash=secrethash,
            message_identifier=message_identifier,
        ),
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_onchain_unlockedlocks
