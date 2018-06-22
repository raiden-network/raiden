# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random

from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import MediatorTransferState
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal
from raiden.transfer.mediated_transfer.events import SendLockedTransfer
from raiden.transfer.state_change import Block
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    HOP1,
    HOP2,
    UNIT_SECRETHASH,
    UNIT_SECRET,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_SENDER,
)


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
    channelmap = {
        channel1.identifier: channel1,
        payer_channel.identifier: payer_channel,
    }
    possible_routes = [factories.route_from_channel(channel1)]

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    initial_iteration = mediator.mediate_transfer(
        mediator_state,
        possible_routes,
        payer_channel,
        channelmap,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )

    send_transfer = must_contain_entry(initial_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    lock_expiration = send_transfer.transfer.lock.expiration

    new_state = initial_iteration.new_state
    for block_number in range(block_number, lock_expiration + 1):
        block_state_change = Block(block_number)

        block_iteration = mediator.handle_block(
            channelmap,
            new_state,
            block_state_change,
            block_number,
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
        channelmap,
        pseudo_random_generator,
        block_number,
    )
    paid_state = paid_iteration.new_state
    assert paid_state.transfers_pair[0].payee_state == 'payee_balance_proof'

    # move to the block in which the payee lock expires. This must not raise an
    # assertion
    expired_block_number = lock_expiration + 1
    expired_block_state_change = Block(expired_block_number)
    block_iteration = mediator.handle_block(
        channelmap,
        paid_state,
        expired_block_state_change,
        expired_block_number,
    )
