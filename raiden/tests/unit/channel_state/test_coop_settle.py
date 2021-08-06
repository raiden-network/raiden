import random

import pytest

from raiden.tests.unit.channel_state.utils import (
    assert_partner_state,
    create_channel_from_models,
    create_model,
)
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import make_block_hash
from raiden.transfer import channel
from raiden.transfer.events import (
    ContractSendChannelCoopSettle,
    EventInvalidReceivedWithdrawRequest,
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawRequest,
)
from raiden.transfer.state import (
    CoopSettleState,
    PendingWithdrawState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionChannelCoopSettle,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawRequest,
)
from raiden.utils.packing import pack_withdraw
from raiden.utils.signer import LocalSigner


def _make_receive_coop_settle_withdraw_confirmation(
    channel_state, pseudo_random_generator, signer, nonce, total_withdraw, withdraw_expiration
):
    packed = pack_withdraw(
        canonical_identifier=channel_state.canonical_identifier,
        participant=channel_state.our_state.address,
        total_withdraw=total_withdraw,
        expiration_block=withdraw_expiration,
    )
    signature = signer.sign(packed)
    # Withdraw request larger than balance
    withdraw_confirmation = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        # has to be the maximum withdrawable amount
        total_withdraw=total_withdraw,
        signature=signature,
        sender=channel_state.partner_state.address,
        participant=channel_state.our_state.address,
        nonce=nonce,
        expiration=withdraw_expiration,
    )
    return withdraw_confirmation


def _make_receive_coop_settle_withdraw_request(
    channel_state, pseudo_random_generator, signer, nonce, total_withdraw, withdraw_expiration
):
    packed = pack_withdraw(
        canonical_identifier=channel_state.canonical_identifier,
        participant=channel_state.partner_state.address,
        total_withdraw=total_withdraw,
        expiration_block=withdraw_expiration,
    )
    signature = signer.sign(packed)
    # Withdraw request larger than balance
    withdraw_request = ReceiveWithdrawRequest(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        # has to be the maximum withdrawable amount
        total_withdraw=total_withdraw,
        signature=signature,
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        nonce=nonce,
        expiration=withdraw_expiration,
        coop_settle=True,
    )
    return withdraw_request


def _assert_coop_settle_state(
    our_state,
    partner_state,
    our_initial_model,
    our_current_nonce,
    coop_settle_expiration,
    initiated_coop_settle=False,
):
    # Those properties also ensure that we don't receive or send out
    # any transfers in that channel while the coop settle is pending
    our_model2 = our_initial_model._replace(
        distributable=0, balance=0, next_nonce=our_current_nonce + 1
    )
    assert_partner_state(our_state, partner_state, our_model2)

    if initiated_coop_settle:
        assert our_state.initiated_coop_settle is not None
        assert (
            our_state.initiated_coop_settle.total_withdraw_initiator == our_initial_model.balance
        )
        assert our_state.initiated_coop_settle.expiration == coop_settle_expiration
    else:
        assert our_state.initiated_coop_settle is None

    assert our_state.offchain_total_withdraw == our_initial_model.balance

    pending_withdraw_initiator = our_state.withdraws_pending[our_initial_model.balance]
    assert pending_withdraw_initiator is not None
    assert pending_withdraw_initiator.total_withdraw == our_initial_model.balance


def test_initiate():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1

    action_coop_settle = ActionChannelCoopSettle(channel_state.canonical_identifier)

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=action_coop_settle,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    send_withdraw_request = search_for_item(
        iteration.events,
        SendWithdrawRequest,
        {"total_withdraw": 70, "nonce": 1, "coop_settle": True},
    )

    assert send_withdraw_request is not None
    expiration = send_withdraw_request.expiration

    # our view
    _assert_coop_settle_state(
        channel_state.our_state,
        channel_state.partner_state,
        our_initial_model=our_model1,
        our_current_nonce=1,
        coop_settle_expiration=expiration,
        initiated_coop_settle=True,
    )
    # The partner still has full balance in his state.
    # He could therefore initiate a transfer in our direction now and we would accept it
    # Then he could try to continue the coop-settle with old balances.
    # This is no problem, since this would invalidate later acceptance of
    # the withdraw-request - the balance would be too low for when the transfer was unlocked,
    # or we would have pending locks for the case where it was still pending.
    assert (
        channel.get_balance(channel_state.partner_state, channel_state.our_state)
        == partner_model1.balance
    )
    assert channel_state.partner_state.withdraws_pending.get(partner_model1.balance) is None


def test_receive_request_while_pending_transfers():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70, num_pending_locks=1)
    partner_model1, privkey2 = create_model(balance=100)
    signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1
    expiration = 1000

    withdraw_request = _make_receive_coop_settle_withdraw_request(
        channel_state,
        pseudo_random_generator,
        signer,
        nonce=1,
        total_withdraw=100,
        withdraw_expiration=expiration,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=withdraw_request,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # Don't accept incoming coop-settle withdraw requests when there are pending
    # transfers
    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdrawRequest, {"attempted_withdraw": 100}
        )
        is not None
    )


def test_receive_request():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1
    expiration = 1000

    withdraw_request = _make_receive_coop_settle_withdraw_request(
        channel_state,
        pseudo_random_generator,
        signer,
        nonce=1,
        total_withdraw=100,
        withdraw_expiration=expiration,
    )
    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=withdraw_request,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events,
            SendWithdrawConfirmation,
            {"total_withdraw": 100, "nonce": 2, "expiration": expiration},
        )
        is not None
    )
    assert (
        search_for_item(
            iteration.events,
            SendWithdrawRequest,
            {"total_withdraw": 70, "nonce": 1, "coop_settle": False, "expiration": expiration},
        )
        is not None
    )

    # partner's view
    _assert_coop_settle_state(
        channel_state.partner_state,
        channel_state.our_state,
        our_initial_model=partner_model1,
        our_current_nonce=1,
        coop_settle_expiration=expiration,
        initiated_coop_settle=True,
    )
    # our view
    _assert_coop_settle_state(
        channel_state.our_state,
        channel_state.partner_state,
        our_initial_model=our_model1,
        our_current_nonce=2,
        coop_settle_expiration=expiration,
        initiated_coop_settle=False,
    )


def test_contract_event():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    partner_signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1
    expiration = 1000

    channel_state.our_state.withdraws_pending[our_model1.balance] = PendingWithdrawState(
        total_withdraw=our_model1.balance, expiration=expiration, nonce=0
    )
    channel_state.our_state.initiated_coop_settle = CoopSettleState(
        total_withdraw_initiator=our_model1.balance,
        total_withdraw_partner=partner_model1.balance,
        expiration=expiration,
    )

    withdraw_request = _make_receive_coop_settle_withdraw_request(
        channel_state,
        pseudo_random_generator,
        partner_signer,
        nonce=1,
        total_withdraw=partner_model1.balance,
        withdraw_expiration=expiration,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=withdraw_request,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events,
            SendWithdrawConfirmation,
            {"total_withdraw": 100, "nonce": 1, "expiration": expiration},
        )
        is not None
    )

    assert len(iteration.events) == 1

    # our view
    _assert_coop_settle_state(
        channel_state.our_state,
        channel_state.partner_state,
        our_initial_model=our_model1,
        our_current_nonce=1,
        coop_settle_expiration=expiration,
        initiated_coop_settle=True,
    )
    # partner's view
    _assert_coop_settle_state(
        channel_state.partner_state,
        channel_state.our_state,
        our_initial_model=partner_model1,
        our_current_nonce=1,
        coop_settle_expiration=expiration,
        initiated_coop_settle=False,
    )

    withdraw_confirmation = _make_receive_coop_settle_withdraw_confirmation(
        channel_state,
        pseudo_random_generator,
        partner_signer,
        nonce=2,
        total_withdraw=our_model1.balance,
        withdraw_expiration=expiration,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=withdraw_confirmation,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events,
            SendProcessed,
            {
                "recipient": partner_model1.participant_address,
                "message_identifier": withdraw_confirmation.message_identifier,
            },
        )
        is not None
    )
    assert (
        search_for_item(
            iteration.events,
            ContractSendChannelCoopSettle,
            {
                "our_total_withdraw": our_model1.balance,
                "partner_total_withdraw": partner_model1.balance,
                "expiration": expiration,
                "signature_our_withdraw": withdraw_confirmation.signature,
                "signature_partner_withdraw": withdraw_request.signature,
            },
        )
        is not None
    )


def test_receive_initiator_confirmation_has_no_effect():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    partner_signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1
    expiration = 1000

    channel_state.our_state.withdraws_pending[our_model1.balance] = PendingWithdrawState(
        total_withdraw=our_model1.balance, expiration=expiration, nonce=0
    )
    channel_state.partner_state.withdraws_pending[partner_model1.balance] = PendingWithdrawState(
        total_withdraw=partner_model1.balance, expiration=expiration, nonce=0
    )
    channel_state.partner_state.initiated_coop_settle = CoopSettleState(
        total_withdraw_initiator=partner_model1.balance,
        total_withdraw_partner=our_model1.balance,
        expiration=expiration,
    )

    # assume we sent out our Confirmation and Request, now the partner answers with
    # a confirmation to our request.
    withdraw_confirmation = _make_receive_coop_settle_withdraw_confirmation(
        channel_state,
        pseudo_random_generator,
        partner_signer,
        nonce=1,
        total_withdraw=our_model1.balance,
        withdraw_expiration=expiration,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=withdraw_confirmation,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # There only should be the processed for the confirmation
    assert len(iteration.events) == 1
    assert (
        search_for_item(
            iteration.events,
            SendProcessed,
            {
                "recipient": partner_model1.participant_address,
                "message_identifier": withdraw_confirmation.message_identifier,
            },
        )
        is not None
    )


@pytest.mark.skip(reason="Test yet to be implemented")
def test_clean_state_after_successful_onchain_coop_settle():
    # TODO as soon as the contract interaction-events are implemented
    pass
