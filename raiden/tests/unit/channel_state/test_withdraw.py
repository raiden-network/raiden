# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random

from raiden.settings import MediationFeeConfig
from raiden.tests.unit.channel_state.utils import create_channel_from_models, create_model
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import make_32bytes, make_block_hash, make_transaction_hash
from raiden.transfer import channel
from raiden.transfer.events import (
    ContractSendChannelWithdraw,
    EventInvalidActionWithdraw,
    EventInvalidReceivedWithdraw,
    EventInvalidReceivedWithdrawExpired,
    EventInvalidReceivedWithdrawRequest,
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.state import (
    ExpiredWithdrawState,
    PendingWithdrawState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionChannelWithdraw,
    Block,
    ContractReceiveChannelWithdraw,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.utils.packing import pack_withdraw
from raiden.utils.signer import LocalSigner


def test_action_withdraw():
    pseudo_random_generator = random.Random()

    our_balance = 70
    our_model1, _ = create_model(balance=our_balance)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    # Invalid withdraw larger than balance
    action_withdraw = ActionChannelWithdraw(
        canonical_identifier=channel_state.canonical_identifier, total_withdraw=100
    )

    iteration = channel._handle_action_withdraw(
        action=action_withdraw,
        channel_state=channel_state,
        pseudo_random_generator=pseudo_random_generator,
        block_number=2,
    )

    assert (
        search_for_item(iteration.events, EventInvalidActionWithdraw, {"attempted_withdraw": 100})
        is not None
    )

    # Withdraw whole balance
    action_withdraw = ActionChannelWithdraw(
        canonical_identifier=channel_state.canonical_identifier, total_withdraw=our_balance
    )

    iteration = channel._handle_action_withdraw(
        action=action_withdraw,
        channel_state=channel_state,
        pseudo_random_generator=pseudo_random_generator,
        block_number=3,
    )

    assert iteration.new_state.our_state.offchain_total_withdraw == our_balance
    assert (
        search_for_item(iteration.events, SendWithdrawRequest, {"total_withdraw": our_balance})
        is not None
    )

    # Set total withdraw similar to the previous one
    action_withdraw = ActionChannelWithdraw(
        canonical_identifier=channel_state.canonical_identifier, total_withdraw=our_balance
    )

    iteration = channel._handle_action_withdraw(
        action=action_withdraw,
        channel_state=iteration.new_state,
        pseudo_random_generator=pseudo_random_generator,
        block_number=4,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidActionWithdraw, {"attempted_withdraw": our_balance}
        )
        is not None
    )


def test_receive_withdraw_request():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()
    block_number = 1
    expiration = 10

    # Withdraw request larger than balance
    withdraw_request = ReceiveWithdrawRequest(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=120,
        signature=make_32bytes(),
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=expiration,
    )

    iteration = channel._handle_receive_withdraw_request(
        action=withdraw_request,
        channel_state=channel_state,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdrawRequest, {"attempted_withdraw": 120}
        )
        is not None
    )

    packed = pack_withdraw(
        canonical_identifier=channel_state.canonical_identifier,
        # pylint: disable=no-member
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        total_withdraw=20,
        expiration_block=expiration,
    )
    signature = signer.sign(packed)

    withdraw_request = ReceiveWithdrawRequest(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=20,
        signature=signature,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=expiration,
    )

    iteration = channel._handle_receive_withdraw_request(
        action=withdraw_request,
        channel_state=channel_state,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # pylint: disable=no-member
    assert iteration.new_state.partner_state.offchain_total_withdraw == 20
    # pylint: enable=no-member
    assert (
        search_for_item(iteration.events, SendWithdrawConfirmation, {"total_withdraw": 20})
        is not None
    )

    # Repeat above withdraw
    withdraw_request = ReceiveWithdrawRequest(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=20,
        signature=make_32bytes(),
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=10,
    )

    iteration = channel._handle_receive_withdraw_request(
        action=withdraw_request,
        channel_state=iteration.new_state,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdrawRequest, {"attempted_withdraw": 20}
        )
        is not None
    )

    # Another withdraw with invalid signature
    withdraw_request = ReceiveWithdrawRequest(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=40,
        signature=make_32bytes(),
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=10,
    )

    iteration = channel._handle_receive_withdraw_request(
        action=withdraw_request,
        channel_state=iteration.new_state,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdrawRequest, {"attempted_withdraw": 40}
        )
        is not None
    )


def test_receive_withdraw_confirmation():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    signer = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    block_number = 1
    total_withdraw = 50
    expiration_block = channel.get_safe_initial_expiration(
        block_number, channel_state.reveal_timeout
    )

    packed = pack_withdraw(
        canonical_identifier=channel_state.canonical_identifier,
        # pylint: disable=no-member
        participant=channel_state.our_state.address,
        # pylint: enable=no-member
        total_withdraw=total_withdraw,
        expiration_block=expiration_block,
    )
    partner_signature = signer.sign(packed)

    channel_state.our_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block, nonce=1
    )

    receive_withdraw = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=100,
        signature=partner_signature,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=expiration_block,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw,
        block_number=10,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdraw, {"attempted_withdraw": 100}
        )
        is not None
    )

    channel_state = iteration.new_state

    receive_withdraw = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        signature=make_32bytes(),
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        nonce=1,
        expiration=expiration_block,
    )

    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=receive_withdraw,
        block_number=10,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events, EventInvalidReceivedWithdraw, {"attempted_withdraw": total_withdraw}
        )
        is not None
    )

    receive_withdraw = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        signature=partner_signature,
        sender=channel_state.partner_state.address,
        participant=channel_state.our_state.address,
        nonce=1,
        expiration=expiration_block,
    )

    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=receive_withdraw,
        block_number=10,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events, ContractSendChannelWithdraw, {"total_withdraw": total_withdraw}
        )
        is not None
    )


def test_node_sends_withdraw_expiry():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    nonce = 1
    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_sender_expiration_threshold(expiration_block_number)

    channel_state.our_state.nonce = nonce
    channel_state.our_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )

    block_hash = make_transaction_hash()
    block = Block(block_number=expiration_threshold - 1, gas_limit=1, block_hash=block_hash)

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=block,
        block_number=expiration_threshold - 1,
        pseudo_random_generator=pseudo_random_generator,
        block_hash=block_hash,
    )

    assert iteration.events == []

    block_hash = make_transaction_hash()
    block = Block(block_number=expiration_threshold, gas_limit=1, block_hash=block_hash)

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=block,
        block_number=expiration_threshold,
        pseudo_random_generator=pseudo_random_generator,
        block_hash=block_hash,
    )

    assert total_withdraw not in channel_state.our_state.withdraws_pending
    expired_withdraw = ExpiredWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=nonce
    )
    assert expired_withdraw in iteration.new_state.our_state.withdraws_expired

    assert (
        search_for_item(
            iteration.events,
            SendWithdrawExpired,
            {
                "total_withdraw": total_withdraw,
                "participant": channel_state.our_state.address,
                "recipient": channel_state.partner_state.address,
                "nonce": 2,
            },
        )
        is not None
    )


def test_node_handles_received_withdraw_expiry():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_receiver_expiration_threshold(expiration_block_number)

    channel_state.partner_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )

    receive_withdraw_expired = ReceiveWithdrawExpired(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=10,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw_expired,
        block_number=expiration_threshold,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert search_for_item(iteration.events, SendProcessed, {}) is not None

    channel_state = iteration.new_state
    assert channel_state.partner_state.offchain_total_withdraw == 0
    assert not channel_state.partner_state.withdraws_pending


def test_node_rejects_received_withdraw_expiry_invalid_total_withdraw():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_receiver_expiration_threshold(expiration_block_number)

    pending_withdraw = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )
    channel_state.partner_state.withdraws_pending[total_withdraw] = pending_withdraw

    # Test a withdraw that has not expired yet
    receive_withdraw_expired = ReceiveWithdrawExpired(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=expiration_block_number,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw_expired,
        block_number=expiration_threshold - 1,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events,
            EventInvalidReceivedWithdrawExpired,
            {"attempted_withdraw": total_withdraw},
        )
        is not None
    )
    assert (
        pending_withdraw
        == iteration.new_state.partner_state.withdraws_pending[pending_withdraw.total_withdraw]
    )


def test_node_rejects_received_withdraw_expiry_invalid_signature():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_receiver_expiration_threshold(expiration_block_number)

    pending_withdraw = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )
    channel_state.partner_state.withdraws_pending[total_withdraw] = pending_withdraw

    # Signed by wrong party
    receive_withdraw_expired = ReceiveWithdrawExpired(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        sender=channel_state.our_state.address,  # signed by wrong party
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=1,
        expiration=expiration_block_number,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw_expired,
        block_number=expiration_threshold,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events,
            EventInvalidReceivedWithdrawExpired,
            {"attempted_withdraw": total_withdraw},
        )
        is not None
    )
    assert (
        pending_withdraw
        == iteration.new_state.partner_state.withdraws_pending[pending_withdraw.total_withdraw]
    )


def test_node_rejects_received_withdraw_expiry_invalid_nonce():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_receiver_expiration_threshold(expiration_block_number)

    pending_withdraw = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )
    channel_state.partner_state.withdraws_pending[total_withdraw] = pending_withdraw

    # Invalid Nonce
    receive_withdraw_expired = ReceiveWithdrawExpired(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=5,
        expiration=expiration_block_number,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw_expired,
        block_number=expiration_threshold,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert (
        search_for_item(
            iteration.events,
            EventInvalidReceivedWithdrawExpired,
            {"attempted_withdraw": total_withdraw},
        )
        is not None
    )
    assert (
        pending_withdraw
        == iteration.new_state.partner_state.withdraws_pending[pending_withdraw.total_withdraw]
    )


def test_node_multiple_withdraws_with_one_expiring():
    pseudo_random_generator = random.Random()

    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)
    block_hash = make_block_hash()

    total_withdraw = 50
    expiration_block_number = 10
    expiration_threshold = channel.get_receiver_expiration_threshold(expiration_block_number)

    second_total_withdraw = total_withdraw * 2

    # Test multiple withdraws with one expiring
    channel_state.partner_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=expiration_block_number, nonce=1
    )
    channel_state.partner_state.withdraws_pending[second_total_withdraw] = PendingWithdrawState(
        total_withdraw=second_total_withdraw, expiration=expiration_block_number * 2, nonce=2
    )
    channel_state.partner_state.nonce = 2

    receive_withdraw_expired = ReceiveWithdrawExpired(
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        sender=channel_state.partner_state.address,
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        nonce=3,
        expiration=expiration_block_number,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=receive_withdraw_expired,
        block_number=expiration_threshold,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert search_for_item(iteration.events, SendProcessed, {}) is not None

    channel_state = iteration.new_state
    # An older withdraw expired.
    # The latest withdraw should still be our partner's latest withdraw
    assert channel_state.partner_state.offchain_total_withdraw == second_total_withdraw
    assert second_total_withdraw in channel_state.partner_state.withdraws_pending


def test_receive_contract_withdraw():
    pseudo_random_generator = random.Random()
    our_model1, _ = create_model(balance=70)
    partner_model1, privkey2 = create_model(balance=100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    block_hash = make_block_hash()
    block_number = 15

    total_withdraw = 50

    channel_state.our_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=1, nonce=1
    )

    channel_state.partner_state.withdraws_pending[total_withdraw] = PendingWithdrawState(
        total_withdraw=total_withdraw, expiration=1, nonce=1
    )

    contract_receive_withdraw = ContractReceiveChannelWithdraw(
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        participant=channel_state.our_state.address,
        # pylint: enable=no-member
        block_number=block_number,
        block_hash=block_hash,
        transaction_hash=make_transaction_hash(),
        fee_config=MediationFeeConfig(),
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=contract_receive_withdraw,
        block_hash=block_hash,
        block_number=block_number,
        pseudo_random_generator=pseudo_random_generator,
    )

    assert iteration.new_state.our_state.offchain_total_withdraw == 0
    assert iteration.new_state.our_state.onchain_total_withdraw == total_withdraw
    assert iteration.new_state.our_state.total_withdraw == total_withdraw
    assert iteration.new_state.our_total_withdraw == total_withdraw
    assert total_withdraw not in iteration.new_state.our_state.withdraws_pending

    contract_receive_withdraw = ContractReceiveChannelWithdraw(
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        # pylint: disable=no-member
        participant=channel_state.partner_state.address,
        # pylint: enable=no-member
        block_number=block_number,
        block_hash=block_hash,
        transaction_hash=make_transaction_hash(),
        fee_config=MediationFeeConfig(),
    )

    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=contract_receive_withdraw,
        block_hash=block_hash,
        block_number=block_number,
        pseudo_random_generator=pseudo_random_generator,
    )
    assert iteration.new_state.partner_state.offchain_total_withdraw == 0
    assert iteration.new_state.partner_state.onchain_total_withdraw == total_withdraw
    assert iteration.new_state.partner_state.total_withdraw == total_withdraw
    assert iteration.new_state.partner_total_withdraw == total_withdraw
    assert total_withdraw not in iteration.new_state.partner_state.withdraws_pending
