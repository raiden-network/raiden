import random

from raiden.constants import EMPTY_HASH
from raiden.tests.utils import factories
from raiden.transfer import node, state, state_change
from raiden.transfer.events import SendWithdrawRequest
from raiden.transfer.identifiers import (
    CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
    CanonicalIdentifier,
    QueueIdentifier,
)
from raiden.transfer.mediated_transfer.events import SendSecretReveal
from raiden.transfer.state_change import ReceiveWithdrawConfirmation


def test_delivered_message_must_clean_unordered_messages(chain_id):
    pseudo_random_generator = random.Random()
    block_number = 10
    our_address = factories.make_address()
    recipient = factories.make_address()
    canonical_identifier = factories.make_canonical_identifier()
    message_identifier = random.randint(0, 2 ** 16)
    secret = factories.random_secret()

    chain_state = state.ChainState(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )
    queue_identifier = QueueIdentifier(
        recipient=recipient, canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE
    )

    # Regression test:
    # The code delivered_message handler worked only with a queue of one
    # element
    first_message = SendSecretReveal(
        recipient=recipient,
        message_identifier=message_identifier,
        secret=secret,
        canonical_identifier=canonical_identifier,
    )

    second_message = SendSecretReveal(
        recipient=recipient,
        message_identifier=random.randint(0, 2 ** 16),
        secret=secret,
        canonical_identifier=canonical_identifier,
    )

    chain_state.queueids_to_queues[queue_identifier] = [first_message, second_message]

    delivered_message = state_change.ReceiveDelivered(recipient, message_identifier)

    iteration = node.handle_delivered(chain_state, delivered_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    assert first_message not in new_queue


def test_withdraw_request_message_cleanup(chain_id, token_network_state):
    pseudo_random_generator = random.Random()
    block_number = 10
    our_address = factories.make_address()
    recipient1 = factories.make_address()
    recipient2 = factories.make_address()
    channel_identifier = 1
    message_identifier = random.randint(0, 2 ** 16)

    chain_state = state.ChainState(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )
    queue_identifier = QueueIdentifier(recipient1, CANONICAL_IDENTIFIER_GLOBAL_QUEUE)

    withdraw_message = SendWithdrawRequest(
        message_identifier=message_identifier,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_state.address,
            channel_identifier=channel_identifier,
        ),
        total_withdraw=100,
        participant=our_address,
        recipient=recipient1,
        nonce=1,
        expiration=10,
    )

    chain_state.queueids_to_queues[queue_identifier] = [withdraw_message]
    processed_message = state_change.ReceiveProcessed(recipient1, message_identifier)

    iteration = node.handle_processed(chain_state, processed_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    # Processed should not have removed the WithdrawRequest message
    assert withdraw_message in new_queue

    receive_withdraw = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_state.address,
            channel_identifier=channel_identifier,
        ),
        total_withdraw=100,
        signature=factories.make_32bytes(),
        sender=recipient2,
        participant=recipient2,
        nonce=1,
        expiration=10,
    )
    iteration = node.handle_receive_withdraw(chain_state, receive_withdraw)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    # ReceiveWithdraw from another recipient should not remove the WithdrawRequest
    assert withdraw_message in new_queue

    receive_withdraw = ReceiveWithdrawConfirmation(
        message_identifier=message_identifier,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_state.address,
            channel_identifier=channel_identifier,
        ),
        total_withdraw=100,
        signature=factories.make_32bytes(),
        sender=recipient1,
        participant=recipient1,
        nonce=1,
        expiration=10,
    )
    iteration = node.handle_receive_withdraw(chain_state, receive_withdraw)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])
    assert withdraw_message not in new_queue


def test_delivered_processed_message_cleanup():
    recipient = factories.make_address()
    canonical_identifier = factories.make_canonical_identifier()
    secret = factories.random_secret()

    first_message = SendSecretReveal(
        recipient=recipient,
        message_identifier=random.randint(0, 2 ** 16),
        secret=secret,
        canonical_identifier=canonical_identifier,
    )
    second_message = SendSecretReveal(
        recipient=recipient,
        message_identifier=random.randint(0, 2 ** 16),
        secret=secret,
        canonical_identifier=canonical_identifier,
    )
    message_queue = [first_message, second_message]

    fake_message_identifier = random.randint(0, 2 ** 16)
    node.inplace_delete_message(
        message_queue, state_change.ReceiveDelivered(recipient, fake_message_identifier)
    )
    assert first_message in message_queue, "invalid message id must be ignored"
    assert second_message in message_queue, "invalid message id must be ignored"

    invalid_sender_address = factories.make_address()
    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveDelivered(invalid_sender_address, first_message.message_identifier),
    )
    assert first_message in message_queue, "invalid sender id must be ignored"
    assert second_message in message_queue, "invalid sender id must be ignored"

    node.inplace_delete_message(
        message_queue, state_change.ReceiveProcessed(recipient, first_message.message_identifier)
    )
    msg = "message must be cleared when a valid delivered is received"
    assert first_message not in message_queue, msg
    assert second_message in message_queue, msg


def test_channel_closed_must_clear_ordered_messages(
    chain_state, token_network_state, netting_channel_state
):
    recipient = netting_channel_state.partner_state.address
    message_identifier = random.randint(0, 2 ** 16)
    amount = 10

    queue_identifier = QueueIdentifier(
        recipient=recipient, canonical_identifier=netting_channel_state.canonical_identifier
    )

    # Regression test:
    # The code delivered_message handler worked only with a queue of one
    # element
    message = factories.create(
        factories.LockedTransferProperties(
            message_identifier=message_identifier,
            token=token_network_state.token_address,
            canonical_identifier=netting_channel_state.canonical_identifier,
            transferred_amount=amount,
            recipient=recipient,
        )
    )

    chain_state.queueids_to_queues[queue_identifier] = [message]

    closed = state_change.ContractReceiveChannelClosed(
        transaction_hash=EMPTY_HASH,
        transaction_from=recipient,
        canonical_identifier=netting_channel_state.canonical_identifier,
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    iteration = node.handle_state_change(chain_state, closed)
    assert queue_identifier not in iteration.new_state.queueids_to_queues
