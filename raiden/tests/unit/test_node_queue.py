import random

from raiden.tests.utils import factories
from raiden.transfer import node, state, state_change
from raiden.transfer.mediated_transfer import events
from raiden.transfer.queue_identifier import QueueIdentifier


def test_delivered_message_must_clean_unordered_messages(chain_id):
    pseudo_random_generator = random.Random()
    block_number = 10
    our_address = factories.make_address()
    recipient = factories.make_address()
    channel_identifier = 1
    message_identifier = random.randint(0, 2 ** 16)
    secret = factories.random_secret()

    chain_state = state.ChainState(
        pseudo_random_generator,
        block_number,
        our_address,
        chain_id,
    )
    queue_identifier = QueueIdentifier(
        recipient,
        events.CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    )

    # Regression test:
    # The code delivered_message handler worked only with a queue of one
    # element
    first_message = events.SendSecretReveal(
        recipient,
        channel_identifier,
        message_identifier,
        secret,
    )
    second_message = events.SendSecretReveal(
        recipient,
        channel_identifier,
        random.randint(0, 2 ** 16),
        secret,
    )

    chain_state.queueids_to_queues[queue_identifier] = [first_message, second_message]

    delivered_message = state_change.ReceiveDelivered(recipient, message_identifier)

    iteration = node.handle_delivered(chain_state, delivered_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    assert first_message not in new_queue


def test_delivered_processed_message_cleanup(chain_id):
    recipient = factories.make_address()
    channel_identifier = 1
    secret = factories.random_secret()

    # Regression test:
    # The code delivered_message handler worked only with a queue of one
    # element
    first_message = events.SendSecretReveal(
        recipient,
        channel_identifier,
        random.randint(0, 2 ** 16),
        secret,
    )
    second_message = events.SendSecretReveal(
        recipient,
        channel_identifier,
        random.randint(0, 2 ** 16),
        secret,
    )

    # Register 2 messages into the queue
    message_queue = [first_message, second_message]

    # Generate a random message_identifier
    fake_message_identifier = random.randint(0, 2 ** 16)
    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveDelivered(recipient, fake_message_identifier),
    )

    # The queue should have the original 2 messages and
    # our fake delivered should have been ignored
    assert first_message in message_queue
    assert second_message in message_queue

    # Now try to handle delivered with a wrong sender
    # Generate a random message_identifier
    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveDelivered(factories.make_address(), first_message.message_identifier),
    )

    # The queue should have the original 2 messages and
    # our delivered messages don't match the state change sender
    assert first_message in message_queue
    assert second_message in message_queue

    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveDelivered(recipient, first_message.message_identifier),
    )

    assert first_message not in message_queue
    assert second_message in message_queue

    # Register 2 messages into the queue
    message_queue = [first_message, second_message]

    # Generate a random message_identifier
    fake_message_identifier = random.randint(0, 2 ** 16)
    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveProcessed(recipient, fake_message_identifier),
    )

    # The queue should have the original 2 messages and
    # our fake delivered should have been ignored
    assert first_message in message_queue
    assert second_message in message_queue

    # Now try to handle delivered with a wrong sender
    # Generate a random message_identifier
    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveProcessed(factories.make_address(), first_message.message_identifier),
    )

    # The queue should have the original 2 messages and
    # our delivered messages don't match the state change sender
    assert first_message in message_queue
    assert second_message in message_queue

    node.inplace_delete_message(
        message_queue,
        state_change.ReceiveProcessed(recipient, first_message.message_identifier),
    )

    assert first_message not in message_queue
    assert second_message in message_queue
