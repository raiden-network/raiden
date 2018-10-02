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

    # Register 2 messages into the queue
    chain_state.queueids_to_queues[queue_identifier] = [first_message, second_message]

    delivered_message = state_change.ReceiveDelivered(recipient, message_identifier)

    iteration = node.handle_delivered(chain_state, delivered_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    assert first_message not in new_queue


def test_delivered_message(chain_id):
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

    # Register 2 messages into the queue
    chain_state.queueids_to_queues[queue_identifier] = [first_message, second_message]

    # Generate a random message_identifier
    fake_message_identifier = random.randint(0, 2 ** 16)
    node.handle_delivered(
        chain_state,
        state_change.ReceiveDelivered(recipient, fake_message_identifier),
    )

    # The queue should have the original 2 messages and
    # our fake delivered should have been ignored
    assert len(chain_state.queueids_to_queues[queue_identifier]) == 2

    # Now try to handle delivered with a wrong sender
    # Generate a random message_identifier
    node.handle_delivered(
        chain_state,
        state_change.ReceiveDelivered(factories.make_address(), message_identifier),
    )

    # The queue should have the original 2 messages and
    # our delivered messages don't match the state change sender
    assert len(chain_state.queueids_to_queues[queue_identifier]) == 2

    delivered_message = state_change.ReceiveDelivered(recipient, message_identifier)

    iteration = node.handle_delivered(chain_state, delivered_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    assert first_message not in new_queue

    # Register 2 messages into the queue
    chain_state.queueids_to_queues[queue_identifier] = [first_message, second_message]

    # Generate a random message_identifier
    fake_message_identifier = random.randint(0, 2 ** 16)
    node.handle_delivered(
        chain_state,
        state_change.ReceiveDelivered(recipient, fake_message_identifier),
    )

    # The queue should have the original 2 messages and
    # our fake delivered should have been ignored
    assert len(chain_state.queueids_to_queues[queue_identifier]) == 2

    # Now try to handle delivered with a wrong sender
    # Generate a random message_identifier
    node.handle_delivered(
        chain_state,
        state_change.ReceiveDelivered(factories.make_address(), message_identifier),
    )

    # The queue should have the original 2 messages and
    # our delivered messages don't match the state change sender
    assert len(chain_state.queueids_to_queues[queue_identifier]) == 2

    delivered_message = state_change.ReceiveDelivered(recipient, message_identifier)

    iteration = node.handle_delivered(chain_state, delivered_message)
    new_queue = iteration.new_state.queueids_to_queues.get(queue_identifier, [])

    assert first_message not in new_queue
