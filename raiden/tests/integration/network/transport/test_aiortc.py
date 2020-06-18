from typing import Tuple
import gevent
import pytest
from raiden.constants import (

    EMPTY_SIGNATURE,

)

from raiden.messages.synchronization import Delivered, Processed
from raiden.network.transport.matrix.transport import MatrixTransport, MessagesQueue
from raiden.tests.utils.mocks import MockRaidenService
from raiden.utils.formatting import to_checksum_address
from raiden.transfer.identifiers import QueueIdentifier
from raiden.tests.utils import factories
from raiden.transfer import views
from gevent.timeout import Timeout

TIMEOUT_MESSAGE_RECEIVE = 15

class MessageHandler:
    def __init__(self, bag: set):
        self.bag = bag

    def on_messages(self, _, messages):
        self.bag.update(messages)

@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("number_of_transports", [2])
def test_matrix_message_sync(matrix_transports: Tuple[MatrixTransport]):

    transport0, transport1 = matrix_transports

    transport0_messages = set()
    transport1_messages = set()

    transport0_message_handler = MessageHandler(transport0_messages)
    transport1_message_handler = MessageHandler(transport1_messages)

    raiden_service0 = MockRaidenService(transport0_message_handler)
    raiden_service1 = MockRaidenService(transport1_message_handler)

    print(f"transport0: {to_checksum_address(raiden_service0.address)}")
    print(f"transport1: {to_checksum_address(raiden_service1.address)}")

    transport0.start(raiden_service0, [], None)
    transport1.start(raiden_service1, [], None)

    transport0.immediate_health_check_for(transport1._raiden_service.address)
    transport1.immediate_health_check_for(transport0._raiden_service.address)

    while raiden_service1.address not in transport0.aio_gevent_transceiver.peer_connections:
        gevent.wait(timeout=1)
    while raiden_service0.address not in transport1.aio_gevent_transceiver.peer_connections:
        gevent.wait(timeout=1)



    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=factories.UNIT_CANONICAL_ID,
    )

    raiden0_queues = views.get_all_messagequeues(views.state_from_raiden(raiden_service0))
    raiden0_queues[queue_identifier] = []

    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        raiden0_queues[queue_identifier].append(message)
        transport0._raiden_service.sign(message)
        transport0.send_async([MessagesQueue(queue_identifier, [message])])

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while not len(transport0_messages) == 5:
            gevent.sleep(0.1)

        while not len(transport1_messages) == 5:
            gevent.sleep(0.1)

    # transport1 receives the `Processed` messages sent by transport0
    for i in range(5):
        assert any(m.message_identifier == i for m in transport1_messages)

    # transport0 answers with a `Delivered` for each `Processed`
    for i in range(5):
        assert any(m.delivered_message_identifier == i for m in transport0_messages)

    # Clear out queue
    raiden0_queues[queue_identifier] = []

    gevent.sleep(100)
