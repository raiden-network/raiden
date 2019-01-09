import random
from unittest.mock import Mock

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.state_change import ActionInitChain


def MockTokenNetwork():
    """ Tests might want to `.configure_mock(participant_details.return_value=ParticipantDetails..`
    """
    return Mock()


def MockPaymentChannel(token_network, channel_id):
    return Mock(
        name='MockPaymentChannel',
        token_network=token_network,
        channel_id=channel_id,
    )


def MockChain():
    mock = Mock()

    def payment_channel(token_network_address, channel_id):
        if not (token_network_address, channel_id) in mock._payment_channels:
            mock._payment_channels[(
                token_network_address,
                channel_id,
            )] = MockPaymentChannel(mock.token_network, channel_id)
        return mock._payment_channels[(token_network_address, channel_id)]
    mock.configure_mock(**dict(
        network_id=17,
        # let's make a single mock token network for testing
        token_network=MockTokenNetwork(),
        payment_channel=payment_channel,
    ))
    mock._payment_channels = dict()
    return mock


def MockRaidenService(message_handler=None, state_transition=None):
    mock = Mock()
    mock.chain = MockChain()
    mock.private_key, mock.address = factories.make_privatekey_address()

    mock.chain.node_address = mock.address
    mock.message_handler = message_handler

    if state_transition is None:
        state_transition = node.state_transition

    serializer = JSONSerializer
    state_manager = StateManager(state_transition, None)
    storage = SQLiteStorage(':memory:', serializer)
    mock.wal = WriteAheadLog(state_manager, storage)

    state_change = ActionInitChain(
        random.Random(),
        0,
        mock.chain.node_address,
        mock.chain.network_id,
    )

    mock.wal.log_and_dispatch(state_change)

    def on_message(message):
        if mock.message_handler:
            mock.message_handler.on_message(mock, message)

    def handle_state_change(state_change):
        pass

    def sign(message):
        message.sign(mock.private_key)

    mock.on_message = on_message
    mock.handle_state_change = handle_state_change
    mock.sign = sign
    return mock
