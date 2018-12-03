import random

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.state_change import ActionInitChain


class MockChain:
    def __init__(self):
        self.network_id = 17


class MockRaidenService:
    def __init__(self, message_handler=None, state_transition=None):
        self.chain = MockChain()
        self.private_key, self.address = factories.make_privatekey_address()

        self.chain.node_address = self.address
        self.message_handler = message_handler

        if state_transition is None:
            state_transition = node.state_transition

        serializer = JSONSerializer
        state_manager = StateManager(state_transition, None)
        storage = SQLiteStorage(':memory:', serializer)
        self.wal = WriteAheadLog(state_manager, storage)

        state_change = ActionInitChain(
            random.Random(),
            0,
            self.chain.node_address,
            self.chain.network_id,
        )

        self.wal.log_and_dispatch(state_change)

    def on_message(self, message):
        if self.message_handler:
            self.message_handler.on_message(self, message)

    def handle_state_change(self, state_change):
        pass

    def sign(self, message):
        message.sign(self.private_key)


class MockDiscovery(object):

    def get(self, node_address: bytes):
        return '127.0.0.1:5252'
