import random

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.signer import LocalSigner


class MockTokenNetwork:

    @staticmethod
    def detail_participants(
            participant1,
            participant2,
            block_identifier,
            channel_identifier,
    ):
        # To be changed by each test
        return None


class MockPaymentChannel:

    def __init__(self, token_network, channel_id):
        self.token_network = token_network


class MockChain:
    def __init__(self):
        self.network_id = 17
        # let's make a single mock token network for testing
        self.token_network = MockTokenNetwork()

    def payment_channel(self, token_network_address, channel_id):
        return MockPaymentChannel(self.token_network, channel_id)


class MockRaidenService:
    def __init__(self, message_handler=None, state_transition=None):
        self.chain = MockChain()
        self.private_key, self.address = factories.make_privatekey_address()
        self.signer = LocalSigner(self.private_key)

        self.chain.node_address = self.address
        self.message_handler = message_handler

        if state_transition is None:
            state_transition = node.state_transition

        serializer = JSONSerializer
        state_manager = StateManager(state_transition, None)
        storage = SerializedSQLiteStorage(':memory:', serializer)
        self.wal = WriteAheadLog(state_manager, storage)

        state_change = ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=0,
            block_hash=factories.make_block_hash(),
            our_address=self.chain.node_address,
            chain_id=self.chain.network_id,
        )

        self.wal.log_and_dispatch(state_change)

    def on_message(self, message):
        if self.message_handler:
            self.message_handler.on_message(self, message)

    def handle_and_track_state_change(self, state_change):
        pass

    def handle_state_change(self, state_change):
        pass

    def sign(self, message):
        message.sign(self.signer)
