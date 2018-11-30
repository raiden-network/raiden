from raiden.tests.utils import factories


class MockChain:
    def __init__(self):
        self.network_id = 17


class MockRaidenService:
    def __init__(self, message_handler=None):
        self.chain = MockChain()
        self.private_key, self.address = factories.make_privatekey_address()
        self.message_handler = message_handler

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
