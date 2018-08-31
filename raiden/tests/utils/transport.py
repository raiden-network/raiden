class MockRaidenService(object):

    def __init__(self, address):
        self.address = address


class MockDiscovery(object):

    def get(self, node_address: bytes):
        return '127.0.0.1:5252'
