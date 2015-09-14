import rlp
import messages
from utils import privtoaddr


class RaidenProtocol(object):

    def __init__(self, network_, discovery, raiden_service):
        self.network = network_
        self.discovery = discovery
        self.raiden_service = raiden_service

    def send(self, receiver_address, msg):
        host_port = self.discovery.get(receiver_address)
        self.network.send(self.raiden_service, host_port, rlp.encode(msg))

    def receive(self, msg):
        # note, we ignore the sending endpoint, as this can not be known w/ UDP
        msg = messages.deserialize(msg)
        assert msg.sender
        self.raiden_service.on_message(msg)


class RaidenService(object):

    def __init__(self, chain, privkey, network_, discovery):
        self.chain = chain
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(network_, discovery, self)

    def on_message(self, msg):
        method = 'on_%s' % msg.__class__.__name__.lower()
        getattr(self, method)(msg)

    def on_ping(self, msg):
        self.send_ack(msg)

    def on_ack(self, msg):
        pass

    def send_ack(self, msg):
        self.protocol.send(msg.sender, messages.Ack(msg.hash).sign(self.address))

    def on_rejected(self, msg):
        pass

    def on_hashlockrequest(self, msg):
        pass

    def on_hashlock(self, msg):
        pass

    def on_transfer(self, msg):
        pass

    def on_lockedtransfer(self, msg):
        pass

    def on_mediatedtransfer(self, msg):
        pass

    def on_transferrequest(self, msg):
        pass

    def on_exchangerequest(self, msg):
        pass
