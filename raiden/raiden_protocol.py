import messages
from messages import Ack, Secret, BaseError
from utils import isaddress, sha3, pex
import gevent


class RaidenProtocol(object):

    """
    each message sent or received is stored by hash
    if message is received twice, resent previous answer
    if there is no response to a message, message gets repeated max N times
    """

    try_interval = 1.
    max_tries = 5
    max_message_size = 1200
    repeat_messages = False  # default for testing, w/o packet loss

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden

        self.tries = dict()  # msg hash: count_tries
        self.sent_acks = dict()  # msghash: Ack

    def send(self, receiver_address, msg):
        assert isaddress(receiver_address)
        assert not isinstance(msg, (Ack, BaseError)), msg
        print "SENDING {} > {} : {}".format(pex(self.raiden.address), pex(receiver_address), msg)
        host_port = self.discovery.get(receiver_address)
        data = msg.encode()
        msghash = sha3(data)
        self.tries[msghash] = self.max_tries
        print "MSGHASH SENT", pex(msghash)

        assert len(data) < self.max_message_size

        def repeater():
            while self.tries.get(msghash, 0) > 0:
                if not self.repeat_messages and self.tries[msghash] < self.max_tries:
                    raise Exception(
                        "DEACTIVATED MSG resents {} {}".format(pex(receiver_address), msg))
                self.tries[msghash] -= 1
                self.transport.send(self.raiden, host_port, data)
                gevent.sleep(self.try_interval)
            if msghash in self.tries:
                assert False, "Node does not reply, fixme suspend node"

        gevent.spawn(repeater)

    def send_ack(self, receiver_address, msg):
        assert isinstance(msg,  (Ack, BaseError))
        assert isaddress(receiver_address)
        host_port = self.discovery.get(receiver_address)
        self.transport.send(self.raiden, host_port, msg.encode())
        self.sent_acks[msg.echo] = (receiver_address, msg)
        print "ACK MSGHASH SENT", pex(msg.echo)

    def receive(self, data):
        assert len(data) < self.max_message_size

        # check if we handled this message already, if so repeat Ack
        msghash = sha3(data)
        if msghash in self.sent_acks:
            # assert False, "DEACTIVATED ACK RESENTS"
            return self.send_ack(*self.sent_acks[msghash])

        # note, we ignore the sending endpoint, as this can not be known w/ UDP
        msg = messages.decode(data)
        # handle Acks
        if isinstance(msg, Ack):
            print "ACK MSGHASH RECEIVED", pex(msg.echo)
            del self.tries[msg.echo]
            return

        assert isinstance(msg, Secret) or msg.sender
        self.raiden.on_message(msg, msghash)
