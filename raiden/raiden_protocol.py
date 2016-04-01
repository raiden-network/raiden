# -*- coding: utf8 -*-
import gevent

from ethereum import slogging

from raiden import messages
from raiden.utils import isaddress, sha3, pex
from raiden.messages import Ack, Secret, BaseError

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


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

        host_port = self.discovery.get(receiver_address)
        data = msg.encode()
        msghash = sha3(data)
        self.tries[msghash] = self.max_tries

        log.info('SENDING {} > {} : [{}] {}'.format(
            pex(self.raiden.address),
            pex(receiver_address),
            pex(msghash),
            msg,
        ))

        assert len(data) < self.max_message_size

        def repeater():
            while self.tries.get(msghash, 0) > 0:
                if not self.repeat_messages and self.tries[msghash] < self.max_tries:
                    raise Exception('DEACTIVATED MSG resents {} {}'.format(
                        pex(receiver_address),
                        msg,
                    ))

                self.tries[msghash] -= 1
                self.transport.send(self.raiden, host_port, data)
                gevent.sleep(self.try_interval)

            # Each sent msg must be acked. When msg is acked its hash is removed from self.tries
            if msghash in self.tries:
                # FIXME: suspend node
                raise RuntimeError('Node does not reply')

        gevent.spawn(repeater)

    def send_ack(self, receiver_address, msg):
        assert isinstance(msg, (Ack, BaseError))
        assert isaddress(receiver_address)

        host_port = self.discovery.get(receiver_address)
        data = msg.encode()
        msghash = sha3(data)

        log.info('SENDING ACK {} > {} : [{}] [echo={}] {}'.format(
            pex(self.raiden.address),
            pex(receiver_address),
            pex(msghash),
            pex(msg.echo),
            msg,
        ))

        self.transport.send(self.raiden, host_port, msg.encode())
        self.sent_acks[msg.echo] = (receiver_address, msg)

    def receive(self, data):
        assert len(data) < self.max_message_size

        msghash = sha3(data)

        # check if we handled this message already, if so repeat Ack
        if msghash in self.sent_acks:
            return self.send_ack(*self.sent_acks[msghash])

        # We ignore the sending endpoint as this can not be known w/ UDP
        msg = messages.decode(data)

        # handle Acks
        if isinstance(msg, Ack):
            log.debug('ACK MSGHASH RECEIVED', echo=pex(msg.echo))
            del self.tries[msg.echo]
            return

        assert isinstance(msg, Secret) or msg.sender
        self.raiden.on_message(msg, msghash)
