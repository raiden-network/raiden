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

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden

        self.number_of_tries = dict()  # msg hash: count_tries
        self.sent_acks = dict()  # msghash: Ack

    def send(self, receiver_address, msg):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(msg, (Ack, BaseError)):
            raise ValueError('Do not use send for Ack messages or Erorrs')

        if len(msg.encode()) > self.max_message_size:
            raise ValueError('message size excedes the maximum {}'.format(self.max_message_size))

        return gevent.spawn(self._repeat_until_ack, receiver_address, msg)

    def _repeat_until_ack(self, receiver_address, msg):
        data = msg.encode()
        host_port = self.discovery.get(receiver_address)

        # msghash is removed from the `number_of_tries` once a Ack is
        # received, resend until we receive it or give up
        msghash = sha3(data)
        self.number_of_tries[msghash] = 0

        log.info('SENDING {} > {} : [{}] {}'.format(
            pex(self.raiden.address),
            pex(receiver_address),
            pex(msghash),
            msg,
        ))

        while msghash in self.number_of_tries:
            if self.number_of_tries[msghash] > self.max_tries:
                # FIXME: suspend node + recover from the failure
                raise Exception('DEACTIVATED MSG resents {} {}'.format(
                    pex(receiver_address),
                    msg,
                ))

            self.number_of_tries[msghash] += 1
            self.transport.send(self.raiden, host_port, data)
            gevent.sleep(self.try_interval)

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
        # ignore large packets
        if len(data) > self.max_message_size:
            log.error('receive packet larger than maximum size', length=len(data))
            return

        msghash = sha3(data)

        # check if we handled this message already, if so repeat Ack
        if msghash in self.sent_acks:
            return self.send_ack(*self.sent_acks[msghash])

        # We ignore the sending endpoint as this can not be known w/ UDP
        msg = messages.decode(data)

        if isinstance(msg, Ack):
            # we might receive the same Ack more than once
            if msg.echo in self.number_of_tries:
                log.debug('ACK RECEIVED {} [echo={}]'.format(
                    pex(self.raiden.address),
                    pex(msg.echo)
                ))

                del self.number_of_tries[msg.echo]
            else:
                log.debug('DUPLICATED ACK RECEIVED {} [echo={}]'.format(
                    pex(self.raiden.address),
                    pex(msg.echo)
                ))
        else:
            assert isinstance(msg, Secret) or msg.sender
            self.raiden.on_message(msg, msghash)
