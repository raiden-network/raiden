# -*- coding: utf8 -*-
import gevent
from ethereum import slogging

from raiden.messages import decode, Ack, BaseError, Secret
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class RaidenProtocol(object):
    """ Encode the message into a packet and send it.

    Each message received is stored by hash and if it is received twice the
    previous answer is resent.

    Repeat sending messages until an acknowledgment is received or the maximum
    number of retries is hitted.
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

    def send(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, (Ack, BaseError)):
            raise ValueError('Do not use send for Ack messages or Errors')

        if len(message.encode()) > self.max_message_size:
            raise ValueError('message size exceeds the maximum {}'.format(self.max_message_size))

        return gevent.spawn(self._repeat_until_ack, receiver_address, message)

    def _repeat_until_ack(self, receiver_address, message):
        data = message.encode()
        host_port = self.discovery.get(receiver_address)

        # msghash is removed from the `number_of_tries` once a Ack is
        # received, resend until we receive it or give up
        msghash = sha3(data)
        self.number_of_tries[msghash] = 0

        log.info('SENDING {} > {} : [{}] {}'.format(
            pex(self.raiden.address),
            pex(receiver_address),
            pex(msghash),
            message,
        ))

        while msghash in self.number_of_tries:
            if self.number_of_tries[msghash] > self.max_tries:
                # FIXME: suspend node + recover from the failure
                raise Exception('DEACTIVATED MSG resents {} {}'.format(
                    pex(receiver_address),
                    message,
                ))

            self.number_of_tries[msghash] += 1
            self.transport.send(self.raiden, host_port, data)
            gevent.sleep(self.try_interval)

    def send_ack(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if not isinstance(message, (Ack, BaseError)):
            raise ValueError('Use send_Ack only for Ack messages or Erorrs')

        host_port = self.discovery.get(receiver_address)
        data = message.encode()
        msghash = sha3(data)

        log.info('SENDING ACK {} > {} : [{}] [echo={}] {}'.format(
            pex(self.raiden.address),
            pex(receiver_address),
            pex(msghash),
            pex(message.echo),
            message,
        ))

        self.transport.send(self.raiden, host_port, data)
        self.sent_acks[message.echo] = (receiver_address, message)

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
        message = decode(data)

        if isinstance(message, Ack):
            # we might receive the same Ack more than once
            if message.echo in self.number_of_tries:
                log.info('ACK RECEIVED {} [echo={}]'.format(
                    pex(self.raiden.address),
                    pex(message.echo)
                ))

                del self.number_of_tries[message.echo]
            else:
                log.info('DUPLICATED ACK RECEIVED {} [echo={}]'.format(
                    pex(self.raiden.address),
                    pex(message.echo)
                ))
        else:
            # message may not have been decoded
            if message is not None:
                assert isinstance(message, Secret) or message.sender
                self.raiden.on_message(message, msghash)
