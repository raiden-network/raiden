# -*- coding: utf8 -*-
import gevent
from gevent.queue import Queue
from gevent.event import AsyncResult
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
    short_delay = .1

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden
        self.queued_messages = Queue()
        self.stop_event = AsyncResult()

        self.number_of_tries = dict()  # msg hash: count_tries
        self.sent_acks = dict()  # msghash: Ack

        gevent.spawn(self._send_queued_messages)

    def _send_queued_messages(self):
        countdown_to_send = self.try_interval / self.short_delay
        countdown = 0

        stop = None
        while stop is None:
            # blocks waiting for data in queue, don't remove data from
            # the queue just now because sending can still fail.
            receiver_address, message = self.queued_messages.peek()

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

            # loop should iterate as fast as possible checking for acks
            while msghash in self.number_of_tries:
                if self.number_of_tries[msghash] > self.max_tries:
                    # free send_and_wait...
                    del self.number_of_tries[msghash]

                    # FIXME: there was no connectivity or other network error?
                    # for now just losing the packet but better error handler
                    # needs to be added.
                    log.error('DEACTIVATED MSG resents {} {}'.format(
                        pex(receiver_address),
                        message,
                    ))

                # only send a message again after some time (don't DOS!)
                if countdown == 0:
                    self.number_of_tries[msghash] += 1
                    self.transport.send(self.raiden, host_port, data)
                    countdown = countdown_to_send

                gevent.sleep(self.short_delay)
                countdown -= 1

            # consume last sent message
            self.queued_messages.get()
            stop = self.stop_event.wait(self.short_delay)

    def send(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, (Ack, BaseError)):
            raise ValueError('Do not use send for Ack messages or Erorrs')

        if len(message.encode()) > self.max_message_size:
            raise ValueError('message size excedes the maximum {}'.format(self.max_message_size))

        self.queued_messages.put((receiver_address, message))

    def send_and_wait(self, receiver_address, message):
        """Sends a message and wait for the response ack."""
        self.send(receiver_address, message)

        data = message.encode()
        msghash = sha3(data)
        # FIXME: add error handling
        while msghash in self.number_of_tries:
            gevent.sleep(self.short_delay)

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
            assert isinstance(message, Secret) or message.sender
            self.raiden.on_message(message, msghash)

    def stop(self):
        self.stop_event.set(True)
