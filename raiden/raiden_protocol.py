# -*- coding: utf8 -*-
import logging

import gevent
from gevent.queue import Queue
from gevent.event import AsyncResult, Event
from ethereum import slogging

from raiden.messages import decode, Ack, Secret
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class NotifyingQueue(Event):
    """ A queue that follows the wait protocol. """

    def __init__(self):
        super(NotifyingQueue, self).__init__()
        self._queue = Queue()

    def put(self, item):
        """ Add new item to the queue. """
        self._queue.put(item)
        self.set()

    def get(self, block=True, timeout=None):
        """ Removes and returns an item from the queue. """
        value = self._queue.get(block, timeout)
        if self._queue.empty():
            self.clear()
        return value

    def stop(self):
        """ Request a stop event. """
        self.set()


class RaidenProtocol(object):
    """ Encode the message into a packet and send it.

    Each message received is stored by hash and if it is received twice the
    previous answer is resent.

    Repeat sending messages until an acknowledgment is received or the maximum
    number of retries is hitted.
    """

    try_interval = 1.
    max_retries = 5
    max_message_size = 1200

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden

        # Messages are sent in-order for each partner
        self.address_queue = dict()
        self.address_greenlet = dict()

        # The Ack for a processed message, used to avoid re-processing a know
        # message
        self.msghash_acks = dict()

        # Maps the message hash to the event set when a message is acknowledge
        self.msghash_asyncresult = dict()

    def stop(self):
        for greenlet in self.address_greenlet.itervalues():
            greenlet.kill()

        for ack_result in self.msghash_asyncresult.itervalues():
            ack_result.set(False)

        self.address_queue = dict()
        self.address_greenlet = dict()
        self.msghash_acks = dict()
        self.msghash_asyncresult = dict()

    def _send_queued_messages(self, receiver_address):
        # Note: this task can be killed at any time

        queue = self.address_queue[receiver_address]
        host_port = self.discovery.get(receiver_address)

        while queue.wait():
            # avoid to reserialize the message and calculate it's hash
            message, messagedata, messagehash = queue.get()

            ack_result = self.msghash_asyncresult[messagehash]

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'SENDING %s -> %s msghash:%s %s',
                    pex(self.raiden.address),
                    pex(receiver_address),
                    pex(messagehash),
                    message,
                )

            self.transport.send(self.raiden, host_port, messagedata)

            retries_left = self.max_retries
            while ack_result.wait(timeout=self.try_interval) is None:  # ack_result can be False
                retries_left -= 1
                # TODO: fix the graph
                # if retries_left < 1:
                #     if log.isEnabledFor(logging.ERROR):
                #         log.error(
                #                'DEACTIVATED MSG resents %s %s',
                #                pex(receiver_address),
                #                message,
                #         )
                #         return

                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'SENDING %s -> %s msghash:%s %s',
                        pex(self.raiden.address),
                        pex(receiver_address),
                        pex(messagehash),
                        message,
                    )

                self.transport.send(self.raiden, host_port, messagedata)

    def _send(self, receiver_address, message, messagedata, messagehash):
        if receiver_address not in self.address_queue:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'new queue created for %s > %s',
                    pex(self.raiden.address),
                    pex(receiver_address),
                )

            self.address_queue[receiver_address] = NotifyingQueue()
            self.address_greenlet[receiver_address] = gevent.spawn(self._send_queued_messages, receiver_address)

        self.address_queue[receiver_address].put(
            (message, messagedata, messagehash),
        )

    def _send_ack(self, host_port, messagedata, messagehash):
        # ACK should not go into the queue
        self.transport.send(
            self.raiden,
            host_port,
            messagedata,
        )

    def send_async(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, Ack):
            raise ValueError('Do not use send for Ack messages or Errors')

        if len(message.encode()) > self.max_message_size:
            raise ValueError('message size exceeds the maximum {}'.format(self.max_message_size))

        messagedata = message.encode()
        messagehash = sha3(messagedata + receiver_address)
        ack_result = AsyncResult()
        self.msghash_asyncresult[messagehash] = ack_result

        self._send(receiver_address, message, messagedata, messagehash)

        return ack_result

    def send_and_wait(self, receiver_address, message, timeout=None):
        """Sends a message and wait for the response ack."""
        ack_result = self.send_async(receiver_address, message)
        return ack_result.wait(timeout=timeout)

    def send_ack(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if not isinstance(message, Ack):
            raise ValueError('Use send_Ack only for Ack messages or Erorrs')

        host_port = self.discovery.get(receiver_address)
        messagedata = message.encode()
        messagehash = sha3(messagedata)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'SENDING ACK %s > %s : [%s] [echo=%s] %s',
                pex(self.raiden.address),
                pex(receiver_address),
                pex(messagehash),
                pex(message.echo),
                message,
            )

        self.msghash_acks[message.echo] = (host_port, messagedata, messagehash)
        self._send_ack(*self.msghash_acks[message.echo])

    def receive(self, data):
        # ignore large packets
        if len(data) > self.max_message_size:
            log.error('receive packet larger than maximum size', length=len(data))
            return

        msghash = sha3(data + self.raiden.address)

        # check if we handled this message already, if so repeat Ack
        if msghash in self.msghash_acks:
            return self._send_ack(*self.msghash_acks[msghash])

        # We ignore the sending endpoint as this can not be known w/ UDP
        message = decode(data)

        if isinstance(message, Ack):
            ack_result = self.msghash_asyncresult[message.echo]

            if ack_result.ready():
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'DUPLICATED ACK RECEIVED node:%s [echo=%s]',
                        pex(self.raiden.address),
                        pex(message.echo)
                    )
            else:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'ACK RECEIVED node:%s [echo=%s]',
                        pex(self.raiden.address),
                        pex(message.echo)
                    )

                ack_result.set(True)

        elif message is not None:
            assert isinstance(message, Secret) or message.sender

            # this might exit with an exception
            self.raiden.on_message(message, msghash)

            # only send the Ack if the message was handled without exceptions
            ack = Ack(
                self.raiden.address,
                msghash,
            )

            self.send_ack(
                message.sender,
                ack,
            )

        else:  # payload was not a valid message and decoding failed
            if log.isEnabledFor(logging.ERROR):
                log.error(
                    'could not decode message %s',
                    pex(data),
                )
