# -*- coding: utf-8 -*-
import logging
import time
from collections import namedtuple
from collections import defaultdict

import gevent
from gevent.queue import Queue
from gevent.event import AsyncResult, Event
from ethereum import slogging

from raiden.messages import decode, Ack, Ping, SignedMessage
from raiden.transfermanager import UnknownAddress, UnknownAssetAddress
from raiden.channel import InvalidLocksRoot, InvalidNonce
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name

# - ack_result available for code that wants to block on message acknowledgment
# - receiver_address used to tie back the echohash to the receiver (mainly for
#   logging purposes)
WaitAck = namedtuple('WaitAck', ('ack_result', 'receiver_address'))


class NotifyingQueue(Event):
    """ A queue that follows the wait protocol. """

    def __init__(self):
        super(NotifyingQueue, self).__init__()
        self._queue = Queue()

    def put(self, item):
        """ Add new item to the queue. """
        self._queue.put(item)
        self.set()

    def empty(self):
        return self._queue.empty()

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
    number of retries is hit.
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

        # TODO: remove old ACKs from the dict to free memory
        # The Ack for a processed message, used to avoid re-processing a known
        # message
        self.echohash_acks = dict()

        # Maps the echo hash `sha3(message + address)` to a WaitAck tuple
        self.echohash_asyncresult = dict()

        # Maps an address to timestamp representing last time any kind of messsage
        # was received for that address
        self.last_received_time = dict()

        self._ping_nonces = defaultdict(int)

    def stop_async(self):
        for greenlet in self.address_greenlet.itervalues():
            greenlet.kill()

        for waitack in self.echohash_asyncresult.itervalues():
            waitack.ack_result.set(False)

        self.address_queue = dict()
        self.address_greenlet = dict()
        self.echohash_acks = dict()
        self.echohash_asyncresult = dict()

    def stop_and_wait(self):
        self.stop_async()
        gevent.wait(self.address_greenlet.itervalues())

    def _send_queued_messages(self, receiver_address, queue_name):
        # Note: this task can be killed at any time

        queue = self.address_queue[(receiver_address, queue_name)]
        host_port = self.discovery.get(receiver_address)

        while queue.wait():
            # avoid reserializing the message and calculate it's hash
            message, messagedata, echohash = queue.get()

            waitack = self.echohash_asyncresult[echohash]

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'SENDING %s -> %s echohash:%s %s',
                    pex(self.raiden.address),
                    pex(receiver_address),
                    pex(echohash),
                    message,
                )

            self.transport.send(self.raiden, host_port, messagedata)

            retries_left = self.max_retries

            # ack_result can be False
            while waitack.ack_result.wait(timeout=self.try_interval) is None:
                retries_left -= 1

                # TODO: The graph should be updated and the node should be marked
                #       as temporarily unreachable, so that get_best_routes don't
                #       try this route when looking for a path.
                # XXX: How should it be marked available again?

                if retries_left < 1:
                    if log.isEnabledFor(logging.ERROR):
                        log.error(
                            'DEACTIVATED MSG resents %s %s',
                            pex(receiver_address),
                            message,
                        )
                    waitack.ack_result.set(False)
                    break

                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'SENDING %s -> %s echohash:%s %s',
                        pex(self.raiden.address),
                        pex(receiver_address),
                        pex(echohash),
                        message,
                    )

                self.transport.send(self.raiden, host_port, messagedata)

    def _send(self, receiver_address, queue_name, message, messagedata, echohash):
        key = (receiver_address, queue_name)
        if key not in self.address_queue:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'new queue created for (%s, %s) > %s',
                    pex(self.raiden.address),
                    pex(queue_name),
                    pex(receiver_address),
                )

            self.last_received_time[receiver_address] = time.time()
            self.address_queue[key] = NotifyingQueue()
            self.address_greenlet[receiver_address] = gevent.spawn(
                self._send_queued_messages,
                receiver_address,
                queue_name,
            )

        # XXX: consider changing to a echohash only queue and storing the
        # message data in echohash_asyncresult
        self.address_queue[key].put((message, messagedata, echohash))

    def _send_ack(self, host_port, messagedata):
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

        # Adding the receiver address into the echohash to avoid collisions
        # among different receivers.
        # (Messages that are not unique per receiver
        # can result in hash colision, eg. Secret message sent to more than one
        # node, this hash collision has the undesired effect of aborting
        # message resubmission once a single node replied with an Ack)
        echohash = sha3(messagedata + receiver_address)

        # Don't add the same message twice into the queue
        if echohash not in self.echohash_asyncresult:
            ack_result = AsyncResult()
            self.echohash_asyncresult[echohash] = WaitAck(ack_result, receiver_address)

            # state changes are local to each channel/asset
            queue_name = getattr(message, 'asset', '')

            self._send(receiver_address, queue_name, message, messagedata, echohash)
        else:
            waitack = self.echohash_asyncresult[echohash]
            ack_result = waitack.ack_result

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

        if log.isEnabledFor(logging.INFO):
            log.info(
                'SENDING ACK %s > %s %s',
                pex(self.raiden.address),
                pex(receiver_address),
                message,
            )

        self.echohash_acks[message.echo] = (host_port, messagedata)
        self._send_ack(*self.echohash_acks[message.echo])

    def send_ping(self, receiver_address):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        nonce = self._ping_nonces[receiver_address]
        self._ping_nonces[receiver_address] += 1

        message = Ping(nonce)
        self.raiden.sign(message)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'SENDING PING %s > %s',
                pex(self.raiden.address),
                pex(receiver_address)
            )

        message_data = message.encode()
        echohash = sha3(message_data + receiver_address)
        async_result = AsyncResult()
        if echohash not in self.echohash_asyncresult:
            self.echohash_asyncresult[echohash] = WaitAck(async_result, receiver_address)
        # Just like ACK, a PING message is sent directly. No need for queuing
        self.transport.send(
            self.raiden,
            self.discovery.get(receiver_address),
            message_data
        )
        return async_result

    def receive(self, data):
        # ignore large packets
        if len(data) > self.max_message_size:
            log.error('receive packet larger than maximum size', length=len(data))
            return

        echohash = sha3(data + self.raiden.address)

        # check if we handled this message already, if so repeat Ack
        if echohash in self.echohash_acks:
            return self._send_ack(*self.echohash_acks[echohash])

        # We ignore the sending endpoint as this can not be known w/ UDP
        message = decode(data)
        # note down the time we got a message from the address
        self.last_received_time[message.sender] = time.time()

        if isinstance(message, Ack):
            waitack = self.echohash_asyncresult[message.echo]

            if waitack.ack_result.ready():
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'DUPLICATED ACK RECEIVED node:%s receiver:%s echohash:%s',
                        pex(self.raiden.address),
                        pex(waitack.receiver_address),
                        pex(message.echo),
                    )
            else:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'ACK RECEIVED node:%s receiver:%s echohash:%s',
                        pex(self.raiden.address),
                        pex(waitack.receiver_address),
                        pex(message.echo)
                    )

                waitack.ack_result.set(True)

        elif message is not None:
            # all messages require an Ack, to send it back an address is required
            assert isinstance(message, SignedMessage)

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'MESSAGE RECEIVED node:%s echohash:%s %s',
                    pex(self.raiden.address),
                    pex(echohash),
                    message,
                )

            # this might exit with an exception
            try:
                self.raiden.on_message(message, echohash)
            except (UnknownAddress, InvalidNonce):
                # Do not send ACK for these cases
                return
            except (UnknownAssetAddress, InvalidLocksRoot) as e:
                if log.isEnabledFor(logging.WARN):
                    log.warn(str(e))
                return

            # only send the Ack if the message was handled without exceptions
            ack = Ack(
                self.raiden.address,
                echohash,
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
