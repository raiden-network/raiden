# -*- coding: utf-8 -*-
import logging
import time
from collections import namedtuple
from collections import defaultdict

import cachetools
import gevent
from gevent.queue import Queue
from gevent.event import AsyncResult
from gevent.lock import Semaphore
from ethereum import slogging

from raiden.exceptions import (
    InvalidAddress,
    InvalidLocksRoot,
    InvalidNonce,
    TransferWhenClosed,
    TransferUnwanted,
    UnknownAddress,
    UnknownTokenAddress,
)
from raiden.constants import (
    MINUTE_SEC,
)
from raiden.settings import (
    CACHE_TTL,
    PROTOCOL_RESEND_INTERVAL,
    PROTOCOL_RETRIES_BEFORE_BACKOFF,
    PROTOCOL_MAX_MESSAGE_SIZE,
)
from raiden.messages import decode, Ack, Ping, SignedMessage
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name

# - ack_result available for code that wants to block on message acknowledgment
# - receiver_address used to tie back the echohash to the receiver (mainly for
#   logging purposes)
WaitAck = namedtuple('WaitAck', ('ack_result', 'receiver_address'))
QueueItem = namedtuple('QueueItem', (
    'message',
    'ack_result',
    # precomputed caches
    'messagedata',
    'echohash',
))


class RaidenProtocol(object):
    """ Encode the message into a packet and send it.

    Each message received is stored by hash and if it is received twice the
    previous answer is resent.

    Repeat sending messages until an acknowledgment is received or the maximum
    number of retries is hit.
    """

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden

        self.retry_interval = PROTOCOL_RESEND_INTERVAL
        self.retries = PROTOCOL_RETRIES_BEFORE_BACKOFF
        self.max_message_size = PROTOCOL_MAX_MESSAGE_SIZE

        self.channel_queue_lock = Semaphore()

        # Messages are sent in-order for each partner
        self.channel_queue = dict()
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

        cache = cachetools.TTLCache(
            maxsize=50,
            ttl=CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.get_host_port = cache_wrapper(discovery.get)

    def stop_async(self):
        for greenlet in self.address_greenlet.itervalues():
            greenlet.kill()

        for waitack in self.echohash_asyncresult.itervalues():
            waitack.ack_result.set(False)

        self.channel_queue = dict()
        self.address_greenlet = dict()
        self.echohash_acks = dict()
        self.echohash_asyncresult = dict()

    def stop_and_wait(self):
        self.stop_async()
        gevent.wait(list(self.address_greenlet.itervalues()))

    def _send_queued_messages(self, receiver_address, queue):
        # Note: this task can be killed at any time

        while True:
            message, ack_result, messagedata, echohash = queue.peek(
                block=True,
                timeout=None,
            )

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'SENDING %s -> %s echohash:%s %s',
                    pex(self.raiden.address),
                    pex(receiver_address),
                    pex(echohash),
                    message,
                )

            host_port = self.get_host_port(receiver_address)
            self.transport.send(self.raiden, host_port, messagedata)

            retries_left = self.retries
            retry_interval = self.retry_interval

            while not ack_result.wait(timeout=retry_interval):
                if retries_left <= 0:
                    # TODO: The graph should be updated and the node should be
                    # marked as temporarily unreachable, so that
                    # get_best_routes don't try this route when looking for a
                    # path (Issue #447).
                    if log.isEnabledFor(logging.ERROR):
                        log.error(
                            'DEACTIVATED MSG resents %s %s',
                            pex(receiver_address),
                            message,
                        )

                    # Change the constant of one minute to a random health
                    # check (Issue #448)
                    retry_interval = min(
                        retry_interval * 2,
                        MINUTE_SEC,
                    )

                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'SENDING %s -> %s echohash:%s %s',
                        pex(self.raiden.address),
                        pex(receiver_address),
                        pex(echohash),
                        message,
                    )

                retries_left -= 1
                self.transport.send(self.raiden, host_port, messagedata)

            # Discard the message since it's acknowledgment
            queue.get()

    def _send(
            self,
            receiver_address,
            token_address,
            message,
            ack_result,
            messagedata,
            echohash):

        queue = self._get_task_queue(
            receiver_address,
            token_address,
        )

        queue_item = QueueItem(
            message,
            ack_result,
            messagedata,
            echohash,
        )

        # XXX: consider changing to a echohash only queue and storing the
        # message data in echohash_asyncresult
        queue.put(queue_item)

    def _send_ack(self, host_port, messagedata):
        # ACK must not go into the queue, otherwise nodes will deadlock waiting
        # for the confirmation
        self.transport.send(
            self.raiden,
            host_port,
            messagedata,
        )

    def _get_task_queue(self, receiver_address, token_address):
        # TODO: Change this to the channel address
        key = (
            receiver_address,
            token_address,
        )

        queue = None
        new_queue = False

        with self.channel_queue_lock:
            if key in self.channel_queue:
                queue = self.channel_queue[key]

            else:
                new_queue = True
                queue = Queue()
                self.last_received_time[receiver_address] = time.time()
                self.channel_queue[key] = queue
                self.address_greenlet[receiver_address] = gevent.spawn(
                    self._send_queued_messages,
                    receiver_address,
                    queue,
                )

        if new_queue and log.isEnabledFor(logging.DEBUG):
            log.debug(
                'new queue created for (%s, %s) > %s',
                pex(self.raiden.address),
                pex(token_address),
                pex(receiver_address),
            )

        return queue

    def send_async(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, Ack):
            raise ValueError('Do not use send for Ack messages or Errors')

        # Messages that are not unique per receiver can result in hash
        # colision, e.g. Secret messages. The hash collision has the undesired
        # effect of aborting message resubmission once /one/ of the nodes
        # replied with an Ack, adding the receiver address into the echohash to
        # avoid these collisions.
        messagedata = message.encode()
        echohash = sha3(messagedata + receiver_address)

        if len(messagedata) > self.max_message_size:
            raise ValueError(
                'message size exceeds the maximum {}'.format(self.max_message_size)
            )

        # All messages must be ordered, but only on a per channel basis, since
        # each channel correspond to a single token address this with the
        # partner address gives an unique queue name.
        token_address = getattr(message, 'token', '')

        # Ignore duplicated messages
        if echohash not in self.echohash_asyncresult:
            ack_result = AsyncResult()
            self.echohash_asyncresult[echohash] = WaitAck(ack_result, receiver_address)

            self._send(
                receiver_address,
                token_address,
                message,
                ack_result,
                messagedata,
                echohash,
            )
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

        if log.isEnabledFor(logging.INFO):
            log.info(
                'SENDING ACK %s > %s %s',
                pex(self.raiden.address),
                pex(receiver_address),
                message,
            )

        messagedata = message.encode()
        host_port = self.get_host_port(receiver_address)
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

        # Ping messages don't need to be ordered.
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
            waitack = self.echohash_asyncresult.get(message.echo)

            if waitack is None:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'ACK FOR UNKNOWN ECHO node:%s echohash:%s',
                        pex(self.raiden.address),
                        pex(message.echo)
                    )

            elif waitack.ack_result.ready():
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

            try:
                # this might exit with an exception
                self.raiden.on_message(message, echohash)

                # only send the Ack if the message was handled without exceptions
                ack = Ack(
                    self.raiden.address,
                    echohash,
                )

                try:
                    self.send_ack(
                        message.sender,
                        ack,
                    )
                except InvalidAddress:
                    log.debug("Couldn't send the ACK")

            except (UnknownAddress, InvalidNonce, TransferWhenClosed, TransferUnwanted) as e:
                log.DEV('maybe unwanted transfer', e=e)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(str(e))

            except (UnknownTokenAddress, InvalidLocksRoot) as e:
                if log.isEnabledFor(logging.WARN):
                    log.warn(str(e))

            except:  # pylint: disable=bare-except
                log.exception('unexpected exception raised.')

        # payload was not a valid message and decoding failed
        elif log.isEnabledFor(logging.ERROR):
            log.error(
                'could not decode message %s',
                pex(data),
            )
