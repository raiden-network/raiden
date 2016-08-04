# -*- coding: utf8 -*-
import gevent
from gevent.queue import Queue
from gevent.event import Event
from ethereum import slogging

from raiden.messages import decode, Ack, BaseError, Secret
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class NotifyingQueue(Event):
    """A queue that follows the wait protocol, as well as providing a stop event."""

    def __init__(self):
        super(NotifyingQueue, self).__init__()
        self._queue = Queue()
        self._stop_flag = False

    def put(self, item):
        """Add new item to the queue."""
        self._queue.put(item)
        self.set()

    def get(self, block=True, timeout=None):
        """Removes and returns an item from the queue."""
        value = self._queue.get(block, timeout)
        if self._queue.empty():
            self.clear()
        return value

    def stop(self):
        """Request a stop event."""
        self._stop_flag = True
        self.set()

    def has_stop(self):
        """True if a stop event was requested."""
        return self._stop_flag


class NotifyingReceive(Event):

    def __init__(self):
        super(NotifyingReceive, self).__init__()
        self._stop_flag = False

    def stop(self):
        """Request a stop event."""
        self._stop_flag = True
        self.set()

    def has_stop(self):
        """True if a stop event was requested."""
        return self._stop_flag


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
    short_delay = .01  # 10ms

    def __init__(self, transport, discovery, raiden):
        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden
        self.running = False
        self.sent_acks = dict()  # msghash: Ack

        self.start()

    def start(self):
        if not self.running:
            self.message_queue_by_address = dict()
            self.response_or_stop = dict()  # msg hash: NotifyingReceive
            self.status_by_message = dict()  # msg hash: status|None
            self.running = True

    def stop(self):
        if self.running:
            # XXX: maybe should wait for the greenlets termination...
            for message_queue in self.message_queue_by_address.itervalues():
                message_queue.stop()
            for receiver in self.response_or_stop.itervalues():
                receiver.stop()
            self.running = False

    def _send_queued_messages(self, receiver_address):

        message_queue = self.message_queue_by_address[receiver_address]
        while True:
            message_queue.wait()
            if message_queue.has_stop():
                return

            message = message_queue.get()
            data = message.encode()

            # XXX: is this cached?
            host_port = self.discovery.get(receiver_address)

            msghash = sha3(data)
            self.response_or_stop[msghash] = NotifyingReceive()

            log.info('SENDING {} > {} : [{}] {}'.format(
                pex(self.raiden.address),
                pex(receiver_address),
                pex(msghash),
                message,
            ))

            number_of_tries = 0
            while True:
                self.transport.send(self.raiden, host_port, data)
                number_of_tries += 1

                result = self.response_or_stop[msghash].wait(timeout=self.try_interval)
                if result:
                    has_stop = self.response_or_stop[msghash].has_stop()
                    del self.response_or_stop[msghash]

                    if has_stop:
                        return
                    else:
                        if msghash in self.status_by_message:
                            self.status_by_message[msghash] = True
                        break

                if number_of_tries >= self.max_tries:
                    del self.response_or_stop[msghash]
                    if msghash in self.status_by_message:
                        self.status_by_message[msghash] = False

                    # FIXME: there was no connectivity or other network error?
                    # for now just losing the packet but better error handler
                    # needs to be added.
                    log.error('DEACTIVATED MSG resents {} {}'.format(
                        pex(receiver_address),
                        message,
                    ))
                    break

    def send(self, receiver_address, message, with_status=False):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, (Ack, BaseError)):
            raise ValueError('Do not use send for Ack messages or Errors')

        if len(message.encode()) > self.max_message_size:
            raise ValueError('message size exceeds the maximum {}'.format(self.max_message_size))

        if with_status:
            data = message.encode()
            self.status_by_message[sha3(data)] = None

        if not receiver_address in self.message_queue_by_address:
            self.message_queue_by_address[receiver_address] = NotifyingQueue()
            gevent.spawn(self._send_queued_messages, receiver_address)

        self.message_queue_by_address[receiver_address].put(message)

    def send_and_wait(self, receiver_address, message):
        """Sends a message and wait for the response ack."""
        self.send(receiver_address, message, with_status=True)

        data = message.encode()
        msghash = sha3(data)
        while self.status_by_message[msghash] is None:
            gevent.sleep(self.short_delay)
        status = self.status_by_message[msghash]
        del self.status_by_message[msghash]
        return status

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
            if message.echo in self.response_or_stop:
                log.info('ACK RECEIVED {} [echo={}]'.format(
                    pex(self.raiden.address),
                    pex(message.echo)
                ))

                self.response_or_stop[message.echo].set()

                if message.echo in self.status_by_message:
                    self.status_by_message[message.echo] = True
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
