# -*- coding: utf-8 -*-
import logging
import random
from collections import (
    namedtuple,
    defaultdict,
)
from itertools import repeat

import cachetools
import gevent
from gevent.queue import Queue
from gevent.event import (
    _AbstractLinkable,
    AsyncResult,
    Event,
)
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
    UDP_MAX_MESSAGE_SIZE,
)
from raiden.settings import (
    CACHE_TTL,
)
from raiden.messages import decode, Ack, Ping, SignedMessage
from raiden.utils import isaddress, sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name

# - async_result available for code that wants to block on message acknowledgment
# - receiver_address used to tie back the echohash to the receiver (mainly for
#   logging purposes)
WaitAck = namedtuple('WaitAck', (
    'async_result',
    'receiver_address',
))
HealthEvents = namedtuple('HealthEvents', (
    'event_healthy',
    'event_unhealthy',
))

NODE_NETWORK_UNKNOWN = 'unknown'
NODE_NETWORK_UNREACHABLE = 'unreachable'
NODE_NETWORK_REACHABLE = 'reachable'

# GOALS:
# - Each netting channel must have the messages processed in-order, the
# protocol must detect unacknowledged messages and retry them.
# - A queue must not stall because of synchronization problems in other queues.
# - Assuming a queue can stall, the unhealthiness of a node must not be
# inferred from the lack of acknowledgement from a single queue, but healthiness
# may be safely inferred from it.
# - The state of the node must be synchronized among all tasks that are
# handling messages.


def event_first_of(*events):
    """ Waits until one of `events` is set.

    The event returned is /not/ cleared with any of the `events`, this value
    must not be reused if the clearing behavior is used.
    """
    first_finished = Event()

    if not all(isinstance(e, _AbstractLinkable) for e in events):
        raise ValueError('all events must be linkable')

    for event in events:
        event.rawlink(lambda _: first_finished.set())

    return first_finished


def timeout_exponential_backoff(retries, timeout, maximum):
    """ Timeouts generator with an exponential backoff strategy.

    Timeouts start spaced by `timeout`, after `retries` exponentially increase
    the retry delays until `maximum`, then maximum is returned indefinitely.
    """
    yield timeout

    tries = 1
    while tries < retries:
        tries += 1
        yield timeout

    while timeout < maximum:
        timeout = min(timeout * 2, maximum)
        yield timeout

    while True:
        yield maximum


def retry(protocol, data, receiver_address, event_stop, timeout_backoff):
    """ Send data until it's acknowledged.

    Exits when the first of the following happen:

    - The packet is acknowledged.
    - Event_stop is set.
    - The iterator timeout_backoff runs out of values.

    Returns:
        bool: True if the message was acknowledged, False otherwise.
    """

    async_result = protocol.send_raw_with_result(
        data,
        receiver_address,
    )

    event_quit = event_first_of(
        async_result,
        event_stop,
    )

    for timeout in timeout_backoff:

        if event_quit.wait(timeout=timeout) is True:
            break

        protocol.send_raw_with_result(
            data,
            receiver_address,
        )

    return async_result.ready()


def wait_recovery(event_stop, event_healthy):
    event_first_of(
        event_stop,
        event_healthy,
    ).wait()

    if event_stop.is_set():
        return

    # There may be multiple threads waiting, do not restart them all at
    # once to avoid message flood.
    gevent.sleep(random.random())


def retry_with_recovery(
        protocol,
        data,
        receiver_address,
        event_stop,
        event_healthy,
        event_unhealthy,
        backoff):
    """ Send data while the node is healthy until it's acknowledged.

    Note:
        backoff must be an infinite iterator, otherwise this task will
        become a hot loop.
    """

    # The underlying unhealthy will be cleared, care must be taken to properly
    # clear stop_or_unhealthy too.
    stop_or_unhealthy = event_first_of(
        event_stop,
        event_unhealthy,
    )

    acknowledged = False
    while not event_stop.is_set() and not acknowledged:

        # Packets must not be sent to an unhealthy node, nor should the task
        # wait for it to become available if the message has been acknowledged.
        if event_unhealthy.is_set():
            wait_recovery(
                event_stop,
                event_healthy,
            )

            # Assume wait_recovery returned because unhealthy was cleared and
            # continue execution, this is safe to do because event_stop is
            # checked below.
            stop_or_unhealthy.clear()

            if event_stop.is_set():
                return

        acknowledged = retry(
            protocol,
            data,
            receiver_address,

            # retry will stop when this event is set, allowing this task to
            # wait for recovery when the node becomes unhealthy or to quit if
            # the stop event is set.
            stop_or_unhealthy,

            # Intentionally reusing backoff to restart from the last
            # timeout/number of iterations.
            backoff,
        )

    return acknowledged


def single_queue_send(
        protocol,
        receiver_address,
        queue,
        event_stop,
        event_healthy,
        event_unhealthy,
        message_retries,
        message_retry_timeout,
        message_retry_max_timeout):

    """ Handles a single message queue for `receiver_address`.

    Notes:
    - This task must be the only consumer of queue.
    - This task can be killed at any time, but the intended usage is to stop it
      with the event_stop.
    - If there are many queues for the same receiver_address, it is the
      caller's responsibility to not start them together to avoid congestion.
    """

    # A NotifyingQueue is required to implement cancelability, otherwise the
    # task cannot be stoped while the greenlet waits for an element to be
    # inserted in the queue.
    if not isinstance(queue, NotifyingQueue):
        raise ValueError('queue must be a NotifyingQueue.')

    # Reusing the event, clear must be carefully done
    data_or_stop = event_first_of(
        queue,
        event_stop,
    )

    while True:
        data_or_stop.wait()

        if event_stop.is_set():
            return

        # The queue is not empty at this point, so this won't raise Empty.
        # This task being the only consumer is a requirement.
        data = queue.peek(block=False)

        backoff = timeout_exponential_backoff(
            message_retries,
            message_retry_timeout,
            message_retry_max_timeout,
        )

        acknowledged = retry_with_recovery(
            protocol,
            data,
            receiver_address,
            event_stop,
            event_healthy,
            event_unhealthy,
            backoff,
        )

        if acknowledged:
            queue.get()

            # Checking the length of the queue does not trigger a
            # context-switch, so it's safe to assume the length of the queue
            # won't change under our feet and when a new item will be added the
            # event will be set again.
            if not queue:
                data_or_stop.clear()

                if event_stop.is_set():
                    return


def healthcheck(
        protocol,
        receiver_address,
        event_stop,
        event_healthy,
        event_unhealthy,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        nat_invitation_timeout,
        ping_nonce=0):

    """ Sends a periodical Ping to `receiver_address` to check its health. """

    # The state of the node is unknown, the events are set to allow the tasks
    # to do work.
    protocol.set_node_network_state(
        receiver_address,
        NODE_NETWORK_UNKNOWN,
    )

    # Always call `clear` before `set`, since only `set` does context-switches
    # it's easier to reason about tasks that are waiting on both events.
    event_unhealthy.clear()
    event_healthy.set()

    # Don't wait to send the first Ping
    sleep = 0

    while not event_stop.wait(sleep) is True:
        sleep = nat_keepalive_timeout

        data = protocol.get_ping(
            ping_nonce,
        )
        ping_nonce += 1

        # Send Ping a few times before setting the node as unreachable
        acknowledged = retry(
            protocol,
            data,
            receiver_address,
            event_stop,
            [nat_keepalive_timeout] * nat_keepalive_retries,
        )

        if event_stop.is_set():
            return

        if not acknowledged:
            # The node is not healthy, clear the event to stop all queue
            # tasks
            protocol.set_node_network_state(
                receiver_address,
                NODE_NETWORK_UNREACHABLE,
            )
            event_healthy.clear()
            event_unhealthy.set()

            # Retry until recovery, used for:
            # - Checking node status.
            # - Nat punching.
            acknowledged = retry(
                protocol,
                data,
                receiver_address,
                event_stop,
                repeat(nat_invitation_timeout),
            )

        if acknowledged:
            event_unhealthy.clear()
            event_healthy.set()
            protocol.set_node_network_state(
                receiver_address,
                NODE_NETWORK_REACHABLE,
            )


class NotifyingQueue(Event):
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

    def peek(self, block=True, timeout=None):
        return self._queue.peek(block, timeout)

    def __len__(self):
        return len(self._queue)


class RaidenProtocol(object):
    """ Encode the message into a packet and send it.

    Each message received is stored by hash and if it is received twice the
    previous answer is resent.

    Repeat sending messages until an acknowledgment is received or the maximum
    number of retries is hit.
    """

    def __init__(
            self,
            transport,
            discovery,
            raiden,
            retry_interval,
            retries_before_backoff,
            nat_keepalive_retries,
            nat_keepalive_timeout,
            nat_invitation_timeout):

        self.transport = transport
        self.discovery = discovery
        self.raiden = raiden

        self.retry_interval = retry_interval
        self.retries_before_backoff = retries_before_backoff

        self.nat_keepalive_retries = nat_keepalive_retries
        self.nat_keepalive_timeout = nat_keepalive_timeout
        self.nat_invitation_timeout = nat_invitation_timeout

        self.event_stop = Event()

        self.channel_queue = dict()  # TODO: Change keys to the channel address
        self.greenlets = list()
        self.addresses_events = dict()
        self.nodeaddresses_networkstatuses = defaultdict(lambda: NODE_NETWORK_UNKNOWN)

        # TODO: remove old ACKs from the dict to free memory
        # The Ack for a processed message, used to avoid re-processing a known
        # message
        self.echohash_acks = dict()

        # Maps the echo hash `sha3(message + address)` to a WaitAck tuple
        self.echohash_asyncresult = dict()

        cache = cachetools.TTLCache(
            maxsize=50,
            ttl=CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.get_host_port = cache_wrapper(discovery.get)

    def stop_and_wait(self):
        self.event_stop.set()

        for waitack in self.echohash_asyncresult.itervalues():
            waitack.async_result.set(False)

        gevent.wait(self.greenlets)

        # The transport must be stopped after the protocol. The protocol can be
        # running multiple threads of execution and it expects the protocol to
        # be available.
        self.transport.stop()

    def get_health_events(self, receiver_address):
        """ Starts a healthcheck taks for `receiver_address` and returns a
        HealthEvents with locks to react on its current state.
        """
        if receiver_address not in self.addresses_events:
            self.start_health_check(
                receiver_address,
                ping_nonce=0,
            )

        return self.addresses_events[receiver_address]

    def start_health_check(self, receiver_address, ping_nonce):
        """ Starts a task for healthchecking `receiver_address` if there is not
        one yet.
        """
        if receiver_address not in self.addresses_events:
            events = HealthEvents(
                event_healthy=Event(),
                event_unhealthy=Event(),
            )

            self.addresses_events[receiver_address] = events

            self.greenlets.append(gevent.spawn(
                healthcheck,
                self,
                receiver_address,
                self.event_stop,
                events.event_healthy,
                events.event_unhealthy,
                self.nat_keepalive_retries,
                self.nat_keepalive_timeout,
                self.nat_invitation_timeout,
                ping_nonce,
            ))

    def get_channel_queue(self, receiver_address, token_address):
        key = (
            receiver_address,
            token_address,
        )

        if key in self.channel_queue:
            return self.channel_queue[key]

        queue = NotifyingQueue()
        self.channel_queue[key] = queue

        events = self.get_health_events(receiver_address)

        self.greenlets.append(gevent.spawn(
            single_queue_send,
            self,
            receiver_address,
            queue,
            self.event_stop,
            events.event_healthy,
            events.event_unhealthy,
            self.retries_before_backoff,
            self.retry_interval,
            self.retry_interval * 10,
        ))

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'new queue created for (%s, %s) > %s',
                pex(self.raiden.address),
                pex(token_address),
                pex(receiver_address),
            )

        return queue

    def _send_ack(self, host_port, messagedata):
        # ACK must not go into the queue, otherwise nodes will deadlock waiting
        # for the confirmation
        self.transport.send(
            self.raiden,
            host_port,
            messagedata,
        )

    def send_async(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, Ack):
            raise ValueError('Do not use send for Ack messages')

        # Messages that are not unique per receiver can result in hash
        # collision, e.g. Secret messages. The hash collision has the undesired
        # effect of aborting message resubmission once /one/ of the nodes
        # replied with an Ack, adding the receiver address into the echohash to
        # avoid these collisions.
        messagedata = message.encode()
        echohash = sha3(messagedata + receiver_address)

        if len(messagedata) > UDP_MAX_MESSAGE_SIZE:
            raise ValueError(
                'message size exceeds the maximum {}'.format(UDP_MAX_MESSAGE_SIZE)
            )

        # All messages must be ordered, but only on a per channel basis.
        token_address = getattr(message, 'token', '')

        # Ignore duplicated messages
        if echohash not in self.echohash_asyncresult:
            async_result = AsyncResult()
            self.echohash_asyncresult[echohash] = WaitAck(
                async_result,
                receiver_address,
            )

            queue = self.get_channel_queue(
                receiver_address,
                token_address,
            )

            queue.put(messagedata)
        else:
            waitack = self.echohash_asyncresult[echohash]
            async_result = waitack.async_result

        return async_result

    def send_and_wait(self, receiver_address, message, timeout=None):
        """Sends a message and wait for the response ack."""
        async_result = self.send_async(receiver_address, message)
        return async_result.wait(timeout=timeout)

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

    def get_ping(self, nonce):
        message = Ping(nonce)
        self.raiden.sign(message)
        message_data = message.encode()

        return message_data

    def send_raw_with_result(self, data, receiver_address):
        """ Sends data to receiver_address and returns an AsyncResult that will
        be set once the message is acknowledged.

        Always returns same AsyncResult instance for equal input.
        """
        host_port = self.get_host_port(receiver_address)
        echohash = sha3(data + receiver_address)

        if echohash not in self.echohash_asyncresult:
            async_result = AsyncResult()
            self.echohash_asyncresult[echohash] = WaitAck(
                async_result,
                receiver_address,
            )
        else:
            async_result = self.echohash_asyncresult[echohash].async_result

        if not async_result.ready():
            self.transport.send(
                self.raiden,
                host_port,
                data,
            )

        return async_result

    def set_node_network_state(self, node_address, node_state):
        self.nodeaddresses_networkstatuses[node_address] = node_state

    def receive(self, data):
        if len(data) > UDP_MAX_MESSAGE_SIZE:
            log.error('receive packet larger than maximum size', length=len(data))
            return

        echohash = sha3(data + self.raiden.address)

        # check if we handled this message already, if so repeat Ack
        if echohash in self.echohash_acks:
            return self._send_ack(*self.echohash_acks[echohash])

        # We ignore the sending endpoint as this can not be known w/ UDP
        message = decode(data)

        if isinstance(message, Ack):
            waitack = self.echohash_asyncresult.get(message.echo)

            if waitack is None:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'ACK FOR UNKNOWN ECHO node:%s echohash:%s',
                        pex(self.raiden.address),
                        pex(message.echo)
                    )

            elif waitack.async_result.ready():
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

                waitack.async_result.set(True)

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
