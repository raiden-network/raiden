# -*- coding: utf-8 -*-
import logging
import random
import socket
from binascii import hexlify
from collections import namedtuple
from itertools import repeat

import cachetools
import gevent
from gevent.event import (
    _AbstractLinkable,
    AsyncResult,
    Event,
)
from gevent.server import DatagramServer
from ethereum import slogging

from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    RaidenShuttingDown,
)
from raiden.constants import UDP_MAX_MESSAGE_SIZE
from raiden.messages import decode, Delivered, Ping, Pong
from raiden.settings import CACHE_TTL
from raiden.utils import isaddress, pex, typing
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.udp_message_handler import on_udp_message
from raiden.transfer import views
from raiden.transfer.state_change import ReceiveDelivered
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
    NODE_NETWORK_UNREACHABLE,
)
from raiden.transfer.state_change import ActionChangeNodeNetworkState

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
healthcheck_log = slogging.get_logger(__name__ + '.healthcheck')
ping_log = slogging.get_logger(__name__ + '.ping')

# - async_result available for code that wants to block on message acknowledgment
# - recipient used to tie back the message_id to the receiver (mainly for
#   logging purposes)
SentMessageState = namedtuple('SentMessageState', (
    'async_result',
    'recipient',
))
HealthEvents = namedtuple('HealthEvents', (
    'event_healthy',
    'event_unhealthy',
))

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


def timeout_two_stage(retries, timeout1, timeout2):
    """ Timeouts generator with a two stage strategy

    Timeouts start spaced by `timeout1`, after `retries` increase
    to `timeout2` which is repeated indefinitely.
    """
    for _ in range(retries):
        yield timeout1
    while True:
        yield timeout2


def retry(protocol, messagedata, message_id, recipient, event_stop, timeout_backoff):
    """ Send messagedata until it's acknowledged.

    Exit when:

    - The message is delivered.
    - Event_stop is set.
    - The iterator timeout_backoff runs out.

    Returns:
        bool: True if the message was acknowledged, False otherwise.
    """

    async_result = protocol.maybe_sendraw_with_result(
        recipient,
        messagedata,
        message_id,
    )

    event_quit = event_first_of(
        async_result,
        event_stop,
    )

    for timeout in timeout_backoff:

        if event_quit.wait(timeout=timeout) is True:
            break

        protocol.maybe_sendraw_with_result(
            recipient,
            messagedata,
            message_id,
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
        messagedata,
        message_id,
        recipient,
        event_stop,
        event_healthy,
        event_unhealthy,
        backoff,
):
    """ Send messagedata while the node is healthy until it's acknowledged.

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
                return acknowledged

        acknowledged = retry(
            protocol,
            messagedata,
            message_id,
            recipient,

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
        recipient,
        queue,
        event_stop,
        event_healthy,
        event_unhealthy,
        message_retries,
        message_retry_timeout,
        message_retry_max_timeout):

    """ Handles a single message queue for `recipient`.

    Notes:
    - This task must be the only consumer of queue.
    - This task can be killed at any time, but the intended usage is to stop it
      with the event_stop.
    - If there are many queues for the same recipient, it is the
      caller's responsibility to not start them together to avoid congestion.
    - This task assumes the endpoint is never cleared after it's first known.
      If this assumption changes the code must be updated to handle unknown
      addresses.
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

    # Wait for the endpoint registration or to quit
    event_first_of(
        event_healthy,
        event_stop,
    ).wait()

    while True:
        data_or_stop.wait()

        if event_stop.is_set():
            return

        # The queue is not empty at this point, so this won't raise Empty.
        # This task being the only consumer is a requirement.
        (messagedata, message_id) = queue.peek(block=False)

        backoff = timeout_exponential_backoff(
            message_retries,
            message_retry_timeout,
            message_retry_max_timeout,
        )

        try:
            acknowledged = retry_with_recovery(
                protocol,
                messagedata,
                message_id,
                recipient,
                event_stop,
                event_healthy,
                event_unhealthy,
                backoff,
            )
        except RaidenShuttingDown:  # For a clean shutdown process
            return

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
        recipient,
        event_stop,
        event_healthy,
        event_unhealthy,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        nat_invitation_timeout,
        ping_nonce):

    """ Sends a periodical Ping to `recipient` to check its health. """
    # pylint: disable=too-many-branches

    if log.isEnabledFor(logging.DEBUG):
        log.debug(
            'starting healthcheck for',
            node=pex(protocol.raiden.address),
            to=pex(recipient),
        )

    # The state of the node is unknown, the events are set to allow the tasks
    # to do work.
    last_state = NODE_NETWORK_UNKNOWN
    protocol.set_node_network_state(
        recipient,
        last_state,
    )

    # Always call `clear` before `set`, since only `set` does context-switches
    # it's easier to reason about tasks that are waiting on both events.

    # Wait for the end-point registration or for the node to quit
    try:
        protocol.get_host_port(recipient)
    except UnknownAddress:
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'waiting for endpoint registration',
                node=pex(protocol.raiden.address),
                to=pex(recipient),
            )

        event_healthy.clear()
        event_unhealthy.set()

        backoff = timeout_exponential_backoff(
            nat_keepalive_retries,
            nat_keepalive_timeout,
            nat_invitation_timeout,
        )
        sleep = next(backoff)

        while not event_stop.wait(sleep):
            try:
                protocol.get_host_port(recipient)
            except UnknownAddress:
                sleep = next(backoff)
            else:
                break

    # Don't wait to send the first Ping and to start sending messages if the
    # endpoint is known
    sleep = 0
    event_unhealthy.clear()
    event_healthy.set()

    while not event_stop.wait(sleep):
        sleep = nat_keepalive_timeout

        ping_nonce['nonce'] += 1
        messagedata = protocol.get_ping(ping_nonce['nonce'])
        message_id = ('ping', ping_nonce['nonce'], recipient)

        # Send Ping a few times before setting the node as unreachable
        try:
            acknowledged = retry(
                protocol,
                messagedata,
                message_id,
                recipient,
                event_stop,
                [nat_keepalive_timeout] * nat_keepalive_retries,
            )
        except RaidenShuttingDown:  # For a clean shutdown process
            return

        if event_stop.is_set():
            return

        if not acknowledged:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'node is unresponsive',
                    node=pex(protocol.raiden.address),
                    to=pex(recipient),
                    current_state=last_state,
                    new_state=NODE_NETWORK_UNREACHABLE,
                    retries=nat_keepalive_retries,
                    timeout=nat_keepalive_timeout,
                )

            # The node is not healthy, clear the event to stop all queue
            # tasks
            last_state = NODE_NETWORK_UNREACHABLE
            protocol.set_node_network_state(
                recipient,
                last_state,
            )
            event_healthy.clear()
            event_unhealthy.set()

            # Retry until recovery, used for:
            # - Checking node status.
            # - Nat punching.
            try:
                acknowledged = retry(
                    protocol,
                    messagedata,
                    message_id,
                    recipient,
                    event_stop,
                    repeat(nat_invitation_timeout),
                )
            except RaidenShuttingDown:  # For a clean shutdown process
                return

        if acknowledged:
            if log.isEnabledFor(logging.DEBUG):
                current_state = views.get_node_network_status(
                    views.state_from_raiden(protocol.raiden),
                    recipient,
                )
                log.debug(
                    'node answered',
                    node=pex(protocol.raiden.address),
                    to=pex(recipient),
                    current_state=current_state,
                    new_state=NODE_NETWORK_REACHABLE,
                )

            if last_state != NODE_NETWORK_REACHABLE:
                last_state = NODE_NETWORK_REACHABLE
                protocol.set_node_network_state(
                    recipient,
                    last_state,
                )
                event_unhealthy.clear()
                event_healthy.set()


class UDPTransport:
    def __init__(self, discovery, udpsocket, throttle_policy, config):
        # these values are initialized by the start method
        self.queueids_to_queues: typing.Dict
        self.raiden: 'RaidenService'

        self.discovery = discovery
        self.config = config

        self.retry_interval = config['retry_interval']
        self.retries_before_backoff = config['retries_before_backoff']
        self.nat_keepalive_retries = config['nat_keepalive_retries']
        self.nat_keepalive_timeout = config['nat_keepalive_timeout']
        self.nat_invitation_timeout = config['nat_invitation_timeout']

        self.event_stop = Event()

        self.greenlets = list()
        self.addresses_events = dict()

        # Maps the message_id to a SentMessageState
        self.messageids_to_asyncresults = dict()

        # Maps the addresses to a dict with the latest nonce (using a dict
        # because python integers are immutable)
        self.nodeaddresses_to_nonces = dict()

        cache = cachetools.TTLCache(
            maxsize=50,
            ttl=CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.get_host_port = cache_wrapper(discovery.get)

        self.throttle_policy = throttle_policy
        self.server = DatagramServer(udpsocket, handle=self._receive)

    def start(self, raiden, queueids_to_queues):
        self.raiden = raiden
        self.queueids_to_queues = dict()

        # server.stop() clears the handle. Since this may be a restart the
        # handle must always be set
        self.server.set_handle(self._receive)

        for (recipient, queue_name), queue in queueids_to_queues.items():
            queue_copy = list(queue)
            self.init_queue_for(recipient, queue_name, queue_copy)

        self.server.start()

    def stop_and_wait(self):
        # Stop handling incoming packets, but don't close the socket. The
        # socket can only be safely closed after all outgoing tasks are stopped
        self.server.stop_accepting()

        # Stop processing the outgoing queues
        self.event_stop.set()
        gevent.wait(self.greenlets)

        # All outgoing tasks are stopped. Now it's safe to close the socket. At
        # this point there might be some incoming message being processed,
        # keeping the socket open is not useful for these.
        self.server.stop()

        # Calling `.close()` on a gevent socket doesn't actually close the underlying os socket
        # so we do that ourselves here.
        # See: https://github.com/gevent/gevent/blob/master/src/gevent/_socket2.py#L208
        # and: https://groups.google.com/forum/#!msg/gevent/Ro8lRra3nH0/ZENgEXrr6M0J
        try:
            self.server._socket.close()  # pylint: disable=protected-access
        except socket.error:
            pass

        # Set all the pending results to False
        for async_result in self.messageids_to_asyncresults.values():
            async_result.set(False)

    def get_health_events(self, recipient):
        """ Starts a healthcheck taks for `recipient` and returns a
        HealthEvents with locks to react on its current state.
        """
        if recipient not in self.addresses_events:
            self.start_health_check(recipient)

        return self.addresses_events[recipient]

    def start_health_check(self, recipient):
        """ Starts a task for healthchecking `recipient` if there is not
        one yet.
        """
        if recipient not in self.addresses_events:
            ping_nonce = self.nodeaddresses_to_nonces.setdefault(
                recipient,
                {'nonce': 0},  # HACK: Allows the task to mutate the object
            )

            events = HealthEvents(
                event_healthy=Event(),
                event_unhealthy=Event(),
            )

            self.addresses_events[recipient] = events

            self.greenlets.append(gevent.spawn(
                healthcheck,
                self,
                recipient,
                self.event_stop,
                events.event_healthy,
                events.event_unhealthy,
                self.nat_keepalive_retries,
                self.nat_keepalive_timeout,
                self.nat_invitation_timeout,
                ping_nonce,
            ))

    def init_queue_for(self, recipient, queue_name, items):
        """ Create the queue identified by the pair `(recipient, queue_name)`
        and initialize it with `items`.
        """
        queueid = (recipient, queue_name)
        queue = self.queueids_to_queues.get(queueid)
        assert queue is None

        queue = NotifyingQueue(items=items)
        self.queueids_to_queues[queueid] = queue

        events = self.get_health_events(recipient)

        self.greenlets.append(gevent.spawn(
            single_queue_send,
            self,
            recipient,
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
                'new queue created for',
                node=pex(self.raiden.address),
                token=pex(queue_name),
                to=pex(recipient),
            )

        return queue

    def get_queue_for(self, recipient, queue_name):
        """ Return the queue identified by the pair `(recipient, queue_name)`.

        If the queue doesn't exist it will be instantiated.
        """
        queueid = (recipient, queue_name)
        queue = self.queueids_to_queues.get(queueid)

        if queue is None:
            items = ()
            queue = self.init_queue_for(recipient, queue_name, items)

        return queue

    def send_async(self, queue_name, recipient, message):
        """ Send a new ordered message to recipient.

        Messages that use the same `queue_name` are ordered.
        """

        if not isaddress(recipient):
            raise ValueError('Invalid address {}'.format(pex(recipient)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError('Do not use send for {} messages'.format(message.__class__.__name__))

        messagedata = message.encode()
        if len(messagedata) > UDP_MAX_MESSAGE_SIZE:
            raise ValueError(
                'message size exceeds the maximum {}'.format(UDP_MAX_MESSAGE_SIZE)
            )

        # message identifiers must be unique
        message_id = message.message_identifier

        # ignore duplicates
        if message_id not in self.messageids_to_asyncresults:
            self.messageids_to_asyncresults[message_id] = AsyncResult()

            queue = self.get_queue_for(recipient, queue_name)
            queue.put((messagedata, message_id))

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MESSAGE QUEUED',
                    node=pex(self.raiden.address),
                    queue_name=queue_name,
                    to=pex(recipient),
                    message=message,
                )

    def maybe_send(self, recipient, message):
        """ Send message to recipient if the transport is running. """

        if not isaddress(recipient):
            raise InvalidAddress('Invalid address {}'.format(pex(recipient)))

        messagedata = message.encode()
        host_port = self.get_host_port(recipient)

        self.maybe_sendraw(host_port, messagedata)

    def maybe_sendraw_with_result(self, recipient, messagedata, message_id):
        """ Send message to recipient if the transport is running.

        Returns:
            An AsyncResult that will be set once the message is delivered. As
            long as the message has not been acknowledged with a Delivered
            message the function will return the same AsyncResult.
        """
        async_result = self.messageids_to_asyncresults.get(message_id)
        if async_result is None:
            async_result = AsyncResult()
            self.messageids_to_asyncresults[message_id] = async_result

        host_port = self.get_host_port(recipient)
        self.maybe_sendraw(host_port, messagedata)

        return async_result

    def maybe_sendraw(self, host_port, messagedata):
        """ Send message to recipient if the transport is running. """

        # Don't sleep if timeout is zero, otherwise a context-switch is done
        # and the message is delayed, increasing it's latency
        sleep_timeout = self.throttle_policy.consume(1)
        if sleep_timeout:
            gevent.sleep(sleep_timeout)

        # Check the udp socket is still available before trying to send the
        # message. There must be *no context-switches after this test*.
        if hasattr(self.server, 'socket'):
            self.server.sendto(
                messagedata,
                host_port,
            )

    def _receive(self, data, host_port):  # pylint: disable=unused-argument
        try:
            self.receive(data)
        except RaidenShuttingDown:  # For a clean shutdown
            return

    def receive(self, messagedata):
        """ Handle an UDP packet. """
        # pylint: disable=unidiomatic-typecheck

        if len(messagedata) > UDP_MAX_MESSAGE_SIZE:
            log.error(
                'INVALID MESSAGE: Packet larger than maximum size',
                node=pex(self.raiden.address),
                message=hexlify(messagedata),
                length=len(messagedata),
            )
            return

        message = decode(messagedata)

        if type(message) == Pong:
            self.receive_pong(message)
        elif type(message) == Ping:
            self.receive_ping(message)
        elif type(message) == Delivered:
            self.receive_delivered(message)
        elif message is not None:
            self.receive_message(message)
        elif log.isEnabledFor(logging.ERROR):
            log.error(
                'INVALID MESSAGE: Unknown cmdid',
                node=pex(self.raiden.address),
                message=hexlify(messagedata),
            )

    def receive_message(self, message):
        """ Handle a Raiden protocol message.

        The protocol requires durability of the messages. The UDP transport
        relies on the node's WAL for durability. The message will be converted
        to a state change, saved to the WAL, and *processed* before the
        durability is confirmed, which is a stronger property than what is
        required of any transport.
        """
        # pylint: disable=unidiomatic-typecheck

        if on_udp_message(self.raiden, message):

            # Sending Delivered after the message is decoded and *processed*
            # gives a stronger guarantee than what is required from a
            # transport.
            #
            # Alternatives are, from weakest to strongest options:
            # - Just save it on disk and asynchronously process the messages
            # - Decode it, save to the WAL, and asynchronously process the
            #   state change
            # - Decode it, save to the WAL, and process it (the current
            #   implementation)
            delivered_message = Delivered(message.message_identifier)
            self.raiden.sign(delivered_message)

            self.maybe_send(
                message.sender,
                delivered_message,
            )

    def receive_delivered(self, delivered: Delivered):
        """ Handle a Delivered message.

        The Delivered message is how the UDP transport guarantees persistence
        by the partner node. The message itself is not part of the raiden
        protocol, but it's required by this transport to provide the required
        properties.
        """
        processed = ReceiveDelivered(delivered.delivered_message_identifier)
        self.raiden.handle_state_change(processed)

        message_id = delivered.delivered_message_identifier
        async_result = self.raiden.protocol.messageids_to_asyncresults.get(message_id)

        # clear the async result, otherwise we have a memory leak
        if async_result is not None:
            del self.messageids_to_asyncresults[message_id]
            async_result.set()

    # Pings and Pongs are used to check the health status of another node. They
    # are /not/ part of the raiden protocol, only part of the UDP transport,
    # therefore these messages are not forwarded to the message handler.
    def receive_ping(self, ping):
        """ Handle a Ping message by answering with a Pong. """

        if ping_log.isEnabledFor(logging.DEBUG):
            ping_log.debug(
                'PING RECEIVED',
                node=pex(self.raiden.address),
                message_id=ping.nonce,
                message=ping,
                sender=pex(ping.sender),
            )

        pong = Pong(ping.nonce)
        self.raiden.sign(pong)

        try:
            self.maybe_send(ping.sender, pong)
        except (InvalidAddress, UnknownAddress) as e:
            log.debug("Couldn't send the `Delivered` message", e=e)

    def receive_pong(self, pong):
        """ Handles a Pong message. """

        message_id = ('ping', pong.nonce, pong.sender)
        async_result = self.messageids_to_asyncresults.get(message_id)

        if async_result is not None:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'PONG RECEIVED',
                    node=pex(self.raiden.address),
                    message_id=pong.nonce,
                )

            async_result.set(True)

    def get_ping(self, nonce):
        """ Returns a signed Ping message.

        Note: Ping messages don't have an enforced ordering, so a Ping message
        with a higher nonce may be acknowledged first.
        """
        message = Ping(nonce)
        self.raiden.sign(message)
        message_data = message.encode()

        return message_data

    def set_node_network_state(self, node_address, node_state):
        state_change = ActionChangeNodeNetworkState(node_address, node_state)
        self.raiden.handle_state_change(state_change)
