# -*- coding: utf-8 -*-
from binascii import hexlify
import logging
import random
from collections import namedtuple
from itertools import repeat

import cachetools
import gevent
from gevent.event import (
    _AbstractLinkable,
    AsyncResult,
    Event,
)
from ethereum import slogging

from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    UnknownTokenAddress,
    RaidenShuttingDown,
)
from raiden.constants import UDP_MAX_MESSAGE_SIZE, UINT64_MAX
from raiden.messages import decode, Processed, Ping, SignedMessage
from raiden.settings import CACHE_TTL
from raiden.utils import isaddress, sha3, pex
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.udp_message_handler import on_udp_message
from raiden.transfer import views
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
# - receiver_address used to tie back the message_id to the receiver (mainly for
#   logging purposes)
SentMessageState = namedtuple('SentMessageState', (
    'async_result',
    'receiver_address',
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


def messageid_from_data(data, address):
    # Messages that are not unique per receiver can result in hash collision,
    # e.g. Secret messages. The hash collision has the undesired effect of
    # aborting message resubmission once /one/ of the nodes replied with an
    # Ack, adding the receiver address into the echohash to avoid these
    # collisions.
    data = data + address

    return int.from_bytes(sha3(data), 'big') % UINT64_MAX


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
                return acknowledged

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
        data = queue.peek(block=False)

        backoff = timeout_exponential_backoff(
            message_retries,
            message_retry_timeout,
            message_retry_max_timeout,
        )

        try:
            acknowledged = retry_with_recovery(
                protocol,
                data,
                receiver_address,
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
        receiver_address,
        event_stop,
        event_healthy,
        event_unhealthy,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        nat_invitation_timeout,
        ping_nonce):

    """ Sends a periodical Ping to `receiver_address` to check its health. """
    # pylint: disable=too-many-branches

    if log.isEnabledFor(logging.DEBUG):
        log.debug(
            'starting healthcheck for',
            node=pex(protocol.raiden.address),
            to=pex(receiver_address),
        )

    # The state of the node is unknown, the events are set to allow the tasks
    # to do work.
    last_state = NODE_NETWORK_UNKNOWN
    protocol.set_node_network_state(
        receiver_address,
        last_state,
    )

    # Always call `clear` before `set`, since only `set` does context-switches
    # it's easier to reason about tasks that are waiting on both events.

    # Wait for the end-point registration or for the node to quit
    try:
        protocol.get_host_port(receiver_address)
    except UnknownAddress:
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'waiting for endpoint registration',
                node=pex(protocol.raiden.address),
                to=pex(receiver_address),
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
                protocol.get_host_port(receiver_address)
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
        data = protocol.get_ping(
            ping_nonce['nonce'],
        )

        # Send Ping a few times before setting the node as unreachable
        try:
            acknowledged = retry(
                protocol,
                data,
                receiver_address,
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
                    to=pex(receiver_address),
                    current_state=last_state,
                    new_state=NODE_NETWORK_UNREACHABLE,
                    retries=nat_keepalive_retries,
                    timeout=nat_keepalive_timeout,
                )

            # The node is not healthy, clear the event to stop all queue
            # tasks
            last_state = NODE_NETWORK_UNREACHABLE
            protocol.set_node_network_state(
                receiver_address,
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
                    data,
                    receiver_address,
                    event_stop,
                    repeat(nat_invitation_timeout),
                )
            except RaidenShuttingDown:  # For a clean shutdown process
                return

        if acknowledged:
            if log.isEnabledFor(logging.DEBUG):
                current_state = views.get_node_network_status(
                    views.state_from_raiden(protocol.raiden),
                    receiver_address,
                )
                log.debug(
                    'node answered',
                    node=pex(protocol.raiden.address),
                    to=pex(receiver_address),
                    current_state=current_state,
                    new_state=NODE_NETWORK_REACHABLE,
                )

            if last_state != NODE_NETWORK_REACHABLE:
                last_state = NODE_NETWORK_REACHABLE
                protocol.set_node_network_state(
                    receiver_address,
                    last_state,
                )
                event_unhealthy.clear()
                event_healthy.set()


class RaidenProtocol:
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

        # Maps received and *sucessfully* processed message ids to the
        # corresponding `Processed` message. Used to ignored duplicate messages
        # and resend the `Processed` message.
        self.messageids_to_processedmessages = dict()

        # Maps the message_id to a SentMessageState
        self.messageids_to_states = dict()

        # Maps the addresses to a dict with the latest nonce (using a dict
        # because python integers are immutable)
        self.nodeaddresses_to_nonces = dict()

        cache = cachetools.TTLCache(
            maxsize=50,
            ttl=CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.get_host_port = cache_wrapper(discovery.get)

    def start(self):
        self.transport.start()

    def stop_and_wait(self):
        # Stop handling incoming packets, but don't close the socket. The
        # socket can only be safely closed after all outgoing tasks are stopped
        self.transport.stop_accepting()

        # Stop processing the outgoing queues
        self.event_stop.set()
        gevent.wait(self.greenlets)

        # All outgoing tasks are stopped. Now it's safe to close the socket. At
        # this point there might be some incoming message being processed,
        # keeping the socket open is not useful for these.
        self.transport.stop()

        # Set all the pending results to False
        for wait_processed in self.messageids_to_states.values():
            wait_processed.async_result.set(False)

    def get_health_events(self, receiver_address):
        """ Starts a healthcheck taks for `receiver_address` and returns a
        HealthEvents with locks to react on its current state.
        """
        if receiver_address not in self.addresses_events:
            self.start_health_check(receiver_address)

        return self.addresses_events[receiver_address]

    def start_health_check(self, receiver_address):
        """ Starts a task for healthchecking `receiver_address` if there is not
        one yet.
        """
        if receiver_address not in self.addresses_events:
            ping_nonce = self.nodeaddresses_to_nonces.setdefault(
                receiver_address,
                {'nonce': 0},  # HACK: Allows the task to mutate the object
            )

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
                'new queue created for',
                node=pex(self.raiden.address),
                token=pex(token_address),
                to=pex(receiver_address),
            )

        return queue

    def send_async(self, receiver_address, message):
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, (Processed, Ping)):
            raise ValueError('Do not use send for `Processed` or `Ping` messages')

        messagedata = message.encode()
        if len(messagedata) > UDP_MAX_MESSAGE_SIZE:
            raise ValueError(
                'message size exceeds the maximum {}'.format(UDP_MAX_MESSAGE_SIZE)
            )

        message_id = messageid_from_data(messagedata, receiver_address)

        # All messages must be ordered, but only on a per channel basis.
        token_address = getattr(message, 'token', b'')

        # Ignore duplicated messages
        if message_id not in self.messageids_to_states:
            async_result = AsyncResult()
            self.messageids_to_states[message_id] = SentMessageState(
                async_result,
                receiver_address,
            )

            queue = self.get_channel_queue(
                receiver_address,
                token_address,
            )

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SENDING MESSAGE',
                    to=pex(receiver_address),
                    node=pex(self.raiden.address),
                    message=message,
                    message_id=message_id,
                )

            queue.put(messagedata)
        else:
            wait_processed = self.messageids_to_states[message_id]
            async_result = wait_processed.async_result

        return async_result

    def send_and_wait(self, receiver_address, message, timeout=None):
        """Sends a message and wait for the response 'Processed' message."""
        async_result = self.send_async(receiver_address, message)
        return async_result.wait(timeout=timeout)

    def maybe_send_processed(self, receiver_address, processed_message):
        """ Send processed_message to receiver_address if the transport is running. """
        if not isaddress(receiver_address):
            raise InvalidAddress('Invalid address {}'.format(pex(receiver_address)))

        if not isinstance(processed_message, Processed):
            raise ValueError('Use _maybe_send_processed only for `Processed` messages')

        messagedata = processed_message.encode()
        message_id = processed_message.processed_message_identifier

        self.messageids_to_processedmessages[message_id] = (
            receiver_address,
            messagedata
        )

        self._maybe_send_processed(*self.messageids_to_processedmessages[message_id])

    def _maybe_send_processed(self, receiver_address, messagedata):
        """ `Processed` messages must not go into the queue, otherwise nodes will deadlock
        waiting for the confirmation.
        """
        host_port = self.get_host_port(receiver_address)

        # `Processed` messages are sent at the end of the receive method, after the message is
        # sucessfully processed. It may be the case that the server is stopped
        # after the message is received but before the processed message is sent, under that
        # circumstance the udp socket would be unavaiable and then an exception
        # is raised.
        #
        # This check verifies the udp socket is still available before trying
        # to send the `Processed` message. There must be *no context-switches after this test*.
        if self.transport.server.started:
            self.transport.send(
                self.raiden,
                host_port,
                messagedata,
            )

    def get_ping(self, nonce):
        """ Returns a signed Ping message.

        Note: Ping messages don't have an enforced ordering, so a Ping message
        with a higher nonce may be acknowledged first.
        """
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
        message_id = messageid_from_data(data, receiver_address)

        if message_id not in self.messageids_to_states:
            async_result = AsyncResult()
            self.messageids_to_states[message_id] = SentMessageState(
                async_result,
                receiver_address,
            )
        else:
            async_result = self.messageids_to_states[message_id].async_result

        if not async_result.ready():
            self.transport.send(
                self.raiden,
                host_port,
                data,
            )

        return async_result

    def set_node_network_state(self, node_address, node_state):
        state_change = ActionChangeNodeNetworkState(node_address, node_state)
        self.raiden.handle_state_change(state_change)

    def receive(self, data):
        if len(data) > UDP_MAX_MESSAGE_SIZE:
            log.error('receive packet larger than maximum size', length=len(data))
            return

        # Repeat the 'PROCESSED' message if the message has been handled before
        message_id = messageid_from_data(data, self.raiden.address)
        if message_id in self.messageids_to_processedmessages:
            self._maybe_send_processed(*self.messageids_to_processedmessages[message_id])
            return

        message = decode(data)

        if isinstance(message, Processed):
            self.receive_processed(message)

        elif isinstance(message, Ping):
            self.receive_ping(message, message_id)

        elif isinstance(message, SignedMessage):
            self.receive_message(message, message_id)

        elif log.isEnabledFor(logging.ERROR):
            log.error(
                'Invalid message',
                message=hexlify(data),
            )

    def receive_processed(self, processed):
        waitprocessed = self.messageids_to_states.get(processed.processed_message_identifier)

        if waitprocessed is None:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'PROCESSED FOR UNKNOWN',
                    node=pex(self.raiden.address),
                    message_id=processed.processed_message_identifier,
                )

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'PROCESSED RECEIVED',
                    node=pex(self.raiden.address),
                    receiver=pex(waitprocessed.receiver_address),
                    message_id=processed.processed_message_identifier,
                )

            waitprocessed.async_result.set(True)

    def receive_ping(self, ping, message_id):
        if ping_log.isEnabledFor(logging.DEBUG):
            ping_log.debug(
                'PING RECEIVED',
                node=pex(self.raiden.address),
                message_id=message_id,
                message=ping,
                sender=pex(ping.sender),
            )

        processed_message = Processed(self.raiden.address, message_id)

        try:
            self.maybe_send_processed(
                ping.sender,
                processed_message,
            )
        except (InvalidAddress, UnknownAddress) as e:
            log.debug("Couldn't send the `Processed` message", e=e)

    def receive_message(self, message, message_id):
        is_debug_log_enabled = log.isEnabledFor(logging.DEBUG)

        if is_debug_log_enabled:
            log.info(
                'MESSAGE RECEIVED',
                node=pex(self.raiden.address),
                message_id=message_id,
                message=message,
                message_sender=pex(message.sender)
            )

        try:
            on_udp_message(self.raiden, message)

            # only send the Processed message if the message was handled without exceptions
            processed_message = Processed(self.raiden.address, message_id)

            self.maybe_send_processed(
                message.sender,
                processed_message,
            )
        except (InvalidAddress, UnknownAddress, UnknownTokenAddress) as e:
            if is_debug_log_enabled:
                log.warn(str(e))
        else:
            if is_debug_log_enabled:
                log.debug(
                    'PROCESSED',
                    node=pex(self.raiden.address),
                    to=pex(message.sender),
                    message_id=message_id,
                )
