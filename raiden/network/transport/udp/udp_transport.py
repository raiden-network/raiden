import socket
from binascii import hexlify

import cachetools
import gevent
from gevent.event import (
    AsyncResult,
    Event,
)
from gevent.server import DatagramServer
import structlog
from eth_utils import is_binary_address

from raiden.transfer.architecture import SendMessageEvent
from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    RaidenShuttingDown,
)
from raiden.messages import (
    message_from_sendevent,
    decode,
    Delivered,
    Message,
    Ping,
    Pong,
)
from raiden.settings import CACHE_TTL
from raiden.utils import pex, typing
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.message_handler import on_message
from raiden.transfer.state_change import ReceiveDelivered
from raiden.transfer.state_change import ActionChangeNodeNetworkState
from raiden.network.transport.udp import healthcheck
from raiden.network.transport.udp.udp_utils import (
    event_first_of,
    timeout_exponential_backoff,
    retry_with_recovery,
)
from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

QueueItem_T = typing.Tuple[bytes, int]
Queue_T = typing.List[QueueItem_T]

# GOALS:
# - Each netting channel must have the messages processed in-order, the
# transport must detect unacknowledged messages and retry them.
# - A queue must not stall because of synchronization problems in other queues.
# - Assuming a queue can stall, the unhealthiness of a node must not be
# inferred from the lack of acknowledgement from a single queue, but healthiness
# may be safely inferred from it.
# - The state of the node must be synchronized among all tasks that are
# handling messages.


def single_queue_send(
        transport: 'UDPTransport',
        recipient: typing.Address,
        queue: Queue_T,
        event_stop: Event,
        event_healthy: Event,
        event_unhealthy: Event,
        message_retries: int,
        message_retry_timeout: int,
        message_retry_max_timeout: int,
):
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
    # task cannot be stopped while the greenlet waits for an element to be
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
                transport,
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


class UDPTransport:
    UDP_MAX_MESSAGE_SIZE = 1200

    def __init__(self, discovery, udpsocket, throttle_policy, config):
        # these values are initialized by the start method
        self.queueids_to_queues: typing.Dict
        self.raiden: RaidenService

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

    def start(
            self,
            raiden: RaidenService,
            queueids_to_queues: typing.List[SendMessageEvent],
    ):
        self.raiden = raiden
        self.queueids_to_queues = dict()

        # server.stop() clears the handle. Since this may be a restart the
        # handle must always be set
        self.server.set_handle(self._receive)

        for (recipient, queue_name), queue in queueids_to_queues.items():
            encoded_queue = list()

            for sendevent in queue:
                message = message_from_sendevent(sendevent, raiden.address)
                raiden.sign(message)
                encoded = message.encode()

                encoded_queue.append((encoded, sendevent.message_identifier))

            self.init_queue_for(recipient, queue_name, encoded_queue)

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
        """ Starts a healthcheck task for `recipient` and returns a
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

            events = healthcheck.HealthEvents(
                event_healthy=Event(),
                event_unhealthy=Event(),
            )

            self.addresses_events[recipient] = events

            greenlet_healthcheck = gevent.spawn(
                healthcheck.healthcheck,
                self,
                recipient,
                self.event_stop,
                events.event_healthy,
                events.event_unhealthy,
                self.nat_keepalive_retries,
                self.nat_keepalive_timeout,
                self.nat_invitation_timeout,
                ping_nonce,
            )
            greenlet_healthcheck.name = f'Healthcheck for {pex(recipient)}'
            self.greenlets.append(greenlet_healthcheck)

    def init_queue_for(
            self,
            recipient: typing.Address,
            queue_name: bytes,
            items: typing.List[QueueItem_T],
    ) -> Queue_T:
        """ Create the queue identified by the pair `(recipient, queue_name)`
        and initialize it with `items`.
        """
        queueid = (recipient, queue_name)
        queue = self.queueids_to_queues.get(queueid)
        assert queue is None

        queue = NotifyingQueue(items=items)
        self.queueids_to_queues[queueid] = queue

        events = self.get_health_events(recipient)

        greenlet_queue = gevent.spawn(
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
        )

        if queue_name == b'global':
            greenlet_queue.name = f'Queue for {pex(recipient)} - global'
        else:
            greenlet_queue.name = f'Queue for {pex(recipient)} - {pex(queue_name)}'

        self.greenlets.append(greenlet_queue)

        log.debug(
            'new queue created for',
            node=pex(self.raiden.address),
            token=pex(queue_name),
            to=pex(recipient),
        )

        return queue

    def get_queue_for(
            self,
            recipient: typing.Address,
            queue_name: bytes,
    ) -> Queue_T:
        """ Return the queue identified by the pair `(recipient, queue_name)`.

        If the queue doesn't exist it will be instantiated.
        """
        queueid = (recipient, queue_name)
        queue = self.queueids_to_queues.get(queueid)

        if queue is None:
            items = ()
            queue = self.init_queue_for(recipient, queue_name, items)

        return queue

    def send_async(
            self,
            recipient: typing.Address,
            queue_name: bytes,
            message: 'Message',
    ):
        """ Send a new ordered message to recipient.

        Messages that use the same `queue_name` are ordered.
        """

        if not is_binary_address(recipient):
            raise ValueError('Invalid address {}'.format(pex(recipient)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError('Do not use send for {} messages'.format(message.__class__.__name__))

        messagedata = message.encode()
        if len(messagedata) > self.UDP_MAX_MESSAGE_SIZE:
            raise ValueError(
                'message size exceeds the maximum {}'.format(self.UDP_MAX_MESSAGE_SIZE),
            )

        # message identifiers must be unique
        message_id = message.message_identifier

        # ignore duplicates
        if message_id not in self.messageids_to_asyncresults:
            self.messageids_to_asyncresults[message_id] = AsyncResult()

            queue = self.get_queue_for(recipient, queue_name)
            queue.put((messagedata, message_id))

            log.debug(
                'MESSAGE QUEUED',
                node=pex(self.raiden.address),
                queue_name=queue_name,
                to=pex(recipient),
                message=message,
            )

    def maybe_send(self, recipient: typing.Address, message: Message):
        """ Send message to recipient if the transport is running. """

        if not is_binary_address(recipient):
            raise InvalidAddress('Invalid address {}'.format(pex(recipient)))

        messagedata = message.encode()
        host_port = self.get_host_port(recipient)

        self.maybe_sendraw(host_port, messagedata)

    def maybe_sendraw_with_result(
            self,
            recipient: typing.Address,
            messagedata: bytes,
            message_id: typing.MessageID,
    ) -> AsyncResult:
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

    def maybe_sendraw(self, host_port: typing.Tuple[int, int], messagedata: bytes):
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

    def receive(self, messagedata: bytes):
        """ Handle an UDP packet. """
        # pylint: disable=unidiomatic-typecheck

        if len(messagedata) > self.UDP_MAX_MESSAGE_SIZE:
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
        else:
            log.error(
                'INVALID MESSAGE: Unknown cmdid',
                node=pex(self.raiden.address),
                message=hexlify(messagedata),
            )

    def receive_message(self, message: Message):
        """ Handle a Raiden protocol message.

        The protocol requires durability of the messages. The UDP transport
        relies on the node's WAL for durability. The message will be converted
        to a state change, saved to the WAL, and *processed* before the
        durability is confirmed, which is a stronger property than what is
        required of any transport.
        """
        # pylint: disable=unidiomatic-typecheck

        if on_message(self.raiden, message):

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
        async_result = self.raiden.transport.messageids_to_asyncresults.get(message_id)

        # clear the async result, otherwise we have a memory leak
        if async_result is not None:
            del self.messageids_to_asyncresults[message_id]
            async_result.set()

    # Pings and Pongs are used to check the health status of another node. They
    # are /not/ part of the raiden protocol, only part of the UDP transport,
    # therefore these messages are not forwarded to the message handler.
    def receive_ping(self, ping: Ping):
        """ Handle a Ping message by answering with a Pong. """

        log.debug(
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

    def receive_pong(self, pong: Pong):
        """ Handles a Pong message. """

        message_id = ('ping', pong.nonce, pong.sender)
        async_result = self.messageids_to_asyncresults.get(message_id)

        if async_result is not None:
            log.debug(
                'PONG RECEIVED',
                node=pex(self.raiden.address),
                sender=pex(pong.sender),
                message_id=pong.nonce,
            )

            async_result.set(True)

    def get_ping(self, nonce: int) -> Ping:
        """ Returns a signed Ping message.

        Note: Ping messages don't have an enforced ordering, so a Ping message
        with a higher nonce may be acknowledged first.
        """
        message = Ping(nonce)
        self.raiden.sign(message)
        message_data = message.encode()

        return message_data

    def set_node_network_state(self, node_address: typing.Address, node_state):
        state_change = ActionChangeNodeNetworkState(node_address, node_state)
        self.raiden.handle_state_change(state_change)
