import socket

import cachetools
import gevent
import gevent.pool
import structlog
from eth_utils import encode_hex, is_binary_address
from gevent.event import AsyncResult, Event
from gevent.server import DatagramServer

from raiden import constants
from raiden.exceptions import InvalidAddress, InvalidProtocolMessage, UnknownAddress
from raiden.message_handler import MessageHandler
from raiden.messages import Delivered, Message, Ping, Pong, decode
from raiden.network.transport.udp import healthcheck
from raiden.network.transport.udp.udp_utils import (
    event_first_of,
    retry_with_recovery,
    timeout_exponential_backoff,
)
from raiden.raiden_service import RaidenService
from raiden.settings import CACHE_TTL
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.transfer.queue_identifier import QueueIdentifier
from raiden.transfer.state_change import ActionChangeNodeNetworkState
from raiden.utils import pex
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.utils.runnable import Runnable
from raiden.utils.typing import MYPY_ANNOTATION, Address, Dict, List, MessageID, Tuple

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
log_healthcheck = structlog.get_logger(__name__ + '.healthcheck')  # pylint: disable=invalid-name

QueueItem_T = Tuple[bytes, int]
Queue_T = List[QueueItem_T]

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
        recipient: Address,
        queue: Queue_T,
        queue_identifier: QueueIdentifier,
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
    transport.log.debug(
        'queue: waiting for node to become healthy',
        queue_identifier=queue_identifier,
        queue_size=len(queue),
    )

    event_first_of(
        event_healthy,
        event_stop,
    ).wait()

    transport.log.debug(
        'queue: processing queue',
        queue_identifier=queue_identifier,
        queue_size=len(queue),
    )

    while True:
        data_or_stop.wait()

        if event_stop.is_set():
            transport.log.debug(
                'queue: stopping',
                queue_identifier=queue_identifier,
                queue_size=len(queue),
            )
            return

        # The queue is not empty at this point, so this won't raise Empty.
        # This task being the only consumer is a requirement.
        (messagedata, message_id) = queue.peek(block=False)

        transport.log.debug(
            'queue: sending message',
            recipient=pex(recipient),
            msgid=message_id,
            queue_identifier=queue_identifier,
            queue_size=len(queue),
        )

        backoff = timeout_exponential_backoff(
            message_retries,
            message_retry_timeout,
            message_retry_max_timeout,
        )

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


class UDPTransport(Runnable):
    UDP_MAX_MESSAGE_SIZE = 1200
    log = log
    log_healthcheck = log_healthcheck

    def __init__(self, address, discovery, udpsocket, throttle_policy, config):
        super().__init__()
        # these values are initialized by the start method
        self.queueids_to_queues: Dict = dict()
        self.raiden: RaidenService
        self.message_handler: MessageHandler

        self.discovery = discovery
        self.config = config
        self.address = address

        self.retry_interval = config['retry_interval']
        self.retries_before_backoff = config['retries_before_backoff']
        self.nat_keepalive_retries = config['nat_keepalive_retries']
        self.nat_keepalive_timeout = config['nat_keepalive_timeout']
        self.nat_invitation_timeout = config['nat_invitation_timeout']

        self.event_stop = Event()
        self.event_stop.set()

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
        pool = gevent.pool.Pool()
        self.server = DatagramServer(
            udpsocket,
            handle=self.receive,
            spawn=pool,
        )

    def start(
            self,
            raiden_service: RaidenService,
            message_handler: MessageHandler,
            prev_auth_data: str,  # pylint: disable=unused-argument
    ):
        if not self.event_stop.ready():
            raise RuntimeError('UDPTransport started while running')

        self.event_stop.clear()
        self.raiden = raiden_service
        self.log = log.bind(node=pex(self.raiden.address))
        self.log_healthcheck = log_healthcheck.bind(node=pex(self.raiden.address))
        self.message_handler = message_handler

        # server.stop() clears the handle and the pool. Since this may be a
        # restart the handle must always be set
        self.server.set_handle(self.receive)
        pool = gevent.pool.Pool()
        self.server.set_spawn(pool)

        self.server.start()
        self.log.debug('UDP started')
        super().start()

        log.debug('UDP transport started')

    def _run(self):  # pylint: disable=method-hidden
        """ Runnable main method, perform wait on long-running subtasks """
        try:
            self.event_stop.wait()
        except gevent.GreenletExit:  # killed without exception
            self.event_stop.set()
            gevent.killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self):
        if self.event_stop.ready():
            return  # double call, happens on normal stop, ignore

        self.event_stop.set()

        # Stop handling incoming packets, but don't close the socket. The
        # socket can only be safely closed after all outgoing tasks are stopped
        self.server.stop_accepting()

        # Stop processing the outgoing queues
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

        log.debug('UDP stopped', node=pex(self.raiden.address))
        del self.log_healthcheck
        del self.log

    def get_health_events(self, recipient):
        """ Starts a healthcheck task for `recipient` and returns a
        HealthEvents with locks to react on its current state.
        """
        if recipient not in self.addresses_events:
            self.start_health_check(recipient)

        return self.addresses_events[recipient]

    def whitelist(self, address: Address):  # pylint: disable=no-self-use,unused-argument
        """Whitelist peer address to receive communications from

        This may be called before transport is started, to ensure events generated during
        start are handled properly.
        PS: udp currently doesn't do whitelisting, method defined for compatibility with matrix
        """
        return

    def start_health_check(self, recipient):
        """ Starts a task for healthchecking `recipient` if there is not
        one yet.

        It also whitelists the address
        """
        if recipient not in self.addresses_events:
            self.whitelist(recipient)  # noop for now, for compatibility
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
            greenlet_healthcheck.link_exception(self.on_error)
            self.greenlets.append(greenlet_healthcheck)

    def init_queue_for(
            self,
            queue_identifier: QueueIdentifier,
            items: List[QueueItem_T],
    ) -> NotifyingQueue:
        """ Create the queue identified by the queue_identifier
        and initialize it with `items`.
        """
        recipient = queue_identifier.recipient
        queue = self.queueids_to_queues.get(queue_identifier)
        assert queue is None

        queue = NotifyingQueue(items=items)
        self.queueids_to_queues[queue_identifier] = queue

        events = self.get_health_events(recipient)

        greenlet_queue = gevent.spawn(
            single_queue_send,
            self,
            recipient,
            queue,
            queue_identifier,
            self.event_stop,
            events.event_healthy,
            events.event_unhealthy,
            self.retries_before_backoff,
            self.retry_interval,
            self.retry_interval * 10,
        )

        if queue_identifier.channel_identifier == CHANNEL_IDENTIFIER_GLOBAL_QUEUE:
            greenlet_queue.name = f'Queue for {pex(recipient)} - global'
        else:
            greenlet_queue.name = (
                f'Queue for {pex(recipient)} - {queue_identifier.channel_identifier}'
            )

        greenlet_queue.link_exception(self.on_error)
        self.greenlets.append(greenlet_queue)

        self.log.debug(
            'new queue created for',
            queue_identifier=queue_identifier,
            items_qty=len(items),
        )

        return queue

    def get_queue_for(
            self,
            queue_identifier: QueueIdentifier,
    ) -> NotifyingQueue:
        """ Return the queue identified by the given queue identifier.

        If the queue doesn't exist it will be instantiated.
        """
        queue = self.queueids_to_queues.get(queue_identifier)

        if queue is None:
            items: List[QueueItem_T] = list()
            queue = self.init_queue_for(queue_identifier, items)

        return queue

    def send_async(
            self,
            queue_identifier: QueueIdentifier,
            message: Message,
    ):
        """ Send a new ordered message to recipient.

        Messages that use the same `queue_identifier` are ordered.
        """
        recipient = queue_identifier.recipient
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

            queue = self.get_queue_for(queue_identifier)
            queue.put((messagedata, message_id))
            assert queue.is_set()

            self.log.debug(
                'Message queued',
                queue_identifier=queue_identifier,
                queue_size=len(queue),
                message=message,
            )

    def send_global(  # pylint: disable=unused-argument
            self,
            room: str,
            message: Message,
    ) -> None:
        """ This method exists only for interface compatibility with MatrixTransport """
        self.log.warning('UDP is unable to send global messages. Ignoring')

    def maybe_send(self, recipient: Address, message: Message):
        """ Send message to recipient if the transport is running. """

        if not is_binary_address(recipient):
            raise InvalidAddress('Invalid address {}'.format(pex(recipient)))

        messagedata = message.encode()
        host_port = self.get_host_port(recipient)

        self.maybe_sendraw(host_port, messagedata)

    def maybe_sendraw_with_result(
            self,
            recipient: Address,
            messagedata: bytes,
            message_id: MessageID,
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

    def maybe_sendraw(self, host_port: Tuple[int, int], messagedata: bytes):
        """ Send message to recipient if the transport is running. """

        # Don't sleep if timeout is zero, otherwise a context-switch is done
        # and the message is delayed, increasing its latency
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

    def receive(
            self,
            messagedata: bytes,
            host_port: Tuple[str, int],  # pylint: disable=unused-argument
    ) -> bool:
        """ Handle an UDP packet. """
        # pylint: disable=unidiomatic-typecheck

        if len(messagedata) > self.UDP_MAX_MESSAGE_SIZE:
            self.log.warning(
                'Invalid message: Packet larger than maximum size',
                message=encode_hex(messagedata),
                length=len(messagedata),
            )
            return False

        try:
            message = decode(messagedata)
        except InvalidProtocolMessage as e:
            self.log.warning(
                'Invalid protocol message',
                error=str(e),
                message=encode_hex(messagedata),
            )
            return False

        if type(message) == Pong:
            assert isinstance(message, Pong), MYPY_ANNOTATION
            self.receive_pong(message)
        elif type(message) == Ping:
            assert isinstance(message, Ping), MYPY_ANNOTATION
            self.receive_ping(message)
        elif type(message) == Delivered:
            assert isinstance(message, Delivered), MYPY_ANNOTATION
            self.receive_delivered(message)
        elif message is not None:
            self.receive_message(message)
        else:
            self.log.warning(
                'Invalid message: Unknown cmdid',
                message=encode_hex(messagedata),
            )
            return False

        return True

    def receive_message(self, message: Message):
        """ Handle a Raiden protocol message.

        The protocol requires durability of the messages. The UDP transport
        relies on the node's WAL for durability. The message will be converted
        to a state change, saved to the WAL, and *processed* before the
        durability is confirmed, which is a stronger property than what is
        required of any transport.
        """
        self.raiden.on_message(message)

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
        delivered_message = Delivered(delivered_message_identifier=message.message_identifier)
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
        self.raiden.on_message(delivered)

        message_id = delivered.delivered_message_identifier
        async_result = self.raiden.transport.messageids_to_asyncresults.get(message_id)

        # clear the async result, otherwise we have a memory leak
        if async_result is not None:
            del self.messageids_to_asyncresults[message_id]
            async_result.set()
        else:
            self.log.warn(
                'Unknown delivered message received',
                message_id=message_id,
            )

    # Pings and Pongs are used to check the health status of another node. They
    # are /not/ part of the raiden protocol, only part of the UDP transport,
    # therefore these messages are not forwarded to the message handler.
    def receive_ping(self, ping: Ping):
        """ Handle a Ping message by answering with a Pong. """

        self.log_healthcheck.debug(
            'Ping received',
            message_id=ping.nonce,
            message=ping,
            sender=pex(ping.sender),
        )

        pong = Pong(nonce=ping.nonce)
        self.raiden.sign(pong)

        try:
            self.maybe_send(ping.sender, pong)
        except (InvalidAddress, UnknownAddress) as e:
            self.log.debug("Couldn't send the `Delivered` message", e=e)

    def receive_pong(self, pong: Pong):
        """ Handles a Pong message. """

        message_id = ('ping', pong.nonce, pong.sender)
        async_result = self.messageids_to_asyncresults.get(message_id)

        if async_result is not None:
            self.log_healthcheck.debug(
                'Pong received',
                sender=pex(pong.sender),
                message_id=pong.nonce,
            )

            async_result.set(True)

        else:
            self.log_healthcheck.warn(
                'Unknown pong received',
                message_id=message_id,
            )

    def get_ping(self, nonce: int) -> Ping:
        """ Returns a signed Ping message.

        Note: Ping messages don't have an enforced ordering, so a Ping message
        with a higher nonce may be acknowledged first.
        """
        message = Ping(
            nonce=nonce,
            current_protocol_version=constants.PROTOCOL_VERSION,
        )
        self.raiden.sign(message)
        message_data = message.encode()

        return message_data

    def set_node_network_state(self, node_address: Address, node_state):
        state_change = ActionChangeNodeNetworkState(node_address, node_state)
        self.raiden.handle_and_track_state_change(state_change)
