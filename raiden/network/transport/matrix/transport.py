import asyncio
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from json import JSONDecodeError
from random import randint
from typing import TYPE_CHECKING, Counter as CounterType, Union
from urllib.parse import urlparse
from uuid import uuid4

import gevent
import pkg_resources
import structlog
from aiortc import RTCSessionDescription
from eth_utils import is_binary_address, to_normalized_address
from gevent.event import Event
from gevent.lock import Semaphore
from gevent.pool import Pool
from gevent.queue import JoinableQueue
from matrix_client.errors import MatrixError, MatrixHttpLibError
from web3.types import BlockIdentifier

import raiden
from raiden.constants import (
    EMPTY_SIGNATURE,
    MATRIX_AUTO_SELECT_SERVER,
    WEB_RTC_CHANNEL_TIMEOUT,
    Capabilities,
    CommunicationMedium,
    DeviceIDs,
    Environment,
    MatrixMessageType,
    RTCMessageType,
)
from raiden.exceptions import RaidenUnrecoverableError, TransportError
from raiden.messages.abstract import Message, RetrieableMessage, SignedRetrieableMessage
from raiden.messages.healthcheck import Ping, Pong
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.transport.matrix.client import (
    GMatrixClient,
    MatrixMessage,
    MatrixSyncMessages,
    Room,
)
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.network.transport.matrix.utils import (
    JOIN_RETRIES,
    USER_PRESENCE_REACHABLE_STATES,
    AddressReachability,
    DisplayNameCache,
    MessageAckTimingKeeper,
    UserPresence,
    address_from_userid,
    join_broadcast_room,
    login,
    make_client,
    make_message_batches,
    make_room_alias,
    my_place_or_yours,
    validate_and_parse_message,
    validate_userid_signature,
)
from raiden.network.transport.utils import timeout_exponential_backoff
from raiden.settings import CapabilitiesConfig, MatrixTransportConfig
from raiden.storage.serialization import DictSerializer
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state import QueueIdsToQueues
from raiden.utils.capabilities import capconfig_to_dict
from raiden.utils.formatting import to_checksum_address
from raiden.utils.logging import redact_secret
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.utils.runnable import Runnable
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    AddressHex,
    AddressMetadata,
    Any,
    Callable,
    ChainID,
    Dict,
    Iterable,
    Iterator,
    List,
    MessageID,
    NamedTuple,
    Optional,
    RoomID,
    Set,
    Tuple,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)


# Combined with 10 retries (``..utils.JOIN_RETRIES``) this will give a total wait time of ~15s
RETRY_INTERVAL = 0.1
RETRY_INTERVAL_MULTIPLIER = 1.55
# A RetryQueue is considered idle after this many iterations without a message
RETRY_QUEUE_IDLE_AFTER = 10

SET_PRESENCE_INTERVAL = 60


@dataclass
class MessagesQueue:
    queue_identifier: QueueIdentifier
    messages: List[Tuple[Message, Optional[AddressMetadata]]]


class _RetryQueue(Runnable):
    """ A helper Runnable to send batched messages to receiver through transport """

    class _MessageData(NamedTuple):
        """ Small helper data structure for message queue """

        queue_identifier: QueueIdentifier
        message: Message
        text: str
        # generator that tells if the message should be sent now
        expiration_generator: Iterator[bool]
        address_metadata: Optional[AddressMetadata]

    def __init__(self, transport: "MatrixTransport", receiver: Address) -> None:
        self.transport = transport
        self.receiver = receiver
        self._message_queue: List[_RetryQueue._MessageData] = list()
        self._notify_event = gevent.event.Event()
        self._lock = Semaphore()
        self._idle_since: int = 0  # Counter of idle iterations
        super().__init__()
        self.greenlet.name = f"RetryQueue recipient:{to_checksum_address(self.receiver)}"

    @property
    def log(self) -> Any:
        return self.transport.log

    @staticmethod
    def _expiration_generator(
        timeout_generator: Iterable[float], now: Callable[[], float] = time.time
    ) -> Iterator[bool]:
        """Stateful generator that yields True if more than timeout has passed since previous True,
        False otherwise.

        Helper method to tell when a message needs to be retried (more than timeout seconds
        passed since last time it was sent).
        timeout is iteratively fetched from timeout_generator
        First value is True to always send message at least once
        """
        for timeout in timeout_generator:
            _next = now() + timeout  # next value is now + next generated timeout
            yield True
            while now() < _next:  # yield False while next is still in the future
                yield False

    def enqueue(
        self,
        queue_identifier: QueueIdentifier,
        messages: List[Tuple[Message, Optional[AddressMetadata]]],
    ) -> None:
        """ Enqueue a message to be sent, and notify main loop """
        msg = (
            f"queue_identifier.recipient ({to_checksum_address(queue_identifier.recipient)}) "
            f" must match self.receiver ({to_checksum_address(self.receiver)})."
        )
        assert queue_identifier.recipient == self.receiver, msg

        with self._lock:
            timeout_generator = timeout_exponential_backoff(
                self.transport._config.retries_before_backoff,
                self.transport._config.retry_interval_initial,
                self.transport._config.retry_interval_max,
            )

            encoded_messages = list()
            for message, address_metadata in messages:
                already_queued = any(
                    queue_identifier == data.queue_identifier and message == data.message
                    for data in self._message_queue
                )

                if already_queued:
                    self.log.warning(
                        "Message already in queue - ignoring",
                        receiver=to_checksum_address(self.receiver),
                        queue=queue_identifier,
                        message=redact_secret(DictSerializer.serialize(message)),
                    )
                else:
                    expiration_generator = self._expiration_generator(timeout_generator)
                    data = _RetryQueue._MessageData(
                        queue_identifier=queue_identifier,
                        message=message,
                        text=MessageSerializer.serialize(message),
                        expiration_generator=expiration_generator,
                        address_metadata=address_metadata,
                    )
                    encoded_messages.append(data)

            self._message_queue.extend(encoded_messages)

        self.notify()

    def enqueue_unordered(
        self, message: Message, address_metadata: AddressMetadata = None
    ) -> None:
        """ Helper to enqueue a message in the unordered queue. """
        self.enqueue(
            queue_identifier=QueueIdentifier(
                recipient=self.receiver, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
            ),
            messages=[(message, address_metadata)],
        )

    def notify(self) -> None:
        """ Notify main loop to check if anything needs to be sent """
        with self._lock:
            self._notify_event.set()

    def _check_and_send(self) -> None:
        """Check and send all pending/queued messages that are not waiting on retry timeout

        After composing the to-be-sent message, also message queue from messages that are not
        present in the respective SendMessageEvent queue anymore
        """
        if not self.transport.greenlet:
            self.log.warning("Can't retry", reason="Transport not yet started")
            return
        if self.transport._stop_event.ready():
            self.log.warning("Can't retry", reason="Transport stopped")
            return

        assert self._lock.locked(), "RetryQueue lock must be held while messages are being sent"

        # On startup protocol messages must be sent only after the monitoring
        # services are updated. For more details refer to the method
        # `RaidenService._initialize_monitoring_services_queue`
        if self.transport._prioritize_broadcast_messages:
            self.transport._broadcast_queue.join()

        self.log.debug(
            "Retrying message(s)",
            receiver=to_checksum_address(self.receiver),
            queue_size=len(self._message_queue),
        )
        # XXX-UAM: reachability check was here

        def message_is_in_queue(message_data: _RetryQueue._MessageData) -> bool:
            if message_data.queue_identifier not in self.transport._queueids_to_queues:
                # The Raiden queue for this queue identifier has been removed
                return False
            return any(
                isinstance(message_data.message, RetrieableMessage)
                and send_event.message_identifier == message_data.message.message_identifier
                for send_event in self.transport._queueids_to_queues[message_data.queue_identifier]
            )

        message_texts: List[str] = list()
        for message_data in self._message_queue[:]:
            # Messages are sent on two conditions:
            # - Non-retryable (e.g. Delivered)
            #   - Those are immediately remove from the local queue since they are only sent once
            # - Retryable
            #   - Those are retried according to their retry generator as long as they haven't been
            #     removed from the Raiden queue
            remove = False
            if isinstance(message_data.message, (Delivered, Ping, Pong)):
                # e.g. Delivered, send only once and then clear
                # TODO: Is this correct? Will a missed Delivered be 'fixed' by the
                #       later `Processed` message?
                remove = True
                message_texts.append(message_data.text)
            elif not message_is_in_queue(message_data):
                remove = True
                self.log.debug(
                    "Stopping message send retry",
                    queue=message_data.queue_identifier,
                    message=message_data.message,
                    reason="Message was removed from queue or queue was removed",
                )
            else:
                # The message is still eligible for retry, consult the expiration generator if
                # it should be retried now
                if next(message_data.expiration_generator):
                    message_texts.append(message_data.text)
                    if self.transport._environment is Environment.DEVELOPMENT:
                        if isinstance(message_data.message, RetrieableMessage):
                            self.transport._counters["retry"][
                                (
                                    message_data.message.__class__.__name__,
                                    message_data.message.message_identifier,
                                )
                            ] += 1

            if remove:
                self._message_queue.remove(message_data)

        if message_texts:
            self.log.debug(
                "Send", receiver=to_checksum_address(self.receiver), messages=message_texts
            )
            for message_batch in make_message_batches(message_texts):
                self.transport._send_raw(self.receiver, message_batch)

    def _run(self) -> None:  # type: ignore
        msg = (
            """_RetryQueue started before transport._raiden_service is set. """
            """_RetryQueue should not be started before transport.start() is called"""
        )

        assert self.transport._raiden_service is not None, msg
        self.greenlet.name = (
            f"RetryQueue "
            f"node:{to_checksum_address(self.transport._raiden_service.address)} "
            f"recipient:{to_checksum_address(self.receiver)}"
        )
        # run while transport parent is running
        while not self.transport._stop_event.ready():
            # once entered the critical section, block any other enqueue or notify attempt
            with self._lock:
                self._notify_event.clear()
                if self._message_queue:
                    self._idle_since = 0
                    self._check_and_send()
                else:
                    self._idle_since += 1

            if self.is_idle:
                # There have been no messages to process for a while. Exit.
                # A new instance will be created by `MatrixTransport._get_retrier()` if necessary
                self.log.debug("Exiting idle RetryQueue", queue=self)
                return
            # wait up to retry_interval (or to be notified) before checking again
            self._notify_event.wait(self.transport._config.retry_interval_initial)

    @property
    def is_idle(self) -> bool:
        return self._idle_since >= RETRY_QUEUE_IDLE_AFTER

    def __str__(self) -> str:
        return self.greenlet.name

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} for {to_normalized_address(self.receiver)}>"


class MatrixTransport(Runnable):
    _room_prefix = "raiden"
    _room_sep = "_"
    _healthcheck_queue: NotifyingQueue[Address]
    log = log

    def __init__(self, config: MatrixTransportConfig, environment: Environment) -> None:
        super().__init__()
        self._uuid = uuid4()
        self._config = config
        self._environment = environment
        self._raiden_service: Optional["RaidenService"] = None

        if config.server == MATRIX_AUTO_SELECT_SERVER:
            available_servers = config.available_servers
        elif urlparse(config.server).scheme in {"http", "https"}:
            available_servers = [config.server]
        else:
            raise TransportError(
                f"Invalid matrix server specified (valid values: "
                f"'{MATRIX_AUTO_SELECT_SERVER}' or a URL)"
            )

        def _http_retry_delay() -> Iterable[float]:
            return timeout_exponential_backoff(
                self._config.retries_before_backoff,
                self._config.retry_interval_initial,
                self._config.retry_interval_max,
            )

        version = pkg_resources.require(raiden.__name__)[0].version
        self._client: GMatrixClient = make_client(
            self._handle_sync_messages,
            self._handle_member_join,
            available_servers,
            http_pool_maxsize=4,
            http_retry_timeout=40,
            http_retry_delay=_http_retry_delay,
            environment=environment,
            user_agent=f"Raiden {version}",
        )

        # web RTC
        self._web_rtc_manager = WebRTCManager(
            node_address=None,
            _handle_message_callback=self._handle_web_rtc_messages,
            _handle_sdp_callback=self._handle_sdp_callback,
            _handle_candidates_callback=self._handle_candidates_callback,
            _close_connection_callback=self._handle_closed_connection,
        )

        self.server_url = self._client.api.base_url
        self._server_name = urlparse(self.server_url).netloc

        self.greenlets: List[gevent.Greenlet] = list()

        self._address_to_retrier: Dict[Address, _RetryQueue] = dict()
        self._displayname_cache = DisplayNameCache()

        self.broadcast_rooms: Dict[str, Room] = dict()
        self._broadcast_queue: JoinableQueue[Tuple[str, Message]] = JoinableQueue()

        self._started = False
        self._starting = False

        self._stop_event: Event = Event()
        self._stop_event.set()
        self._healthcheck_queue = NotifyingQueue()

        self._broadcast_event = Event()
        self._prioritize_broadcast_messages: bool = True

        self._invite_queue: List[Tuple[RoomID, dict]] = []

        self._client.add_invite_listener(self._reject_invite)

        self._counters: Dict[str, CounterType[Tuple[str, MessageID]]] = {}
        self._message_timing_keeper: Optional[MessageAckTimingKeeper] = None
        if environment is Environment.DEVELOPMENT:
            self._counters["send"] = Counter()
            self._counters["retry"] = Counter()
            self._counters["dispatch"] = Counter()
            self._message_timing_keeper = MessageAckTimingKeeper()

        self.services_addresses: Dict[Address, int] = dict()

    def __repr__(self) -> str:
        if self._raiden_service is not None:
            node = f" node:{self.checksummed_address}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{self._uuid}>"

    @property
    def checksummed_address(self) -> Optional[AddressHex]:
        if self._raiden_service is not None:
            return to_checksum_address(self._raiden_service.address)
        return None

    def start(  # type: ignore
        self,
        raiden_service: "RaidenService",
        prev_auth_data: Optional[str],
    ) -> None:
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.log.debug("Matrix starting")
        self._stop_event.clear()
        self._starting = True
        self._raiden_service = raiden_service
        self._web_rtc_manager.node_address = self._raiden_service.address

        assert asyncio.get_event_loop().is_running(), "the loop must be running"
        self.log.debug("Asyncio loop is running", running=asyncio.get_event_loop().is_running())

        try:
            capabilities = capconfig_to_dict(self._config.capabilities_config)
            login(
                client=self._client,
                signer=self._raiden_service.signer,
                device_id=DeviceIDs.RAIDEN,
                prev_auth_data=prev_auth_data,
                capabilities=capabilities,
            )
        except ValueError as ex:
            # `ValueError` may be raised if `get_user` provides invalid data to
            # the `User` constructor. This is either a bug in the login, that
            # tries to get the user after a failed login, or a bug in the
            # Matrix SDK.
            raise RaidenUnrecoverableError("Matrix SDK failed to properly set the userid") from ex
        except MatrixHttpLibError as ex:
            raise RaidenUnrecoverableError(
                "The Matrix homeserver seems to be unavailable."
            ) from ex

        self.log = log.bind(
            current_user=self._user_id,
            node=to_checksum_address(self._raiden_service.address),
            transport_uuid=str(self._uuid),
        )
        self._initialize_broadcast_rooms()
        self._initialize_first_sync()
        self._initialize_sync()

        # (re)start any _RetryQueue which was initialized before start
        for retrier in self._address_to_retrier.values():
            if not retrier:
                self.log.debug("Starting retrier", retrier=retrier)
                retrier.start()

        super().start()  # start greenlet
        self._starting = False
        self._started = True

        self.log.debug("Matrix started", config=self._config)

        self._schedule_new_greenlet(self._set_presence, UserPresence.ONLINE)

    def _set_presence(self, state: UserPresence) -> None:
        waiting_period = randint(SET_PRESENCE_INTERVAL // 4, SET_PRESENCE_INTERVAL)
        gevent.wait(  # pylint: disable=gevent-disable-wait
            {self._stop_event}, timeout=waiting_period
        )

        if self._stop_event.is_set():
            return
        self._client.set_presence_state(state.value)

    def _run(self) -> None:  # type: ignore
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        assert self._raiden_service is not None, "_raiden_service not set"
        self.greenlet.name = f"MatrixTransport._run node:{self.checksummed_address}"
        try:
            # waits on _stop_event.ready()
            self._broadcast_worker()
            # children crashes should throw an exception here
        except gevent.GreenletExit:  # killed without exception
            self._stop_event.set()
            gevent.killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self) -> None:
        """Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception"""
        if self._stop_event.ready():
            return
        self.log.debug("Matrix stopping")
        # Ensure, we send all broadcast messages before shutting down
        self._broadcast_queue.join()
        self._stop_event.set()
        self._broadcast_event.set()

        if self._raiden_service:
            self._web_rtc_manager.stop()
            for (
                partner_address,
                rtc_partner,
            ) in self._web_rtc_manager.address_to_rtc_partners.items():
                hang_up_message = {
                    "type": RTCMessageType.HANGUP.value,
                    "call_id": rtc_partner.call_id,
                }
                self._send_raw(
                    partner_address, json.dumps(hang_up_message), MatrixMessageType.NOTICE
                )

        for retrier in self._address_to_retrier.values():
            if retrier:
                retrier.notify()

        # Wait for retriers which already started to exit, then discard them
        # Retriers which have not been started yet just get discarded
        # In the meanwhile no other retriers should be started since stop_event is set
        #
        # No need to get on them, exceptions are re-raised because of the
        # `link_exception`
        gevent.wait(  # pylint: disable=gevent-disable-wait
            {r.greenlet for r in self._address_to_retrier.values() if r.greenlet}
        )
        self._address_to_retrier = {}

        # We have to stop the client before the address manager. Otherwise the
        # sync thread might call the address manager after the manager has been
        # stopped.
        self._client.stop()  # stop sync_thread, wait on client's greenlets

        self.log.debug(
            "Waiting on own greenlets",
            greenlets=[greenlet for greenlet in self.greenlets if not greenlet.dead],
        )
        # wait on own greenlets. No need to get on them, exceptions are
        # re-raised because of the `link_exception`
        gevent.wait(self.greenlets)  # pylint: disable=gevent-disable-wait

        self._client.set_presence_state(UserPresence.OFFLINE.value)

        # Ensure keep-alive http connections are closed
        self._client.api.session.close()

        if self._environment is Environment.DEVELOPMENT:
            assert self._message_timing_keeper is not None, MYPY_ANNOTATION
            counters_most_common = {
                counter_type: counter.most_common(50)
                for counter_type, counter in self._counters.items()
            }
            self.log.debug(
                "Transport performance report",
                counters=counters_most_common,
                message_ack_durations=self._message_timing_keeper.generate_report(),
            )

        self.log.debug("Matrix stopped", config=self._config)
        try:
            del self.log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def send_async(self, message_queues: List[MessagesQueue]) -> None:
        """Queue messages to be sent.

        It may be called before transport is started, to initialize message queues
        The actual sending is started only when the transport is started
        """
        if self._environment is Environment.DEVELOPMENT:
            assert self._message_timing_keeper is not None, MYPY_ANNOTATION

        for queue in message_queues:
            receiver_address = queue.queue_identifier.recipient

            if not is_binary_address(receiver_address):
                raise ValueError(
                    "Invalid address {}".format(to_checksum_address(receiver_address))
                )

            # These are not protocol messages, but transport specific messages
            for message, _ in queue.messages:
                if isinstance(message, (Delivered, Ping, Pong)):
                    raise ValueError(
                        f"Do not use send_async for {message.__class__.__name__} messages"
                    )

                is_development = self._environment is Environment.DEVELOPMENT
                if is_development and isinstance(message, RetrieableMessage):
                    assert self._message_timing_keeper is not None, MYPY_ANNOTATION
                    self._counters["send"][
                        (message.__class__.__name__, message.message_identifier)
                    ] += 1
                    self._message_timing_keeper.add_message(message)

            self.log.debug(
                "Send async",
                receiver_address=to_checksum_address(receiver_address),
                messages=[
                    redact_secret(DictSerializer.serialize(message))
                    for message, _ in queue.messages
                ],
                queue_identifier=queue.queue_identifier,
            )

            self._send_with_retry(queue)

    def update_services_addresses(self, addresses_validity: Dict[Address, int]) -> None:
        """Update the registered services addresses.

        This should be called
        - prior to the transport startup, to populate initial addresses
        - on new `ServiceRegistry.sol::RegisteredService` event
        """
        for address, validity in addresses_validity.items():
            self.services_addresses[address] = validity

    def expire_services_addresses(self, current_timestamp: int, block_number: int) -> None:
        """Check registered service addresses for registration expiry. Purge addresses that
        are no longer valid from `service_addresses`.

        This should be called on a new `Block` event, with the current timestamp from `Block`.
        """
        for address, validity in self.services_addresses.items():
            if validity < current_timestamp:
                log.info(
                    "Retiring service address, registration expired.",
                    validity=validity,
                    current_timestamp=current_timestamp,
                    block_number=block_number,
                    address=address,
                )
                self.services_addresses.pop(address)

    def broadcast(self, message: Message, device_id: DeviceIDs) -> None:
        """Broadcast a message to all services via `to-device` multicast.
        The `device_id` determines the topic of the broadcast message and
        should be either DeviceIDs.MS for a broadcast to the registered Monitoring-Services
        or DeviceIDs.PFS for a broadcast to the registered Pathfinding-Services.

        The messages are sent in a send-and-forget async way, and there is no message
        acknowledgment from the services.

        Params:
            message:    Message instance to be serialized and sent
            device_id:  topic of broadcast (DeviceIDs.MS for monitoring, DeviceIDs.PFS for
                        pathfinding)
        """

        if device_id not in (DeviceIDs.MS, DeviceIDs.PFS):
            raise NotImplementedError(f"Broadcasting to device `{device_id}` is not supported.")

        self._broadcast_queue.put((device_id.value, message))
        self._broadcast_event.set()

    def _broadcast_worker(self) -> None:

        while not self._stop_event.ready():
            self._broadcast_event.clear()
            messages: Dict[str, List[Message]] = defaultdict(list)
            while self._broadcast_queue.qsize() > 0:
                device_id, message = self._broadcast_queue.get()
                messages[device_id].append(message)
            for device_id, messages_for_device_id in messages.items():
                serialized_messages = (
                    MessageSerializer.serialize(message) for message in messages_for_device_id
                )
                for message_batch in make_message_batches(serialized_messages):
                    self._multicast_raw(data=message_batch, device_id=device_id)
                for _ in messages_for_device_id:
                    # Every message needs to be marked as done.
                    # Unfortunately there's no way to do that in one call :(
                    # https://github.com/gevent/gevent/issues/1436
                    self._broadcast_queue.task_done()

            # Stop prioritizing broadcast messages after initial queue has been emptied
            self._prioritize_broadcast_messages = False
            self._broadcast_event.wait(self._config.retry_interval_initial)

    @property
    def _queueids_to_queues(self) -> QueueIdsToQueues:
        assert self._raiden_service is not None, "_raiden_service not set"

        chain_state = views.state_from_raiden(self._raiden_service)
        return views.get_all_messagequeues(chain_state)

    @property
    def _user_id(self) -> Optional[str]:
        return getattr(self, "_client", None) and getattr(self._client, "user_id", None)

    @property
    def chain_id(self) -> ChainID:
        assert self._raiden_service is not None, "_raiden_service not set"
        return self._raiden_service.rpc_client.chain_id

    def _initialize_first_sync(self) -> None:
        msg = "The first sync requires the Matrix client to be properly authenticated."
        assert self._user_id, msg

        msg = (
            "The sync thread must not be started before the `_inventory_rooms` "
            "is executed, the listener for the inventory rooms must be set up "
            "before any messages can be processed."
        )
        assert self._client.sync_thread is None, msg
        assert self._client.message_worker is None, msg
        assert self._raiden_service is not None, "_raiden_service not set"

        # Call sync to fetch the inventory rooms and new invites, the sync
        # limit prevents fetching the messages.
        filter_id = self._client.create_sync_filter(
            not_rooms=self.broadcast_rooms.values(), limit=0
        )
        prev_sync_filter_id = self._client.set_sync_filter_id(filter_id)
        # Need to reset this here, otherwise we might run into problems after a restart
        self._client.last_sync = float("inf")
        self._client.blocking_sync(
            timeout_ms=self._config.sync_timeout, latency_ms=self._config.sync_latency
        )
        # Restore the filter to start fetching the messages
        self._client.set_sync_filter_id(prev_sync_filter_id)

        for room in self._client.rooms.values():
            # We no longer use private rooms for node-to-node communcation.
            # Leave any that are still lingering.
            room.leave()

    def _initialize_broadcast_rooms(self) -> None:
        msg = "To join the broadcast rooms the Matrix client to be properly authenticated."
        assert self._user_id, msg

        pool = Pool(size=10)

        def _join_broadcast_room(transport: MatrixTransport, room_name: str) -> None:
            broadcast_room_alias = f"#{room_name}:{transport._server_name}"
            transport.log.debug(
                "Joining broadcast room", broadcast_room_alias=broadcast_room_alias
            )
            transport.broadcast_rooms[room_name] = join_broadcast_room(
                client=transport._client, broadcast_room_alias=broadcast_room_alias
            )

        for suffix in self._config.broadcast_rooms:
            alias_prefix = make_room_alias(self.chain_id, suffix)

            if alias_prefix not in self.broadcast_rooms:
                pool.apply_async(_join_broadcast_room, args=(self, alias_prefix))

        pool.join(raise_error=True)

    def _initialize_sync(self) -> None:
        msg = "_initialize_sync requires the GMatrixClient to be properly authenticated."
        assert self._user_id, msg

        msg = "The sync thread must not be started twice"
        assert self._client.sync_worker is None, msg
        assert self._client.message_worker is None, msg

        msg = (
            "The node must have joined the broadcast rooms before starting the "
            "sync thread, since that is necessary to properly generate the "
            "filters."
        )
        assert self.broadcast_rooms, msg

        broadcast_filter_id = self._client.create_sync_filter(
            not_rooms=self.broadcast_rooms.values()
        )
        self._client.set_sync_filter_id(broadcast_filter_id)

        def on_success(greenlet: gevent.Greenlet) -> None:
            if greenlet in self.greenlets:
                self.greenlets.remove(greenlet)

        self._client.start_listener_thread(
            timeout_ms=self._config.sync_timeout, latency_ms=self._config.sync_latency
        )
        assert isinstance(self._client.sync_worker, gevent.Greenlet), MYPY_ANNOTATION
        self._client.sync_worker.link_exception(self.on_error)
        self._client.sync_worker.link_value(on_success)

        assert isinstance(self._client.message_worker, gevent.Greenlet), MYPY_ANNOTATION
        self._client.message_worker.link_exception(self.on_error)
        self._client.message_worker.link_value(on_success)
        self.greenlets = [self._client.sync_worker, self._client.message_worker]

    def _extract_addresses(self, room: Room) -> List[Optional[Address]]:
        """
        returns list of address of room members.
        If address can not be extracted due to false displayname
        it will include None in the list
        """
        assert self._raiden_service is not None, "_raiden_service not set"
        joined_addresses = set(
            validate_userid_signature(user) for user in room.get_joined_members()
        )

        return [address for address in joined_addresses if address != self._raiden_service.address]

    def _has_multiple_partner_addresses(self, room: Room) -> bool:
        assert self._raiden_service is not None, "_raiden_service not set"
        joined_addresses = set()
        for user in room.get_joined_members():
            address = validate_userid_signature(user)
            if address != self._raiden_service.address:
                joined_addresses.add(address)
                # if address is None it means a false displayname, should leave
                if len(joined_addresses) > 1 or address is None:
                    return True
        return False

    def _reject_invite(self, room_id: RoomID, state: dict) -> None:
        """Handle an invite request.

        We no longer use peer to peer rooms for communication.
        Reject all incoming invites.
        """
        if self._stop_event.ready():
            return

        invite_events = [
            event
            for event in state["events"]
            if event["type"] == "m.room.member"
            and event["content"].get("membership") == "invite"
            and event["state_key"] == self._user_id
        ]

        if not invite_events or not invite_events[0]:
            # Invalid invite, ignore
            return

        sender = invite_events[0]["sender"]

        self.log.debug("Rejecting invite", room_id=room_id, sender=sender)

        self.retry_api_call(
            self._client.api.send_state_event,
            room_id=room_id,
            event_type="m.room.member",
            content={"membership": "leave"},
        )

    def _handle_member_join(self, room: Room) -> None:
        if self._is_broadcast_room(room):
            raise AssertionError(
                f"Broadcast room events should be filtered in syncs: {room.canonical_alias}."
                f"Joined Broadcast Rooms: {list(self.broadcast_rooms.keys())}"
                f"Should be joined to: {self._config.broadcast_rooms}"
            )

    def _validate_matrix_messages(
        self, room: Optional[Room], messages: List[MatrixMessage]
    ) -> Tuple[List[Message], List[Tuple[Address, MatrixMessage]]]:
        assert self._raiden_service is not None, "_raiden_service not set"

        raiden_messages: List[Message] = []
        call_messages: List[Tuple[Address, MatrixMessage]] = []

        for message in messages:

            is_raiden_message = (
                message["type"] == "m.room.message"
                and message["content"]["msgtype"] == MatrixMessageType.TEXT.value
            )

            is_call_message = (
                message["type"] == "m.room.message"
                and message["content"]["msgtype"] == MatrixMessageType.NOTICE.value
            )
            if not is_raiden_message and not is_call_message:
                continue

            # Ignore our own messages. We can use address_from_userid in this specific case
            # since it is a negative check. This is used to avoid messages from same address
            # but different user (due to roaming)
            sender_id = message["sender"]
            if self._raiden_service.address == address_from_userid(sender_id):
                continue

            user = self._client.get_user(sender_id)
            self._displayname_cache.warm_users([user])

            peer_address = validate_userid_signature(user)
            if not peer_address:
                self.log.debug(
                    "Ignoring message from user with an invalid display name signature",
                    peer_user=user.user_id,
                    room=room,
                )
                continue

            if room and self._is_broadcast_room(room):
                # This must not happen. Nodes must not listen on broadcast rooms.
                raise RaidenUnrecoverableError(
                    f"Received message in broadcast room {room.canonical_alias}"
                )
            elif room:
                # We no longer accept node-to-node communication messages in private rooms and
                # should not be in any.
                raise RaidenUnrecoverableError(f"Received message in room {room.canonical_alias}.")

            # XXX-UAM: Whitelist check was here
            if is_raiden_message:
                raiden_messages.extend(
                    validate_and_parse_message(message["content"]["body"], peer_address)
                )
            if is_call_message:
                call_messages.append((peer_address, message))

        return raiden_messages, call_messages

    def _process_messages(self, all_messages: List[Message]) -> None:
        assert self._raiden_service is not None, "_process_messages must be called after start"

        # Remove this #3254
        for message in all_messages:
            if isinstance(message, (Processed, SignedRetrieableMessage)) and message.sender:
                delivered_message = Delivered(
                    delivered_message_identifier=message.message_identifier,
                    signature=EMPTY_SIGNATURE,
                )
                self._raiden_service.sign(delivered_message)
                retrier = self._get_retrier(message.sender)
                retrier.enqueue_unordered(delivered_message)
            if self._environment is Environment.DEVELOPMENT:
                if isinstance(message, RetrieableMessage):
                    self._counters["dispatch"][
                        (message.__class__.__name__, message.message_identifier)
                    ] += 1
                if isinstance(message, Processed):
                    assert self._message_timing_keeper is not None, MYPY_ANNOTATION
                    self._message_timing_keeper.finalize_message(message)
        self.log.debug("Incoming messages", messages=all_messages)

        self._raiden_service.on_messages(all_messages)

    def _handle_sync_messages(self, sync_messages: MatrixSyncMessages) -> bool:
        """ Handle text messages sent to listening rooms """
        if self._stop_event.ready():
            return False

        assert self._raiden_service is not None, "_raiden_service not set"

        raiden_messages: List[Message] = list()
        call_messages: List[Tuple[Address, MatrixMessage]] = list()

        for room, room_messages in sync_messages:
            raiden_room_messages, call_room_messages = self._validate_matrix_messages(
                room, room_messages
            )
            raiden_messages.extend(raiden_room_messages)
            call_messages.extend(call_room_messages)

        self._process_messages(raiden_messages)
        self._process_call_messages(call_messages)
        return len(raiden_messages) > 0 or len(call_messages) > 0

    def _handle_web_rtc_messages(self, message_data: str, partner_address: Address) -> None:
        if not self._stop_event.is_set():
            messages = validate_and_parse_message(message_data, partner_address)
            self._process_messages(messages)

    def _process_call_messages(self, call_messages: List[Tuple[Address, MatrixMessage]]) -> None:
        """
        This function handles incoming signalling messages (in matrix called 'call' events).
        In Raiden 'm.room.message' events are used as the communication format.
        Main function is to forward it to the aiortc library to establish connections.
        Messages contain sdp messages to follow the ROAP (RTC Offer Answer Protocol).
        Args:
            call_messages: List of signalling messages
        """
        assert self._raiden_service is not None, "_raiden_service not set"

        for partner_address, call_message in call_messages:
            try:
                content = json.loads(call_message["content"]["body"])
                rtc_message_type = content["type"]
                log.debug(
                    "Received signaling message",
                    partner_address=to_checksum_address(partner_address),
                    type=rtc_message_type,
                    content=content,
                )
                if (
                    rtc_message_type in [RTCMessageType.OFFER.value, RTCMessageType.ANSWER.value]
                    and "sdp" in content
                ):
                    self._web_rtc_manager.process_signalling_for_address(partner_address, content)

                elif rtc_message_type == RTCMessageType.HANGUP.value:
                    self._web_rtc_manager.close_connection(partner_address)

                elif rtc_message_type == RTCMessageType.CANDIDATES.value:
                    self._web_rtc_manager.set_candidates_for_address(partner_address, content)
                else:
                    self.log.debug(
                        "Unknown rtc message type",
                        partner_address=to_checksum_address(partner_address),
                        type=rtc_message_type,
                    )
            except (KeyError, JSONDecodeError):
                self.log.warning(
                    "Malformed signaling message",
                    partner_address=partner_address,
                    content=call_message["content"]["body"],
                )
                continue

    def _get_retrier(self, receiver: Address) -> _RetryQueue:
        """ Construct and return a _RetryQueue for receiver """
        retrier = self._address_to_retrier.get(receiver)
        # The RetryQueue may have exited due to being idle
        if retrier is None or retrier.greenlet.ready():
            retrier = _RetryQueue(transport=self, receiver=receiver)
            self._address_to_retrier[receiver] = retrier
            if not self._stop_event.ready():
                retrier.start()
            # ``Runnable.start()`` may re-create the internal greenlet
            retrier.greenlet.link_exception(self.on_error)
        return retrier

    def _send_with_retry(self, queue: MessagesQueue) -> None:
        retrier = self._get_retrier(queue.queue_identifier.recipient)
        retrier.enqueue(queue_identifier=queue.queue_identifier, messages=queue.messages)

    def _multicast_raw(
        self,
        data: str,
        device_id: str = "*",
    ) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"

        # Construct the user without the help of the `UserAddressManager`
        # This will not check for presence of the user-id and will
        # ONLY send the data to the user-ids of the services on the node's connected homeserver.
        user_ids = list()
        for address in self.services_addresses.keys():
            user_ids.append(f"@{to_normalized_address(address)}:{self._server_name}")

        messages = {
            user_id: {device_id: {"msgtype": MatrixMessageType.TEXT.value, "body": data}}
            for user_id in user_ids
        }

        self.log.debug(
            "Multicast (`to-device`)",
            device_id=device_id,
            receivers=user_ids,
            data=data.replace("\n", "\\n"),
        )

        self._client.api.send_to_device(event_type="m.room.message", messages=messages)

    def _send_raw(
        self,
        receiver_address: Address,
        data: str,
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
    ) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"

        # XXX-UAM: extract partner caps from metadata here
        is_to_device = self._capability_usable(Capabilities.TODEVICE, receiver_address)

        communication_medium = (
            CommunicationMedium.WEB_RTC
            if self._web_rtc_manager.has_ready_channel(receiver_address)
            else CommunicationMedium.TO_DEVICE
            if is_to_device
            else CommunicationMedium.ROOM
        )

        self.log.debug(
            "Send raw message",
            receiver=to_checksum_address(receiver_address),
            send_medium=communication_medium.value,
            data=data.replace("\n", "\\n"),
        )

        if communication_medium is CommunicationMedium.WEB_RTC:
            self._web_rtc_manager.send_message_for_address(receiver_address, data)
            return

        elif communication_medium is CommunicationMedium.TO_DEVICE:
            # XXX-UAM: Need user_ids here
            online_userids = []
            messages = {
                user_id: {"*": {"msgtype": message_type.value, "body": data}}
                for user_id in online_userids
            }

            self._client.api.send_to_device(event_type="m.room.message", messages=messages)
            return
        else:
            self.log.error(
                "Can't communicate with peer. No supported communication medium available.",
                peer=receiver_address,
                peer_communication_medium=communication_medium,
            )

    def _maybe_initialize_web_rtc(self, address: Address) -> None:

        if self._stop_event.ready():
            return

        assert self._raiden_service is not None, "_raiden_service not set"

        self._web_rtc_manager.get_rtc_partner(address).sync_events.aio_allow_init.set()
        lower_address = my_place_or_yours(self._raiden_service.address, address)

        if lower_address == self._raiden_service.address:
            self.log.debug(
                "Spawning initialize web rtc for partner",
                partner_address=to_checksum_address(address),
            )
            # initiate web rtc handling
            self._schedule_new_greenlet(self._initialize_web_rtc, address)

    def _initialize_web_rtc(self, partner_address: Address) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"

        rtc_partner = self._web_rtc_manager.get_rtc_partner(partner_address)
        # XXX-UAM: extract partner caps from metadata here
        is_to_device = self._capability_usable(Capabilities.TODEVICE, partner_address)

        if not is_to_device:
            self.log.warning(
                "Can't open WebRTC channel to peer not supporting ToDevice.", peer=partner_address
            )
            return

        # we need to wait for an online partner
        while not self._started:

            self.log.debug(
                "Waiting for partner reachable to create rtc channel",
                partner_address=to_checksum_address(partner_address),
                transport_started=self._started,
            )
            rtc_partner.sync_events.aio_allow_init.clear()
            # this can be ignored here since the underlying awaitables are only events
            gevent.wait(  # pylint: disable=gevent-disable-wait
                {rtc_partner.sync_events.g_allow_init, self._stop_event},
                count=1,
            )

            if self._stop_event.is_set():
                return

        self.log.debug(
            "Initiating web rtc",
            partner_address=to_checksum_address(partner_address),
        )
        self._web_rtc_manager.initialize_signalling_for_address(partner_address)

        # wait for WEB_RTC_CHANNEL_TIMEOUT seconds and check if connection was established
        if self._stop_event.wait(timeout=WEB_RTC_CHANNEL_TIMEOUT):
            return

        # if room is not None that means we are at least in the second iteration
        # call hang up to sync with the partner about a retry
        if not self._web_rtc_manager.has_ready_channel(partner_address):
            self.log.debug(
                "Could not establish channel",
                node=self.checksummed_address,
                partner_address=to_checksum_address(partner_address),
            )
            hang_up_message = {
                "type": RTCMessageType.HANGUP.value,
                "call_id": self._web_rtc_manager.get_rtc_partner(partner_address).call_id,
            }
            self._send_raw(partner_address, json.dumps(hang_up_message), MatrixMessageType.NOTICE)
            self._web_rtc_manager.close_connection(partner_address)

    def _handle_sdp_callback(
        self,
        rtc_session_description: Optional[RTCSessionDescription],
        partner_address: Address,
    ) -> None:
        """
        This is a callback function to process sdp (session description protocol) messages.
        These messages are part of the ROAP (RTC Offer Answer Protocol) which is also called
        signalling. Messages are exchanged via the partners' private matrix room.
        Args:
            rtc_session_description: sdp message for the partner
            partner_address: Address of the partner
        """
        assert self._raiden_service is not None, "_raiden_service not set"

        if self._stop_event.ready():
            return

        if rtc_session_description is None:
            return

        rtc_partner = self._web_rtc_manager.get_rtc_partner(partner_address)

        sdp_type = rtc_session_description.type
        message = {
            "type": sdp_type,
            "sdp": rtc_session_description.sdp,
            "call_id": rtc_partner.call_id,
        }
        self.log.debug(
            f"Send {sdp_type} to partner",
            partner_address=to_checksum_address(partner_address),
            sdp_description=message,
        )

        self._send_raw(partner_address, json.dumps(message), MatrixMessageType.NOTICE)

    def _handle_candidates_callback(
        self, candidates: List[Dict[str, Union[int, str]]], partner_address: Address
    ) -> None:

        assert self._raiden_service is not None, "_raiden_service not set"

        if self._stop_event.ready():
            return

        rtc_partner = self._web_rtc_manager.get_rtc_partner(partner_address)
        message = {
            "type": RTCMessageType.CANDIDATES.value,
            "candidates": candidates,
            "call_id": rtc_partner.call_id,
        }
        self._send_raw(partner_address, json.dumps(message), MatrixMessageType.NOTICE)

    def _handle_closed_connection(self, partner_address: Address) -> None:

        if self._stop_event.is_set():
            return

        # XXX-UAM: Reachability check was here

        # FIXME: temporary sleep to stretch two signaling processes a bit
        #        with a unique call id for each try this wont be necessary
        gevent.sleep(3)
        self._maybe_initialize_web_rtc(partner_address)

    def _is_broadcast_room(self, room: Room) -> bool:
        has_alias = room.canonical_alias is not None
        return has_alias and any(
            suffix in room.canonical_alias for suffix in self._config.broadcast_rooms
        )

    def _capability_usable(
        self, capability: Capabilities, partner_capabilities_config: CapabilitiesConfig
    ) -> bool:
        """ Checks if a given capability is enabled for the local and the partner node """

        own_caps = capconfig_to_dict(self._config.capabilities_config)
        partner_caps = capconfig_to_dict(partner_capabilities_config)

        key = capability.value
        return bool(
            key in own_caps and own_caps[key] and key in partner_caps and partner_caps[key]
        )

    def _address_reachability_changed(
        self, address: Address, reachability: AddressReachability
    ) -> None:
        if reachability is AddressReachability.REACHABLE:
            # _QueueRetry.notify when partner comes online
            retrier = self._address_to_retrier.get(address)
            if retrier:
                retrier.notify()

            # XXX-UAM: extract partner caps from metadata here
            if self._capability_usable(Capabilities.WEBRTC, address):
                # if lower address spawn worker to create web rtc channel
                self._maybe_initialize_web_rtc(address)

        elif reachability is AddressReachability.UNREACHABLE:
            if address in self._web_rtc_manager.address_to_rtc_partners:
                self._web_rtc_manager.close_connection(address)
        else:
            raise TypeError(f'Unexpected reachability state "{reachability}".')

        assert self._raiden_service is not None, "_raiden_service not set"

    def _sign(self, data: bytes) -> bytes:
        """ Use eth_sign compatible hasher to sign matrix data """
        assert self._raiden_service is not None, "_raiden_service not set"
        return self._raiden_service.signer.sign(data=data)

    def retry_api_call(
        self,
        method_with_api_request: Callable,
        verify_response: Callable[[Any], bool] = lambda x: True,
        retries: int = JOIN_RETRIES,
        retry_interval: float = RETRY_INTERVAL,
        retry_interval_multiplier: float = RETRY_INTERVAL_MULTIPLIER,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        This method wraps around api calls to add a retry mechanism
        in case of failure or unsatisfying response

        Args:
            method_with_api_request: wrapped api call
            verify_response: verify response or try again
            retries: number of retries
            retry_interval: retry interval
            retry_interval_multiplier: multiplier to prolong the waiting interval
            *args: will be passed to method_with_api_request
            **kwargs: will be passed to method_with_api_request
        """
        return_value = None
        last_ex = None
        for _ in range(retries):
            try:
                return_value = method_with_api_request(*args, **kwargs)
                if verify_response(return_value):
                    return return_value
            except MatrixError as e:
                last_ex = e
            finally:
                if self._stop_event.wait(retry_interval):
                    return return_value  # noqa: B012
                retry_interval = retry_interval * retry_interval_multiplier

        if last_ex is None:
            return return_value
        raise last_ex


def populate_services_addresses(
    transport: MatrixTransport,
    service_registry: ServiceRegistry,
    block_identifier: BlockIdentifier,
) -> None:
    if service_registry is not None:
        services_addresses: Dict[Address, int] = dict()
        for index in range(service_registry.ever_made_deposits_len(block_identifier)):
            address = service_registry.ever_made_deposits(block_identifier, index)
            if address is None:
                continue
            if service_registry.has_valid_registration(block_identifier, address):
                services_addresses[address] = service_registry.proxy.functions.service_valid_till(
                    address
                ).call(block_identifier=block_identifier)
        transport.update_services_addresses(services_addresses)
