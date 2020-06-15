import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Counter as CounterType
from urllib.parse import urlparse
from uuid import uuid4

import gevent
import pkg_resources
import structlog
from eth_utils import is_binary_address, to_normalized_address
from gevent.event import Event
from gevent.lock import RLock
from gevent.pool import Pool
from gevent.queue import Empty, JoinableQueue
from matrix_client.errors import MatrixError, MatrixHttpLibError, MatrixRequestError

import raiden
from raiden.constants import EMPTY_SIGNATURE, MATRIX_AUTO_SELECT_SERVER, Environment
from raiden.exceptions import RaidenUnrecoverableError, TransportError
from raiden.messages.abstract import Message, RetrieableMessage, SignedRetrieableMessage
from raiden.messages.healthcheck import Ping, Pong
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.transport.matrix.client import (
    GMatrixClient,
    MatrixMessage,
    MatrixSyncMessages,
    Room,
    User,
)
from raiden.network.transport.matrix.utils import (
    JOIN_RETRIES,
    USER_PRESENCE_REACHABLE_STATES,
    AddressReachability,
    DisplayNameCache,
    MessageAckTimingKeeper,
    UserAddressManager,
    UserPresence,
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
from raiden.settings import MatrixTransportConfig
from raiden.storage.serialization import DictSerializer
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state import NetworkState, QueueIdsToQueues
from raiden.transfer.state_change import ActionChangeNodeNetworkState
from raiden.utils.formatting import to_checksum_address, to_hex_address
from raiden.utils.logging import redact_secret
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.utils.runnable import Runnable
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    AddressHex,
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


@dataclass
class MessagesQueue:
    queue_identifier: QueueIdentifier
    messages: List[Message]


class _RetryQueue(Runnable):
    """ A helper Runnable to send batched messages to receiver through transport """

    class _MessageData(NamedTuple):
        """ Small helper data structure for message queue """

        queue_identifier: QueueIdentifier
        message: Message
        text: str
        # generator that tells if the message should be sent now
        expiration_generator: Iterator[bool]

    def __init__(self, transport: "MatrixTransport", receiver: Address) -> None:
        self.transport = transport
        self.receiver = receiver
        self._message_queue: List[_RetryQueue._MessageData] = list()
        self._notify_event = gevent.event.Event()
        self._lock = gevent.lock.Semaphore()
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

    def enqueue(self, queue_identifier: QueueIdentifier, messages: List[Message]) -> None:
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
            for message in messages:
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
                    )
                    encoded_messages.append(data)

            self._message_queue.extend(encoded_messages)

        self.notify()

    def enqueue_unordered(self, message: Message) -> None:
        """ Helper to enqueue a message in the unordered queue. """
        self.enqueue(
            queue_identifier=QueueIdentifier(
                recipient=self.receiver, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
            ),
            messages=[message],
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
        status = self.transport._address_mgr.get_address_reachability(self.receiver)
        if status is not AddressReachability.REACHABLE:
            # if partner is not reachable, return
            self.log.debug(
                "Partner not reachable. Skipping.",
                partner=to_checksum_address(self.receiver),
                status=status,
            )
            return

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
            # below constants are defined in raiden.app.App.DEFAULT_CONFIG
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
        self._server_url = self._client.api.base_url
        self._server_name = urlparse(self._server_url).netloc

        self.greenlets: List[gevent.Greenlet] = list()

        self._address_to_retrier: Dict[Address, _RetryQueue] = dict()
        self._displayname_cache = DisplayNameCache()

        self._broadcast_rooms: Dict[str, Room] = dict()
        self._broadcast_queue: JoinableQueue[Tuple[str, Message]] = JoinableQueue()

        self._started = False
        self._starting = False

        self._stop_event: Event = Event()
        self._stop_event.set()
        self._healthcheck_queue = NotifyingQueue()

        self._broadcast_event = Event()
        self._prioritize_broadcast_messages: bool = True

        self._invite_queue: List[Tuple[RoomID, dict]] = []

        self._address_mgr: UserAddressManager = UserAddressManager(
            client=self._client,
            displayname_cache=self._displayname_cache,
            address_reachability_changed_callback=self._address_reachability_changed,
            user_presence_changed_callback=self._user_presence_changed,
            _log_context={"transport_uuid": str(self._uuid)},
        )

        self._address_to_room_ids: Dict[Address, List[RoomID]] = defaultdict(list)
        self._client.add_invite_listener(self._handle_invite)

        # Forbids concurrent room creation.
        self.room_creation_lock: Dict[Address, RLock] = defaultdict(RLock)

        self._counters: Dict[str, CounterType[Tuple[str, MessageID]]] = {}
        self._message_timing_keeper: Optional[MessageAckTimingKeeper] = None
        if environment is Environment.DEVELOPMENT:
            self._counters["send"] = Counter()
            self._counters["retry"] = Counter()
            self._counters["dispatch"] = Counter()
            self._message_timing_keeper = MessageAckTimingKeeper()

    def __repr__(self) -> str:
        if self._raiden_service is not None:
            node = f" node:{to_checksum_address(self._raiden_service.address)}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{self._uuid}>"

    def start(  # type: ignore
        self,
        raiden_service: "RaidenService",
        health_check_list: List[Address],
        prev_auth_data: Optional[str],
    ) -> None:
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.log.debug("Matrix starting")
        self._stop_event.clear()
        self._starting = True
        self._raiden_service = raiden_service

        self._address_mgr.start()

        try:
            login(
                client=self._client,
                signer=self._raiden_service.signer,
                prev_auth_data=prev_auth_data,
            )
        except ValueError:
            # `ValueError` may be raised if `get_user` provides invalid data to
            # the `User` constructor. This is either a bug in the login, that
            # tries to get the user after a failed login, or a bug in the
            # Matrix SDK.
            raise RaidenUnrecoverableError("Matrix SDK failed to properly set the userid")
        except MatrixHttpLibError:
            raise RaidenUnrecoverableError("The Matrix homeserver seems to be unavailable.")

        self.log = log.bind(
            current_user=self._user_id,
            node=to_checksum_address(self._raiden_service.address),
            transport_uuid=str(self._uuid),
        )

        self._initialize_broadcast_rooms()
        self._initialize_first_sync()
        self._initialize_health_check(health_check_list)
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

        # Handle any delayed invites in the future
        self._schedule_new_greenlet(self._process_queued_invites, in_seconds_from_now=1)
        self._schedule_new_greenlet(self._health_check_worker)

    def _process_queued_invites(self) -> None:
        if self._invite_queue:
            self.log.debug("Processing queued invites", queued_invites=len(self._invite_queue))
            for room_id, state in self._invite_queue:
                self._handle_invite(room_id, state)
            self._invite_queue.clear()

    def _run(self) -> None:  # type: ignore
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        assert self._raiden_service is not None, "_raiden_service not set"
        self.greenlet.name = (
            f"MatrixTransport._run node:{to_checksum_address(self._raiden_service.address)}"
        )
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
        """ Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception """
        if self._stop_event.ready():
            return
        self.log.debug("Matrix stopping")
        self._stop_event.set()
        self._broadcast_event.set()

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

        self._address_mgr.stop()
        self._client.stop()  # stop sync_thread, wait on client's greenlets

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

    def get_user_ids_for_address(self, address: Address) -> Set[str]:
        address_hex = to_normalized_address(address)
        candidates = self._client.search_user_directory(address_hex)
        self._displayname_cache.warm_users(candidates)
        user_ids = {
            user.user_id for user in candidates if validate_userid_signature(user) == address
        }
        return user_ids

    def force_check_address_reachability(self, address: Address) -> AddressReachability:
        """Force checks an address's reachability bypassing the whitelisting"""
        user_ids = self.get_user_ids_for_address(address)
        return self._address_mgr.get_reachability_from_matrix(user_ids)

    def async_start_health_check(self, node_address: Address) -> None:
        """
        Start healthcheck (status monitoring) for a peer
        also starts listening for messages
        Invites are accepted independently of healthchecking
        """
        self._healthcheck_queue.put(node_address)

    def immediate_health_check_for(self, node_address: Address) -> None:
        """ Start healthcheck (status monitoring) for a peer """
        is_health_information_available = (
            self._address_mgr.get_address_reachability(node_address)
            is not AddressReachability.UNKNOWN
        )

        if is_health_information_available:
            self.log.debug(
                "Healthcheck already enabled", peer_address=to_checksum_address(node_address)
            )
        else:
            self.log.debug("Healthcheck", peer_address=to_checksum_address(node_address))

            self._address_mgr.add_address(node_address)

            # Start the room creation early on. This reduces latency for channel
            # partners, by removing the latency of creating the room on the first
            # message.
            #
            # This does not reduce latency for target<->initiator communication,
            # since the target may be the node with lower address, and therefore
            # the node that has to create the room.
            self._maybe_create_room_for_address(node_address)

            # Ensure network state is updated in case we already know about the user presences
            # representing the target node
            user_ids = self.get_user_ids_for_address(node_address)
            self._address_mgr.track_address_presence(node_address, user_ids)

    def _health_check_worker(self) -> None:
        """ Worker to process healthcheck requests. """
        # Instead of busy-looping on the queue, this code used to use
        #
        #    gevent.wait({self._healthcheck_queue, self._stop_event}, count=1)
        #
        # Due to https://github.com/gevent/gevent/issues/1540 this caused AssertionErrors to be
        # printed during startup since, as soon as a node has open channels, the healthcheck
        # queue's internal event will always be already set before the first wait call here.
        #
        # Investigating this issue did suggest that apart from the exception printed on stderr
        # this seemed to have no other negative effects. However to make sure we changed the code
        # to it's current form.
        #
        # FIXME: Once the linked gevent bug has been fixed remove the busy loop and switch back to
        #        using `wait()` and remove the comment above.

        while True:
            try:
                self.immediate_health_check_for(self._healthcheck_queue.get(timeout=0.25))
            except Empty:
                pass
            if self._stop_event.is_set():
                self.log.debug("Health check worker exiting, stop is set")
                return

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
            for message in queue.messages:
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
                    redact_secret(DictSerializer.serialize(message)) for message in queue.messages
                ],
                queue_identifier=queue.queue_identifier,
            )

            self._send_with_retry(queue)

    def broadcast(self, room: str, message: Message) -> None:
        """Broadcast a message to a public room.

        These rooms aren't being listened on and therefore no reply could be heard, so these
        messages are sent in a send-and-forget async way.
        The actual room name is composed from the suffix given as parameter and chain name or id
        e.g.: raiden_ropsten_discovery
        Params:
            room: name suffix as passed in config['broadcast_rooms'] list
            message: Message instance to be serialized and sent
        """
        self._broadcast_queue.put((room, message))
        self._broadcast_event.set()

    def _broadcast_worker(self) -> None:
        def _broadcast(room_name: str, serialized_message: str) -> None:
            if not any(suffix in room_name for suffix in self._config.broadcast_rooms):
                raise RuntimeError(
                    f'Broadcast called on non-public room "{room_name}". '
                    f"Known public rooms: {self._config.broadcast_rooms}."
                )
            room_name = make_room_alias(self.chain_id, room_name)
            if room_name not in self._broadcast_rooms:
                room = join_broadcast_room(self._client, f"#{room_name}:{self._server_name}")
                self._broadcast_rooms[room_name] = room

            existing_room = self._broadcast_rooms.get(room_name)
            assert existing_room, f"Unknown broadcast room: {room_name!r}"

            self.log.debug(
                "Broadcast",
                room_name=room_name,
                room=existing_room,
                data=serialized_message.replace("\n", "\\n"),
            )
            existing_room.send_text(serialized_message)

        while not self._stop_event.ready():
            self._broadcast_event.clear()
            messages: Dict[str, List[Message]] = defaultdict(list)
            while self._broadcast_queue.qsize() > 0:
                room_name, message = self._broadcast_queue.get()
                messages[room_name].append(message)
            for room_name, messages_for_room in messages.items():
                serialized_messages = (
                    MessageSerializer.serialize(message) for message in messages_for_room
                )
                for message_batch in make_message_batches(serialized_messages):
                    _broadcast(room_name, message_batch)
                for _ in messages_for_room:
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

        # Call sync to fetch the inventory rooms and new invites, the sync
        # limit prevents fetching the messages.
        filter_id = self._client.create_sync_filter(
            not_rooms=self._broadcast_rooms.values(), limit=0
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
            partner_address = self._extract_addresses(room)
            # invalid rooms with multiple addresses should be left already
            msg = (
                "rooms with multiple partners should be left instantly "
                "after the join event arrives. "
                "This should be handled by member_join_callback()"
            )
            assert len(partner_address) <= 1, msg
            # should contain only one element which is the partner's address
            if len(partner_address) == 1 and partner_address[0] is not None:
                self._set_room_id_for_address(partner_address[0], room.room_id)

            self.log.debug(
                "Found room", room=room, aliases=room.aliases, members=room.get_joined_members()
            )

    def _leave_unexpected_rooms(
        self, rooms_to_leave: List[Room], reason: str = "No reason given"
    ) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"

        def to_string_representation(partner: Optional[Address]) -> str:
            if partner is not None:
                return to_checksum_address(partner)
            else:
                return "NoAddressUser"

        for room in rooms_to_leave:
            partners: List[Optional[Address]] = self._extract_addresses(room)
            self.log.warning(
                "Leaving Room",
                reason=reason,
                room_aliases=room.aliases,
                room_id=room.room_id,
                partners=[to_string_representation(partner) for partner in partners],
            )
            try:
                self.retry_api_call(room.leave)
            except MatrixRequestError as ex:
                raise TransportError("could not leave room due to MatrixRequestError") from ex

            # update address_to_room_ids (remove room_id for address)
            for valid_partner in [partner for partner in partners if partner is not None]:
                address_to_room_ids = self._get_room_ids_for_address(valid_partner)
                self._address_to_room_ids[valid_partner] = [
                    room_id for room_id in address_to_room_ids if room_id != room.room_id
                ]

    def _initialize_broadcast_rooms(self) -> None:
        msg = "To join the broadcast rooms the Matrix client to be properly authenticated."
        assert self._user_id, msg

        pool = Pool(size=10)

        def _join_broadcast_room(transport: MatrixTransport, room_name: str) -> None:
            broadcast_room_alias = f"#{room_name}:{transport._server_name}"
            transport.log.debug(
                "Joining broadcast room", broadcast_room_alias=broadcast_room_alias
            )
            transport._broadcast_rooms[room_name] = join_broadcast_room(
                client=transport._client, broadcast_room_alias=broadcast_room_alias
            )

        for suffix in self._config.broadcast_rooms:
            alias_prefix = make_room_alias(self.chain_id, suffix)

            if alias_prefix not in self._broadcast_rooms:
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
        assert self._broadcast_rooms, msg

        broadcast_filter_id = self._client.create_sync_filter(
            not_rooms=self._broadcast_rooms.values()
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

    def _initialize_health_check(self, health_check_list: List[Address]) -> None:
        msg = (
            "Healthcheck requires the Matrix client to be properly "
            "authenticated, because this may create the private rooms."
        )
        assert self._user_id, msg

        msg = (
            "Healthcheck must be initialized after the first sync, because "
            "that fetches the existing rooms from the Matrix server, and "
            "healthcheck may create rooms."
        )
        assert self._client.sync_iteration >= 1, msg

        pool = Pool(size=10)
        greenlets = set(
            pool.apply_async(self.immediate_health_check_for, [address])
            for address in health_check_list
        )
        gevent.joinall(greenlets, raise_error=True)

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

    def _handle_invite(self, room_id: RoomID, state: dict) -> None:
        """Handle an invite request.

        Always join a room, even if the partner is not whitelisted. That was
        previously done to prevent a malicious node from inviting and spamming
        the user. However, there are cases where nodes trying to create rooms
        for a channel might race and an invite would be received by one node
        which did not yet whitelist the inviting node, as a result the invite
        would wrongfully be ignored. This change removes the whitelist check.
        To prevent spam, we make sure we ignore presence updates and messages
        from non-whitelisted nodes.
        """
        if self._stop_event.ready():
            return

        if self._starting:
            self.log.debug("Queueing invite", room_id=room_id)
            self._invite_queue.append((room_id, state))
            return

        invite_events = [
            event
            for event in state["events"]
            if event["type"] == "m.room.member"
            and event["content"].get("membership") == "invite"
            and event["state_key"] == self._user_id
        ]

        if not invite_events or not invite_events[0]:
            self.log.debug("Invite: no invite event found", room_id=room_id)
            return  # there should always be one and only one invite membership event for us

        self.log.debug("Got invite", room_id=room_id)

        sender = invite_events[0]["sender"]
        user = self._client.get_user(sender)
        self._displayname_cache.warm_users([user])
        peer_address = validate_userid_signature(user)

        if not peer_address:
            self.log.debug(
                "Got invited to a room by invalid signed user - ignoring",
                room_id=room_id,
                user=user,
            )
            return

        sender_join_events = [
            event
            for event in state["events"]
            if event["type"] == "m.room.member"
            and event["content"].get("membership") == "join"
            and event["state_key"] == sender
        ]

        if not sender_join_events or not sender_join_events[0]:
            self.log.debug("Invite: no sender join event", room_id=room_id)
            return  # there should always be one and only one join membership event for the sender

        join_rules_events = [
            event for event in state["events"] if event["type"] == "m.room.join_rules"
        ]

        # room privacy as seen from the event
        private_room: bool = False
        if join_rules_events:
            join_rules_event = join_rules_events[0]
            private_room = join_rules_event["content"].get("join_rule") == "invite"

        # Ignore the room if it is not private, since that can be an attack
        # vector, e.g. secret reveal messages would be available to any user that
        # knows the room id. (only private rooms are used since ce246af806)
        # this also filters invites to broadcast rooms
        if private_room is False:
            self.log.debug("Invite: ignoring room since it is not private", room_id=room_id)
            return

        room = None
        # try to join the room
        try:
            room = self.retry_api_call(self._client.join_room, room_id_or_alias=room_id)
        except MatrixRequestError as ex:
            # this is catching invitation to room of invalid server -> rejecting the invite
            if ex.code == 404 and ex.content == {
                "errcode": "M_UNKNOWN",
                "error": "No known servers",
            }:
                # reject invite by "leaving" the room
                dummy_room = Room(self._client, room_id)
                self._leave_unexpected_rooms([dummy_room])

        assert room is not None, f"joining room {room} failed"

        self.log.debug(
            "Joined from invite",
            room_id=room_id,
            aliases=room.aliases,
            inviting_address=to_checksum_address(peer_address),
        )

        # room state may not populated yet, so we populate 'invite_only' from event
        room.invite_only = private_room
        self._set_room_id_for_address(address=peer_address, room_id=room_id)

    def _handle_member_join(self, room: Room) -> None:
        if self._is_broadcast_room(room):
            raise AssertionError(
                f"Broadcast room events should be filtered in syncs: {room.aliases}."
                f"Joined Broadcast Rooms: {list(self._broadcast_rooms.keys())}"
                f"Should be joined to: {self._config.broadcast_rooms}"
            )

        if self._has_multiple_partner_addresses(room):
            self._leave_unexpected_rooms(
                [room], "Users from more than one address joined the room"
            )

    def _handle_text(self, room: Room, message: MatrixMessage) -> List[Message]:
        """Handle a single Matrix message.

        The matrix message is expected to be a NDJSON, and each entry should be
        a valid JSON encoded Raiden message.

        Return::
            If any of the validations fail emtpy is returned, otherwise a list
            contained all parsed messages is returned.
        """

        is_valid_type = (
            message["type"] == "m.room.message" and message["content"]["msgtype"] == "m.text"
        )
        if not is_valid_type:
            return []

        # Ignore our own messages
        sender_id = message["sender"]
        if sender_id == self._user_id:
            return []

        user = self._client.get_user(sender_id)
        self._displayname_cache.warm_users([user])

        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "Ignoring message from user with an invalid display name signature",
                peer_user=user.user_id,
                room=room,
            )
            return []

        if self._is_broadcast_room(room):
            # This must not happen. Nodes must not listen on broadcast rooms.
            raise RuntimeError(
                f"Received message in broadcast room {room.aliases[0]}. Sending user: {user}"
            )

        if not self._address_mgr.is_address_known(peer_address):
            self.log.debug(
                "Ignoring message from non-whitelisted peer",
                sender=user,
                sender_address=to_checksum_address(peer_address),
                room=room,
            )
            return []

        # rooms we created and invited user, or we're invited specifically by them
        room_ids = self._get_room_ids_for_address(peer_address)

        if room.room_id not in room_ids:
            self.log.debug(
                "Ignoring invalid message",
                peer_user=user.user_id,
                peer_address=to_checksum_address(peer_address),
                room=room,
                expected_room_ids=room_ids,
                reason="unknown room for user",
            )
            return []

        return validate_and_parse_message(message["content"]["body"], peer_address)

    def _handle_sync_messages(self, sync_messages: MatrixSyncMessages) -> bool:
        """ Handle text messages sent to listening rooms """
        if self._stop_event.ready():
            return False

        assert self._raiden_service is not None, "_raiden_service not set"

        all_messages: List[Message] = list()
        for room, room_messages in sync_messages:
            # TODO: Don't fetch messages from the broadcast rooms. #5535
            if not self._is_broadcast_room(room):
                for text in room_messages:
                    all_messages.extend(self._handle_text(room, text))

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

        return len(all_messages) > 0

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

    def _send_raw(self, receiver_address: Address, data: str) -> None:
        room = self._get_room_for_address(receiver_address, require_online_peer=True)

        if room:
            self.log.debug(
                "Send raw",
                receiver=to_checksum_address(receiver_address),
                room=room,
                data=data.replace("\n", "\\n"),
            )
            room.send_text(data)
        else:
            # It is possible there is no room yet. This happens when:
            #
            # - The room creation is started by a background thread running
            # `whitelist`, and the room can be used by a another thread.
            # - The room should be created by the partner, and this node is waiting
            # on it.
            # - No user for the requested address is online
            #
            # This is not a problem since the messages are retried regularly.
            self.log.warning(
                "No room for receiver", receiver=to_checksum_address(receiver_address)
            )

    def _get_room_for_address(
        self, address: Address, require_online_peer: bool = False
    ) -> Optional[Room]:
        msg = (
            f"address not health checked: "
            f"node: {self._user_id}, "
            f"peer: {to_checksum_address(address)}"
        )
        assert address and self._address_mgr.is_address_known(address), msg

        room_candidates = []
        room_ids = self._get_room_ids_for_address(address)
        if room_ids:
            while room_ids:
                room_id = room_ids.pop(0)
                room = self._client.rooms[room_id]
                if self._is_broadcast_room(room):
                    self.log.warning(
                        "Ignoring broadcast room for peer",
                        room=room,
                        peer=to_checksum_address(address),
                    )
                    continue
                room_candidates.append(room)

        if room_candidates:
            if not require_online_peer:
                # Return the first existing room
                room = room_candidates[0]
                self.log.debug(
                    "Existing room",
                    room=room,
                    members=room.get_joined_members(),
                    require_online_peer=require_online_peer,
                )
                return room
            else:
                # The caller needs a room with a peer that is online
                online_userids = {
                    user_id
                    for user_id in self._address_mgr.get_userids_for_address(address)
                    if self._address_mgr.get_userid_presence(user_id)
                    in USER_PRESENCE_REACHABLE_STATES
                }
                while room_candidates:
                    room = room_candidates.pop(0)
                    has_online_peers = online_userids.intersection(
                        {user.user_id for user in room.get_joined_members()}
                    )
                    if has_online_peers:
                        self.log.debug(
                            "Existing room",
                            room=room,
                            members=room.get_joined_members(),
                            require_online_peer=require_online_peer,
                        )
                        return room

        return None

    def _maybe_create_room_for_address(self, address: Address) -> None:
        if self._stop_event.ready():
            return None

        if self._get_room_for_address(address):
            return None

        assert self._raiden_service is not None, "_raiden_service not set"

        # The rooms creation is asymetric, only the node with the lower
        # address is responsible to create the room. This fixes race conditions
        # were the two nodes try to create a room with each other at the same
        # time, leading to communications problems if the nodes choose a
        # different room.
        #
        # This does not introduce a new attack vector, since not creating the
        # room is the same as being unresponsive.
        room_creator_address = my_place_or_yours(
            our_address=self._raiden_service.address, partner_address=address
        )
        if self._raiden_service.address != room_creator_address:
            self.log.debug(
                "This node should not create the room",
                partner_address=to_checksum_address(address),
            )
            return None

        with self.room_creation_lock[address]:
            candidates = self._client.search_user_directory(to_normalized_address(address))
            self._displayname_cache.warm_users(candidates)

            partner_users = [
                user for user in candidates if validate_userid_signature(user) == address
            ]
            partner_user_ids = [user.user_id for user in partner_users]

            if not partner_users:
                self.log.error(
                    "Partner doesn't have a user", partner_address=to_checksum_address(address)
                )

                return None

            room = self._client.create_room(None, invitees=partner_user_ids, is_public=False)
            self.log.debug("Created private room", room=room, invitees=partner_users)

            self.log.debug(
                "Fetching room members", room=room, partner_address=to_checksum_address(address)
            )

            def partner_joined(fetched_members: Optional[List[User]]) -> bool:
                if fetched_members is None:
                    return False
                return any(member.user_id in partner_user_ids for member in fetched_members)

            members = self.retry_api_call(
                room.get_joined_members, verify_response=partner_joined, force_resync=True
            )

            assert members is not None, "fetching members failed"

            if not partner_joined(members):
                self.log.debug(
                    "Peer has not joined from invite yet, should join eventually",
                    room=room,
                    partner_address=to_checksum_address(address),
                    retry_interval=RETRY_INTERVAL,
                )

            # Here, the list of valid user ids is composed of
            # all known partner user ids along with our own.
            # If our partner roams, the user will be invited to
            # the room, resulting in multiple user ids for the partner.
            # If we roam, a new user and room will be created and only
            # the new user shall be in the room.
            valid_user_ids = partner_user_ids + [self._client.user_id]
            has_unexpected_user_ids = any(
                member.user_id not in valid_user_ids for member in members
            )

            if has_unexpected_user_ids:
                self._leave_unexpected_rooms([room], "Private room has unexpected participants")
                return None

            self._address_mgr.add_userids_for_address(
                address, {user.user_id for user in partner_users}
            )

            self._set_room_id_for_address(address, room.room_id)

            self.log.debug("Channel room", peer_address=to_checksum_address(address), room=room)
            return room

    def _is_broadcast_room(self, room: Room) -> bool:
        return any(
            suffix in room_alias
            for suffix in self._config.broadcast_rooms
            for room_alias in room.aliases
        )

    def _user_presence_changed(self, user: User, _presence: UserPresence) -> None:
        # maybe inviting user used to also possibly invite user's from presence changes
        assert self._raiden_service is not None, "_raiden_service not set"
        greenlet = self._schedule_new_greenlet(self._maybe_invite_user, user)
        greenlet.name = (
            f"invite node:{to_checksum_address(self._raiden_service.address)} user:{user}"
        )

    def _address_reachability_changed(
        self, address: Address, reachability: AddressReachability
    ) -> None:
        if reachability is AddressReachability.REACHABLE:
            node_reachability = NetworkState.REACHABLE
            # _QueueRetry.notify when partner comes online
            retrier = self._address_to_retrier.get(address)
            if retrier:
                retrier.notify()
        elif reachability is AddressReachability.UNKNOWN:
            node_reachability = NetworkState.UNKNOWN
        elif reachability is AddressReachability.UNREACHABLE:
            node_reachability = NetworkState.UNREACHABLE
        else:
            raise TypeError(f'Unexpected reachability state "{reachability}".')

        assert self._raiden_service is not None, "_raiden_service not set"
        state_change = ActionChangeNodeNetworkState(address, node_reachability)
        self._raiden_service.handle_and_track_state_changes([state_change])

    def _maybe_invite_user(self, user: User) -> None:
        """ Invite user if necessary.

        - Only the node with the smallest address should do
          the invites, just like the rule to
          prevent race conditions while creating the room.

        - Invites are necessary for roaming, when the higher
          address node roams, a new user is created. Therefore, the new
          user will not be in the room because the room is private.
          This newly created user has to be invited.
        """
        msg = "Invite user must not be called on a non-started transport"
        assert self._raiden_service is not None, msg

        peer_address = validate_userid_signature(user)
        if not peer_address:
            return

        room_ids = self._get_room_ids_for_address(peer_address)
        if not room_ids:
            return

        if len(room_ids) >= 2:
            # TODO: Handle malicious partner creating
            # and additional room.
            # This cannot lead to loss of funds,
            # it is just unexpected behavior.
            self.log.debug(
                "Multiple rooms exist with peer",
                peer_address=to_checksum_address(peer_address),
                rooms=room_ids,
            )

        inviter = my_place_or_yours(
            our_address=self._raiden_service.address, partner_address=peer_address
        )
        if inviter != self._raiden_service.address:
            self.log.debug(
                "This node is not the inviter", inviter=to_checksum_address(peer_address)
            )
            return

        room = self._client.rooms[room_ids[0]]

        if not room._members:
            room.get_joined_members(force_resync=True)

        if user.user_id not in room._members:
            self.log.debug(
                "Inviting", peer_address=to_checksum_address(peer_address), user=user, room=room
            )
            try:
                room.invite_user(user.user_id)
            except (json.JSONDecodeError, MatrixRequestError):
                self.log.warning(
                    "Exception inviting user, maybe their server is not healthy",
                    peer_address=to_checksum_address(peer_address),
                    user=user,
                    room=room,
                    exc_info=True,
                )

    def _sign(self, data: bytes) -> bytes:
        """ Use eth_sign compatible hasher to sign matrix data """
        assert self._raiden_service is not None, "_raiden_service not set"
        return self._raiden_service.signer.sign(data=data)

    def _set_room_id_for_address(self, address: Address, room_id: RoomID) -> None:

        assert not room_id or room_id in self._client.rooms, "Invalid room_id"

        room_ids = self._get_room_ids_for_address(address)

        # push to front
        room_ids = [room_id] + [r for r in room_ids if r != room_id]
        self._address_to_room_ids[address] = room_ids

    def _get_room_ids_for_address(self, address: Address) -> List[RoomID]:
        address_hex: AddressHex = to_hex_address(address)
        room_ids = self._address_to_room_ids[address]

        self.log.debug("Room ids for address", for_address=address_hex, room_ids=room_ids)

        return [
            room_id
            for room_id in room_ids
            if room_id in self._client.rooms and self._client.rooms[room_id].invite_only
        ]

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
