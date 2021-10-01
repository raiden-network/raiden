import asyncio
import itertools
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from json import JSONDecodeError
from random import randint
from typing import TYPE_CHECKING, Counter as CounterType
from urllib.parse import urlparse
from uuid import uuid4

import gevent
import structlog
from eth_utils import encode_hex, is_binary_address, to_normalized_address
from gevent.event import Event
from gevent.queue import JoinableQueue
from matrix_client.errors import MatrixHttpLibError
from web3.types import BlockIdentifier

from raiden.constants import (
    EMPTY_SIGNATURE,
    MATRIX_AUTO_SELECT_SERVER,
    CommunicationMedium,
    DeviceIDs,
    Environment,
    MatrixMessageType,
)
from raiden.exceptions import RaidenUnrecoverableError, TransportError
from raiden.messages.abstract import Message, RetrieableMessage, SignedRetrieableMessage
from raiden.messages.healthcheck import Ping, Pong
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.pathfinding import PFSProxy
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.transport.matrix.client import (
    GMatrixClient,
    MatrixMessage,
    ReceivedCallMessage,
    ReceivedRaidenMessage,
)
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.network.transport.matrix.utils import (
    DisplayNameCache,
    MessageAckTimingKeeper,
    UserPresence,
    address_from_userid,
    capabilities_schema,
    get_user_id_from_metadata,
    login,
    make_client,
    make_message_batches,
    make_user_id,
    validate_and_parse_message,
    validate_userid_signature,
)
from raiden.network.transport.utils import timeout_exponential_backoff
from raiden.settings import MatrixTransportConfig
from raiden.storage.serialization import DictSerializer
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state import QueueIdsToQueues
from raiden.utils.capabilities import capconfig_to_dict
from raiden.utils.formatting import to_checksum_address
from raiden.utils.logging import redact_secret
from raiden.utils.runnable import Runnable
from raiden.utils.system import get_system_spec
from raiden.utils.tracing import matrix_client_enable_requests_tracing
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
    Set,
    Tuple,
    UserID,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)


# A RetryQueue is considered idle after this many iterations without a message
RETRY_QUEUE_IDLE_AFTER = 10

SET_PRESENCE_INTERVAL = 60


@dataclass
class MessagesQueue:
    queue_identifier: QueueIdentifier
    messages: List[Tuple[Message, Optional[AddressMetadata]]]


def _metadata_key_func(message_data: "_RetryQueue._MessageData") -> str:
    address_metadata = message_data.address_metadata
    if address_metadata is None:
        return ""
    uid = address_metadata.get("user_id", "")
    return uid


class _RetryQueue(Runnable):
    """A helper Runnable to send batched messages to receiver through transport"""

    class _MessageData(NamedTuple):
        """Small helper data structure for message queue"""

        queue_identifier: QueueIdentifier
        message: Message
        text: str
        # generator that tells if the message should be sent now
        expiration_generator: Iterator[bool]
        address_metadata: Optional[AddressMetadata]

    def __init__(self, transport: "MatrixTransport", receiver: Address) -> None:
        self.transport = transport
        self.receiver = receiver
        self._message_queue: List[_RetryQueue._MessageData] = []
        self._notify_event = gevent.event.Event()
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
        """Enqueue a message to be sent, and notify main loop"""
        msg = (
            f"queue_identifier.recipient ({to_checksum_address(queue_identifier.recipient)}) "
            f" must match self.receiver ({to_checksum_address(self.receiver)})."
        )
        assert queue_identifier.recipient == self.receiver, msg

        timeout_generator = timeout_exponential_backoff(
            self.transport._config.retries_before_backoff,
            self.transport._config.retry_interval_initial,
            self.transport._config.retry_interval_max,
        )

        encoded_messages = []
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
        """Helper to enqueue a message in the unordered queue."""
        self.enqueue(
            queue_identifier=QueueIdentifier(
                recipient=self.receiver, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
            ),
            messages=[(message, address_metadata)],
        )

    def notify(self) -> None:
        """Notify main loop to check if anything needs to be sent"""
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

        # batch by user_id, so that we can potentially combine data for send-to-device calls
        queue_by_user_id = sorted(self._message_queue[:], key=_metadata_key_func)
        for user_id, batch in itertools.groupby(queue_by_user_id, _metadata_key_func):
            message_data_batch = list(batch)
            if user_id == "":
                address_metadata = None
            else:
                # simply use the first metadata in the list, event though
                # there could be discrepancies along the batch
                address_metadata = message_data_batch[0].address_metadata

            message_texts: List[str] = []
            for message_data in message_data_batch:
                # Messages are sent on two conditions:
                # - Non-retryable (e.g. Delivered)
                #   - Those are immediately remove from the local queue
                #     since they are only sent once
                # - Retryable
                #   - Those are retried according to their retry generator
                #     as long as they haven't been
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
                    self.transport._send_raw(
                        self.receiver, message_batch, receiver_metadata=address_metadata
                    )

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
    log = log

    def __init__(
        self,
        config: MatrixTransportConfig,
        environment: Environment,
        enable_tracing: Optional[bool] = False,
    ) -> None:
        super().__init__()
        self._uuid = uuid4()
        self._config = config
        self._environment = environment
        self._raiden_service: Optional["RaidenService"] = None
        self._web_rtc_manager: Optional[WebRTCManager] = None

        if config.server == MATRIX_AUTO_SELECT_SERVER:
            homeserver_candidates = config.available_servers
        elif urlparse(config.server).scheme in {"http", "https"}:
            # When an explicit server is given we don't need to do the RTT check on all others
            homeserver_candidates = [config.server]
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

        version = get_system_spec()["raiden"]
        self._client: GMatrixClient = make_client(
            self._handle_messages,
            homeserver_candidates,
            http_pool_maxsize=4,
            http_retry_timeout=40,
            http_retry_delay=_http_retry_delay,
            environment=environment,
            user_agent=f"Raiden {version}",
        )

        if enable_tracing:
            matrix_client_enable_requests_tracing(self._client)

        self.server_url = self._client.api.base_url
        self._server_name = urlparse(self.server_url).netloc
        # FIXME this will not update the servers while Raiden is running,
        #  thus to-device user-id fallback will only try to send to those home-servers that
        #  are fetched during config time
        #  this fixme is about servers joining the federation during runtime of a raiden node
        self._all_server_names = {self._server_name}
        for server_url in config.available_servers:
            self._all_server_names.add(urlparse(server_url).netloc)
        # This shouldn't happen since at least we should know our server
        msg = "There needs to be at least one matrix server known."
        assert self._all_server_names, msg

        self.greenlets: List[gevent.Greenlet] = []

        self._address_to_retrier: Dict[Address, _RetryQueue] = {}
        self._displayname_cache = DisplayNameCache()

        self._broadcast_queue: JoinableQueue[Tuple[str, Message]] = JoinableQueue()

        self._started = False

        self._stop_event: Event = Event()
        self._stop_event.set()

        self._broadcast_event = Event()
        self._prioritize_broadcast_messages: bool = True

        self._counters: Dict[str, CounterType[Tuple[str, MessageID]]] = {}
        self._message_timing_keeper: Optional[MessageAckTimingKeeper] = None
        if environment is Environment.DEVELOPMENT:
            self._counters["send"] = Counter()
            self._counters["retry"] = Counter()
            self._counters["dispatch"] = Counter()
            self._message_timing_keeper = MessageAckTimingKeeper()

        self.services_addresses: Dict[Address, int] = {}

    @property
    def started(self) -> bool:
        return self._started

    def __repr__(self) -> str:
        if self._raiden_service is not None:
            node = f" node:{self.checksummed_address}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{self._uuid}>"

    @property
    def checksummed_address(self) -> Optional[AddressHex]:
        assert self._raiden_service is not None, "_raiden_service not set"

        address = self._node_address
        if address is None:
            return None
        return to_checksum_address(self._raiden_service.address)

    @property
    def _node_address(self) -> Optional[Address]:
        return self._raiden_service.address if self._raiden_service is not None else None

    @property
    def user_id(self) -> Optional[UserID]:
        address = self._node_address
        return make_user_id(address, self._server_name) if address is not None else None

    @property
    def displayname(self) -> str:
        if self._raiden_service is None:
            return ""
        signature_bytes = self._raiden_service.signer.sign(str(self.user_id).encode())
        return encode_hex(signature_bytes)

    @property
    def address_metadata(self) -> Optional[AddressMetadata]:
        cap_dict = capconfig_to_dict(self._config.capabilities_config)
        own_caps = capabilities_schema.dump({"capabilities": cap_dict})["capabilities"]
        own_user_id = self.user_id
        if own_user_id is None:
            return None
        return dict(user_id=own_user_id, capabilities=own_caps, displayname=self.displayname)

    def start(  # type: ignore
        self, raiden_service: "RaidenService", prev_auth_data: Optional[str]
    ) -> None:
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.log.debug("Matrix starting")
        self._stop_event.clear()
        self._raiden_service = raiden_service
        assert raiden_service.pfs_proxy is not None, "must be set"
        self._web_rtc_manager = WebRTCManager(
            raiden_service.address,
            self._process_raiden_messages,
            self._send_signaling_message,
            self._stop_event,
        )
        self._web_rtc_manager.greenlet.link_exception(self.on_error)

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
        self._initialize_first_sync()
        self._initialize_sync()

        # (re)start any _RetryQueue which was initialized before start
        for retrier in self._address_to_retrier.values():
            if not retrier:
                self.log.debug("Starting retrier", retrier=retrier)
                retrier.start()

        super().start()  # start greenlet
        self._started = True

        self.log.debug("Matrix started", config=self._config)

        self._schedule_new_greenlet(self._set_presence, UserPresence.ONLINE)

        chain_state = views.state_from_raiden(raiden_service)
        for neighbour in views.all_neighbour_nodes(chain_state):
            self.health_check_web_rtc(neighbour)

    def health_check_web_rtc(self, partner: Address) -> None:
        assert self._web_rtc_manager is not None, "must be set"
        if self._started and not self._web_rtc_manager.has_ready_channel(partner):
            self._web_rtc_manager.health_check(partner)

    def _set_presence(self, state: UserPresence) -> None:
        waiting_period = randint(SET_PRESENCE_INTERVAL // 4, SET_PRESENCE_INTERVAL)
        gevent.wait(  # pylint: disable=gevent-disable-wait
            {self._stop_event}, timeout=waiting_period
        )

        if self._stop_event.is_set():
            return
        self._client.set_presence_state(state.value)

    def _run(self) -> None:  # type: ignore
        """Runnable main method, perform wait on long-running subtasks"""
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

    def stop(self) -> None:
        """Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception"""
        if self._stop_event.ready():
            return
        self._started = False
        self.log.debug("Matrix stopping")
        # Ensure, we send all broadcast messages before shutting down
        self._broadcast_queue.join()
        self._stop_event.set()
        self._broadcast_event.set()

        assert self._web_rtc_manager is not None, "must be set"
        self._web_rtc_manager.stop()
        self._web_rtc_manager = None

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
                    self._multicast_services(data=message_batch, device_id=device_id)
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

        self._client.last_sync = float("inf")
        self._client.blocking_sync(
            timeout_ms=self._config.sync_timeout, latency_ms=self._config.sync_latency
        )

    def _initialize_sync(self) -> None:
        msg = "_initialize_sync requires the GMatrixClient to be properly authenticated."
        assert self._user_id, msg

        msg = "The sync thread must not be started twice"
        assert self._client.sync_worker is None, msg
        assert self._client.message_worker is None, msg

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

    def _validate_matrix_messages(
        self, messages: List[MatrixMessage]
    ) -> Tuple[List[ReceivedRaidenMessage], List[ReceivedCallMessage]]:
        assert self._raiden_service is not None, "_raiden_service not set"

        raiden_messages: List[ReceivedRaidenMessage] = []
        call_messages: List[ReceivedCallMessage] = []

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
            if peer_address is None:
                self.log.debug(
                    "Ignoring message from user with an invalid display name signature",
                    peer_user=user.user_id,
                )
                continue

            sender_metadata: AddressMetadata = dict(user_id=UserID(sender_id))
            if is_raiden_message:
                for parsed_message in validate_and_parse_message(
                    message["content"]["body"], peer_address
                ):
                    raiden_message = ReceivedRaidenMessage(
                        message=parsed_message,
                        sender=peer_address,
                        sender_metadata=sender_metadata,
                    )
                    raiden_messages.append(raiden_message)
            if is_call_message:
                call_message = ReceivedCallMessage(
                    message=message,
                    sender=peer_address,
                )
                call_messages.append(call_message)
        return raiden_messages, call_messages

    def _process_raiden_messages(self, all_messages: List[ReceivedRaidenMessage]) -> None:
        assert self._raiden_service is not None, "_process_messages must be called after start"
        if self._stop_event.is_set():
            return

        incoming_messages: List[Message] = []
        # Remove this #3254
        for received_message in all_messages:
            message = received_message.message
            incoming_messages.append(message)
            if isinstance(message, (Processed, SignedRetrieableMessage)) and message.sender:
                delivered_message = Delivered(
                    delivered_message_identifier=message.message_identifier,
                    signature=EMPTY_SIGNATURE,
                )
                self._raiden_service.sign(delivered_message)
                retrier = self._get_retrier(message.sender)
                retrier.enqueue_unordered(
                    delivered_message, address_metadata=received_message.sender_metadata
                )
            if self._environment is Environment.DEVELOPMENT:
                if isinstance(message, RetrieableMessage):
                    self._counters["dispatch"][
                        (message.__class__.__name__, message.message_identifier)
                    ] += 1
                if isinstance(message, Processed):
                    assert self._message_timing_keeper is not None, MYPY_ANNOTATION
                    self._message_timing_keeper.finalize_message(message)
        self.log.debug("Incoming messages", messages=incoming_messages)

        self._raiden_service.on_messages(incoming_messages)

    def _handle_messages(self, messages: List[MatrixMessage]) -> bool:
        """Handle text messages"""
        if self._stop_event.ready():
            return False

        if not self.started:
            return False

        assert self._raiden_service is not None, "_raiden_service not set"

        raiden_messages, call_messages = self._validate_matrix_messages(messages)
        self._process_raiden_messages(raiden_messages)
        self._process_call_messages(call_messages)
        return len(raiden_messages) > 0 or len(call_messages) > 0

    def _process_call_messages(self, call_messages: List[ReceivedCallMessage]) -> None:
        """
        This function handles incoming signalling messages (in matrix called 'call' events).
        In Raiden 'm.room.message' events are used as the communication format.
        Main function is to forward it to the aiortc library to establish connections.
        Messages contain sdp messages to follow the ROAP (RTC Offer Answer Protocol).
        Args:
            call_messages: List of signalling messages
        """

        if self._stop_event.is_set():
            return

        assert self._web_rtc_manager is not None, "must be set"

        for received_message in call_messages:
            call_message = received_message.message
            partner_address = received_message.sender
            try:
                content = json.loads(call_message["content"]["body"])
                rtc_message_type = content["type"]
            except (KeyError, JSONDecodeError):
                self.log.warning(
                    "Malformed signaling message",
                    partner_address=partner_address,
                    content=call_message["content"]["body"],
                )
            else:
                self.log.debug(
                    "Received signaling message",
                    partner_address=to_checksum_address(partner_address),
                    type=rtc_message_type,
                    content=content,
                )
                self._web_rtc_manager.process_signaling_message(
                    partner_address, rtc_message_type, content
                )

    def _get_retrier(self, receiver: Address) -> _RetryQueue:
        """Construct and return a _RetryQueue for receiver"""
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
        recipient = queue.queue_identifier.recipient
        retrier = self._get_retrier(recipient)
        retrier.enqueue(queue_identifier=queue.queue_identifier, messages=queue.messages)
        if self.started:
            self.health_check_web_rtc(recipient)

    def _multicast_services(
        self,
        data: str,
        device_id: str = "*",
    ) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"

        user_ids = {make_user_id(addr, self._server_name) for addr in self.services_addresses}
        return self._send_to_device_raw(user_ids, data, device_id)

    def _send_to_device_raw(
        self,
        user_ids: Set[UserID],
        data: str,
        device_id: str = "*",
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
    ) -> None:
        # Sends data to multiple users via to-device in a single Matrix API call
        assert self._raiden_service is not None, "_raiden_service not set"

        messages = {
            user_id: {device_id: {"msgtype": message_type.value, "body": data}}
            for user_id in user_ids
        }

        self.log.debug(
            "Send to-device message",
            device_id=device_id,
            receivers=user_ids,
            multicast=bool(len(user_ids) > 1),
            data=data.replace("\n", "\\n"),
        )

        self._client.api.send_to_device(event_type="m.room.message", messages=messages)

    def _send_raw(
        self,
        receiver_address: Address,
        data: str,
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
        receiver_metadata: AddressMetadata = None,
    ) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"
        if self._stop_event.ready():
            return

        assert self._web_rtc_manager is not None, "must be set"

        user_ids: Set[UserID] = set()
        if self._web_rtc_manager.has_ready_channel(receiver_address):
            communication_medium = CommunicationMedium.WEB_RTC
        else:
            user_id = get_user_id_from_metadata(receiver_address, receiver_metadata)
            # Don't check whether the to-device capability is set -
            # this will only happen for older, incompatible clients that
            # will simply ignore our communication attempt
            communication_medium = CommunicationMedium.TO_DEVICE
            if user_id is None:
                self.log.error(
                    "Cannot send raw message without address metadata.",
                    receiver=to_checksum_address(receiver_address),
                    send_medium=communication_medium.value,
                    data=data.replace("\n", "\\n"),
                )
                return
            else:
                user_ids.add(user_id)

        self.log.debug(
            "Send raw message",
            receiver=to_checksum_address(receiver_address),
            send_medium=communication_medium.value,
            data=data.replace("\n", "\\n"),
        )

        if communication_medium is CommunicationMedium.WEB_RTC:
            # if we already have a webrtc channel ready, the address-metadata doesn't matter
            self._web_rtc_manager.send_message(receiver_address, data)
            return
        else:
            msg = "Only to-device messages are supported other than web-rtc"
            assert communication_medium is CommunicationMedium.TO_DEVICE, msg
            self._send_to_device_raw(
                user_ids=user_ids,
                device_id=DeviceIDs.RAIDEN.value,
                message_type=message_type,
                data=data,
            )
            return

    def _send_signaling_message(self, address: Address, message: str) -> None:
        assert self._raiden_service is not None, "must be set"
        metadata = _query_metadata(self._raiden_service.pfs_proxy, address)
        self._send_raw(address, message, MatrixMessageType.NOTICE, metadata)


def _query_metadata(pfs_proxy: PFSProxy, address: Address) -> Optional[AddressMetadata]:
    try:
        metadata = pfs_proxy.query_address_metadata(address)
    except Exception as e:
        log.warning("Can't query metadata", reason=str(e))
    else:
        return metadata
    return None


def populate_services_addresses(
    transport: MatrixTransport,
    service_registry: ServiceRegistry,
    block_identifier: BlockIdentifier,
) -> None:
    if service_registry is not None:
        services_addresses: Dict[Address, int] = {}
        for index in range(service_registry.ever_made_deposits_len(block_identifier)):
            address = service_registry.ever_made_deposits(block_identifier, index)
            if address is None:
                continue
            if service_registry.has_valid_registration(block_identifier, address):
                services_addresses[address] = service_registry.proxy.functions.service_valid_till(
                    address
                ).call(block_identifier=block_identifier)
        transport.update_services_addresses(services_addresses)
