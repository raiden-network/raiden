import json
import time
from collections import defaultdict
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from uuid import uuid4

import gevent
import structlog
from eth_utils import is_binary_address, to_checksum_address, to_normalized_address
from gevent.event import Event
from gevent.lock import RLock, Semaphore
from gevent.pool import Pool
from gevent.queue import JoinableQueue
from matrix_client.errors import MatrixHttpLibError, MatrixRequestError

from raiden.constants import EMPTY_SIGNATURE
from raiden.exceptions import RaidenUnrecoverableError, TransportError
from raiden.messages.abstract import (
    Message,
    RetrieableMessage,
    SignedMessage,
    SignedRetrieableMessage,
)
from raiden.messages.healthcheck import Ping, Pong
from raiden.messages.matrix import ToDevice
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.transport.matrix.client import GMatrixClient, Room, User
from raiden.network.transport.matrix.utils import (
    JOIN_RETRIES,
    AddressReachability,
    DisplayNameCache,
    UserAddressManager,
    UserPresence,
    join_broadcast_room,
    login,
    make_client,
    make_room_alias,
    my_place_or_yours,
    validate_and_parse_message,
    validate_userid_signature,
)
from raiden.network.transport.utils import timeout_exponential_backoff
from raiden.storage.serialization import DictSerializer
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state import NetworkState, QueueIdsToQueues
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionUpdateTransportAuthData,
)
from raiden.utils.logging import redact_secret
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
    NamedTuple,
    NewType,
    Optional,
    Tuple,
    Union,
    cast,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)

_RoomID = NewType("_RoomID", str)
# Combined with 10 retries (``..utils.JOIN_RETRIES``) this will give a total wait time of ~15s
ROOM_JOIN_RETRY_INTERVAL = 0.1
ROOM_JOIN_RETRY_INTERVAL_MULTIPLIER = 1.55


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

    def enqueue(self, queue_identifier: QueueIdentifier, message: Message) -> None:
        """ Enqueue a message to be sent, and notify main loop """
        assert queue_identifier.recipient == self.receiver
        with self._lock:
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
                return
            timeout_generator = timeout_exponential_backoff(
                self.transport._config["retries_before_backoff"],
                self.transport._config["retry_interval"],
                self.transport._config["retry_interval"] * 10,
            )
            expiration_generator = self._expiration_generator(timeout_generator)
            self._message_queue.append(
                _RetryQueue._MessageData(
                    queue_identifier=queue_identifier,
                    message=message,
                    text=MessageSerializer.serialize(message),
                    expiration_generator=expiration_generator,
                )
            )
        self.notify()

    def enqueue_unordered(self, message: Message) -> None:
        """ Helper to enqueue a message in the unordered queue. """
        self.enqueue(
            queue_identifier=QueueIdentifier(
                recipient=self.receiver, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
            ),
            message=message,
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

        # On startup protocol messages must be sent only after the monitoring
        # services are updated. For more details refer to the method
        # `RaidenService._initialize_monitoring_services_queue`
        if self.transport._prioritize_broadcast_messages:
            self.transport._broadcast_queue.join()

        self.log.debug("Retrying message", receiver=to_checksum_address(self.receiver))
        status = self.transport._address_mgr.get_address_reachability(self.receiver)
        if status is not AddressReachability.REACHABLE:
            # if partner is not reachable, return
            self.log.debug(
                "Partner not reachable. Skipping.",
                partner=to_checksum_address(self.receiver),
                status=status,
            )
            return

        message_texts = [
            data.text
            for data in self._message_queue
            # if expired_gen generator yields False, message was sent recently, so skip it
            if next(data.expiration_generator)
        ]

        def message_is_in_queue(data: _RetryQueue._MessageData) -> bool:
            return any(
                isinstance(data.message, RetrieableMessage)
                and send_event.message_identifier == data.message.message_identifier
                for send_event in self.transport._queueids_to_queues[data.queue_identifier]
            )

        # clean after composing, so any queued messages (e.g. Delivered) are sent at least once
        for msg_data in self._message_queue[:]:
            remove = False
            if isinstance(msg_data.message, (Delivered, Ping, Pong)):
                # e.g. Delivered, send only once and then clear
                # TODO: Is this correct? Will a missed Delivered be 'fixed' by the
                #       later `Processed` message?
                remove = True
            elif msg_data.queue_identifier not in self.transport._queueids_to_queues:
                remove = True
                self.log.debug(
                    "Stopping message send retry",
                    queue=msg_data.queue_identifier,
                    message=msg_data.message,
                    reason="Raiden queue is gone",
                )
            elif not message_is_in_queue(msg_data):
                remove = True
                self.log.debug(
                    "Stopping message send retry",
                    queue=msg_data.queue_identifier,
                    message=msg_data.message,
                    reason="Message was removed from queue",
                )

            if remove:
                self._message_queue.remove(msg_data)

        if message_texts:
            self.log.debug(
                "Send", receiver=to_checksum_address(self.receiver), messages=message_texts
            )
            self.transport._send_raw(self.receiver, "\n".join(message_texts))

    def _run(self) -> None:  # type: ignore
        msg = f"_RetryQueue started before transport._raiden_service is set"
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
                    self._check_and_send()
            # wait up to retry_interval (or to be notified) before checking again
            self._notify_event.wait(self.transport._config["retry_interval"])

    def __str__(self) -> str:
        return self.greenlet.name

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} for {to_normalized_address(self.receiver)}>"


class MatrixTransport(Runnable):
    _room_prefix = "raiden"
    _room_sep = "_"
    log = log

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__()
        self._uuid = uuid4()
        self._config = config
        self._raiden_service: Optional["RaidenService"] = None

        if config["server"] == "auto":
            available_servers = config["available_servers"]
        elif urlparse(config["server"]).scheme in {"http", "https"}:
            available_servers = [config["server"]]
        else:
            raise TransportError('Invalid matrix server specified (valid values: "auto" or a URL)')

        def _http_retry_delay() -> Iterable[float]:
            # below constants are defined in raiden.app.App.DEFAULT_CONFIG
            return timeout_exponential_backoff(
                config["retries_before_backoff"],
                config["retry_interval"] / 5,
                config["retry_interval"],
            )

        self._client: GMatrixClient = make_client(
            available_servers,
            http_pool_maxsize=4,
            http_retry_timeout=40,
            http_retry_delay=_http_retry_delay,
        )
        self._server_url = self._client.api.base_url
        self._server_name = config.get("server_name", urlparse(self._server_url).netloc)

        self.greenlets: List[gevent.Greenlet] = list()

        self._address_to_retrier: Dict[Address, _RetryQueue] = dict()
        self._displayname_cache = DisplayNameCache()

        self._broadcast_rooms: Dict[str, Optional[Room]] = dict()
        self._broadcast_queue: JoinableQueue[Tuple[str, Message]] = JoinableQueue()

        self._started = False
        self._starting = False

        self._stop_event = Event()
        self._stop_event.set()

        self._broadcast_event = Event()
        self._prioritize_broadcast_messages = True

        self._invite_queue: List[Tuple[_RoomID, dict]] = []

        self._address_mgr: UserAddressManager = UserAddressManager(
            client=self._client,
            displayname_cache=self._displayname_cache,
            address_reachability_changed_callback=self._address_reachability_changed,
            user_presence_changed_callback=self._user_presence_changed,
            _log_context={"transport_uuid": str(self._uuid)},
        )

        self._client.add_invite_listener(self._handle_invite)
        self._client.add_listener(self._handle_to_device_message, event_type="to_device")

        self._health_lock = Semaphore()
        self._account_data_lock = Semaphore()

        # Forbids concurrent room creation.
        self.room_creation_lock: Dict[Address, RLock] = defaultdict(RLock)

    def __repr__(self) -> str:
        if self._raiden_service is not None:
            node = f" node:{to_checksum_address(self._raiden_service.address)}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{self._uuid}>"

    def start(  # type: ignore
        self,
        raiden_service: "RaidenService",
        whitelist: List[Address],
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

        self._join_broadcast_rooms()
        self._inventory_rooms()

        def on_success(greenlet: gevent.Greenlet) -> None:
            if greenlet in self.greenlets:
                self.greenlets.remove(greenlet)

        self._client.start_listener_thread()
        assert isinstance(self._client.sync_thread, gevent.Greenlet)
        self._client.sync_thread.link_exception(self.on_error)
        self._client.sync_thread.link_value(on_success)
        self.greenlets = [self._client.sync_thread]

        self._client.set_presence_state(UserPresence.ONLINE.value)

        # (re)start any _RetryQueue which was initialized before start
        for retrier in self._address_to_retrier.values():
            if not retrier:
                self.log.debug("Starting retrier", retrier=retrier)
                retrier.start()

        super().start()  # start greenlet
        self._starting = False
        self._started = True

        pool = Pool(size=10)
        greenlets = set(pool.apply_async(self.whitelist, [address]) for address in whitelist)
        gevent.joinall(greenlets, raise_error=True)

        self.log.debug("Matrix started", config=self._config)

        # Handle any delayed invites in the future
        self._schedule_new_greenlet(self._process_queued_invites, in_seconds_from_now=1)

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
        state_change = ActionUpdateTransportAuthData(f"{self._user_id}/{self._client.api.token}")
        self.greenlet.name = (
            f"MatrixTransport._run node:{to_checksum_address(self._raiden_service.address)}"
        )
        self._raiden_service.handle_and_track_state_changes([state_change])
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

        # Wait for retriers to exit, then discard them
        gevent.wait({r.greenlet for r in self._address_to_retrier.values()})
        self._address_to_retrier = {}

        self._address_mgr.stop()
        self._client.stop()  # stop sync_thread, wait on client's greenlets

        # wait on own greenlets, no need to get on them, exceptions should be raised in _run()
        gevent.wait(self.greenlets)

        self._client.set_presence_state(UserPresence.OFFLINE.value)

        # Ensure keep-alive http connections are closed
        self._client.api.session.close()

        self.log.debug("Matrix stopped", config=self._config)
        try:
            del self.log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def whitelist(self, address: Address) -> None:
        """Whitelist `address` to accept its messages."""
        msg = (
            "Whitelisting can only be done after the Matrix client has been "
            "logged in. This is necessary because whitelisting will create "
            "the Matrix room."
        )
        assert self._user_id, msg

        self.log.debug("Whitelist", address=to_checksum_address(address))
        self._address_mgr.add_address(address)

        # Start the room creation early on. This reduces latency for channel
        # partners, because by removing the latency of creating the room on the
        # first message.
        #
        # This does not reduce latency for target<->initiator communication,
        # since the target may be the node with lower address, and therefore
        # the node that has to create the room.
        self._maybe_create_room_for_address(address)

    def start_health_check(self, node_address: Address) -> None:
        """Start healthcheck (status monitoring) for a peer

        It also whitelists the address to answer invites and listen for messages
        """
        self.whitelist(node_address)
        with self._health_lock:
            node_address_hex = to_normalized_address(node_address)
            self.log.debug("Healthcheck", peer_address=to_checksum_address(node_address))

            candidates = self._client.search_user_directory(node_address_hex)
            self._displayname_cache.warm_users(candidates)

            user_ids = {
                user.user_id
                for user in candidates
                if validate_userid_signature(user) == node_address
            }
            # Ensure network state is updated in case we already know about the user presences
            # representing the target node
            self._address_mgr.track_address_presence(node_address, user_ids)

    def send_async(self, queue_identifier: QueueIdentifier, message: Message) -> None:
        """Queue the message for sending to recipient in the queue_identifier

        It may be called before transport is started, to initialize message queues
        The actual sending is started only when the transport is started
        """
        # even if transport is not started, can run to enqueue messages to send when it starts
        receiver_address = queue_identifier.recipient

        if not is_binary_address(receiver_address):
            raise ValueError("Invalid address {}".format(to_checksum_address(receiver_address)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError(f"Do not use send_async for {message.__class__.__name__} messages")

        self.log.debug(
            "Send async",
            receiver_address=to_checksum_address(receiver_address),
            message=redact_secret(DictSerializer.serialize(message)),
            queue_identifier=queue_identifier,
        )

        self._send_with_retry(queue_identifier, message)

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
            if not any(suffix in room_name for suffix in self._config["broadcast_rooms"]):
                raise RuntimeError(
                    f'Broadcast called on non-public room "{room_name}". '
                    f'Known public rooms: {self._config["broadcast_rooms"]}.'
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
                message_text = "\n".join(
                    MessageSerializer.serialize(message) for message in messages_for_room
                )
                _broadcast(room_name, message_text)
                for _ in messages_for_room:
                    # Every message needs to be marked as done.
                    # Unfortunately there's no way to do that in one call :(
                    # https://github.com/gevent/gevent/issues/1436
                    self._broadcast_queue.task_done()

            # Stop prioritizing broadcast messages after initial queue has been emptied
            self._prioritize_broadcast_messages = False
            self._broadcast_event.wait(self._config["retry_interval"])

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

    def _join_broadcast_rooms(self) -> None:
        for suffix in self._config["broadcast_rooms"]:
            room_name = make_room_alias(self.chain_id, suffix)
            broadcast_room_alias = f"#{room_name}:{self._server_name}"
            self.log.debug("Joining broadcast room", broadcast_room_alias=broadcast_room_alias)
            self._broadcast_rooms[room_name] = join_broadcast_room(
                client=self._client, broadcast_room_alias=broadcast_room_alias
            )

    def _inventory_rooms(self) -> None:
        self.log.debug("Inventory rooms", rooms=self._client.rooms)

        msg = (
            "Fetching the inventory rooms require the node to be logged in with the Matrix server."
        )
        assert self._user_id, msg

        # Call sync to fetch the inventory rooms and new invites. At this point
        # the messages themselves should not be processed because the room
        # callbacks are not installed yet (this is done bellow). The sync limit
        # prevents fetching the messages.
        prev_sync_limit = self._client.set_sync_limit(0)
        self._client._sync()
        self._client.set_sync_limit(prev_sync_limit)

        # Wait on the thread from the sync above, to guarantee the rooms are
        # populated
        thread = self._client._handle_thread
        if thread:
            thread.get()

        for room in self._client.rooms.values():
            room_aliases = set(room.aliases)
            if room.canonical_alias:
                room_aliases.add(room.canonical_alias)
            room_alias_is_broadcast = any(
                broadcast_alias in room_alias
                for broadcast_alias in self._config["broadcast_rooms"]
                for room_alias in room_aliases
            )
            if room_alias_is_broadcast:
                continue
            # we add listener for all valid rooms, _handle_message should ignore them
            # if msg sender isn't whitelisted yet
            if not room.listeners:
                room.add_listener(self._handle_message, "m.room.message")
            self.log.debug(
                "Found room", room=room, aliases=room.aliases, members=room.get_joined_members()
            )

    def _handle_invite(self, room_id: _RoomID, state: dict) -> None:
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

        # we join room and _set_room_id_for_address despite room privacy and requirements,
        # _get_room_ids_for_address will take care of returning only matching rooms and
        # _leave_unused_rooms will clear it in the future, if and when needed
        room: Optional[Room] = None
        last_ex: Optional[Exception] = None
        retry_interval = 0.1
        for _ in range(JOIN_RETRIES):
            try:
                room = self._client.join_room(room_id)
            except MatrixRequestError as e:
                last_ex = e
                if self._stop_event.wait(retry_interval):
                    break
                retry_interval = retry_interval * 2
            else:
                break
        else:
            assert last_ex is not None
            raise last_ex  # re-raise if couldn't succeed in retries

        assert room is not None, f"joining room {room} failed"

        if not room.listeners:
            room.add_listener(self._handle_message, "m.room.message")

        # room state may not populated yet, so we populate 'invite_only' from event
        room.invite_only = private_room

        self._set_room_id_for_address(address=peer_address, room_id=room_id)

        self.log.debug(
            "Joined from invite",
            room_id=room_id,
            aliases=room.aliases,
            inviting_address=to_checksum_address(peer_address),
        )

    def _handle_message(self, room: Room, event: Dict[str, Any]) -> bool:
        """ Handle text messages sent to listening rooms """
        if self._stop_event.ready():
            return False

        is_valid_type = (
            event["type"] == "m.room.message" and event["content"]["msgtype"] == "m.text"
        )
        if not is_valid_type:
            return False

        sender_id = event["sender"]

        if sender_id == self._user_id:
            # Ignore our own messages
            return False

        user = self._client.get_user(sender_id)
        self._displayname_cache.warm_users([user])

        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "Ignoring message from user with an invalid display name signature",
                peer_user=user.user_id,
                room=room,
            )
            return False

        if not self._address_mgr.is_address_known(peer_address):
            self.log.debug(
                "Ignoring message from non-whitelisted peer",
                sender=user,
                sender_address=to_checksum_address(peer_address),
                room=room,
            )
            return False

        # rooms we created and invited user, or were invited specifically by them
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
            return False

        # TODO: With the condition in the TODO above restored this one won't have an effect, check
        #       if it can be removed after the above is solved
        if not room_ids or room.room_id != room_ids[0]:
            if self._is_broadcast_room(room):
                # This must not happen. Nodes must not listen on broadcast rooms.
                raise RuntimeError(f"Received message in broadcast room {room.aliases}.")
            self.log.debug(
                "Received message triggered new comms room for peer",
                peer_user=user.user_id,
                peer_address=to_checksum_address(peer_address),
                known_user_rooms=room_ids,
                room=room,
            )
            self._set_room_id_for_address(peer_address, room.room_id)

        messages = validate_and_parse_message(event["content"]["body"], peer_address)

        if not messages:
            return False

        self.log.debug(
            "Incoming messages",
            messages=messages,
            sender=to_checksum_address(peer_address),
            sender_user=user,
            room=room,
        )

        for message in messages:
            if not isinstance(message, (SignedRetrieableMessage, SignedMessage)):
                self.log.warning(
                    "Received invalid message",
                    message=redact_secret(DictSerializer.serialize(message)),
                )
            if isinstance(message, Delivered):
                self._receive_delivered(message)
            elif isinstance(message, Processed):
                self._receive_message(message)
            else:
                assert isinstance(message, SignedRetrieableMessage)
                self._receive_message(message)

        return True

    def _receive_delivered(self, delivered: Delivered) -> None:
        assert delivered.sender is not None, MYPY_ANNOTATION
        self.log.debug(
            "Delivered message received",
            sender=to_checksum_address(delivered.sender),
            message=DictSerializer.serialize(delivered),
        )

        assert self._raiden_service is not None, "_raiden_service not set"
        self._raiden_service.on_message(delivered)

    def _receive_message(self, message: Union[SignedRetrieableMessage, Processed]) -> None:
        assert self._raiden_service is not None, "_raiden_service not set"
        assert message.sender is not None, MYPY_ANNOTATION
        self.log.debug(
            "Message received",
            node=to_checksum_address(self._raiden_service.address),
            message=redact_secret(DictSerializer.serialize(message)),
            sender=to_checksum_address(message.sender),
        )

        # TODO: Maybe replace with Matrix read receipts.
        #       Unfortunately those work on an 'up to' basis, not on individual messages
        #       which means that message order is important which isn't guaranteed between
        #       federated servers.
        #       See: https://matrix.org/docs/spec/client_server/r0.3.0.html#id57
        delivered_message = Delivered(
            delivered_message_identifier=message.message_identifier, signature=EMPTY_SIGNATURE
        )
        self._raiden_service.sign(delivered_message)

        if message.sender:  # Ignore unsigned messages
            retrier = self._get_retrier(message.sender)
            retrier.enqueue_unordered(delivered_message)
            self._raiden_service.on_message(message)

    def _receive_to_device(self, to_device: ToDevice) -> None:
        assert to_device.sender is not None, MYPY_ANNOTATION
        self.log.debug(
            "ToDevice message received",
            sender=to_checksum_address(to_device.sender),
            message=DictSerializer.serialize(to_device),
        )

    def _get_retrier(self, receiver: Address) -> _RetryQueue:
        """ Construct and return a _RetryQueue for receiver """
        if receiver not in self._address_to_retrier:
            retrier = _RetryQueue(transport=self, receiver=receiver)
            self._address_to_retrier[receiver] = retrier
            # Always start the _RetryQueue, otherwise `stop` will block forever
            # waiting for the corresponding gevent.Greenlet to complete. This
            # has no negative side-effects if the transport has stopped because
            # the retrier itself checks the transport running state.
            retrier.start()
            # ``Runnable.start()`` may re-create the internal greenlet
            retrier.greenlet.link_exception(self.on_error)
        return self._address_to_retrier[receiver]

    def _send_with_retry(self, queue_identifier: QueueIdentifier, message: Message) -> None:
        retrier = self._get_retrier(queue_identifier.recipient)
        retrier.enqueue(queue_identifier=queue_identifier, message=message)

    def _send_raw(self, receiver_address: Address, data: str) -> None:
        room = self._get_room_for_address(receiver_address)

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
            #
            # This is not a problem since the messages are retried regularly.
            self.log.error("No room for receiver", receiver=to_checksum_address(receiver_address))

    def _get_room_for_address(self, address: Address) -> Optional[Room]:
        msg = (
            f"address not health checked: "
            f"node: {self._user_id}, "
            f"peer: {to_normalized_address(address)}"
        )
        assert address and self._address_mgr.is_address_known(address), msg

        room_ids = self._get_room_ids_for_address(address)
        if room_ids:  # if we know any room for this user, use the first one
            # This loop is used to ignore any broadcast rooms that may have 'polluted' the
            # user's room cache due to bug #3765
            # Can be removed after the next upgrade that switches to a new TokenNetworkRegistry
            while room_ids:
                room_id = room_ids.pop(0)
                room = self._client.rooms[room_id]
                if not self._is_broadcast_room(room):
                    self.log.debug("Existing room", room=room, members=room.get_joined_members())
                    return room
                self.log.warning(
                    "Ignoring broadcast room for peer",
                    room=room,
                    peer=to_normalized_address(address),
                )
        return None

    def _maybe_create_room_for_address(self, address: Address) -> None:
        if self._stop_event.ready():
            return None

        if self._get_room_for_address(address):
            return None

        assert self._raiden_service is not None, "_raiden_service not set"

        # The rooms creation is assymetric, only the node with the lower
        # address is responsible to create the room. This fixes race conditions
        # were the two nodes try to create a room with each other at the same
        # time, leading to communications problems if the nodes choose a
        # different room.
        #
        # This does not introduce a new attack vector, since not creating the
        # room is the same as being unresponsible.
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

            retry_interval = ROOM_JOIN_RETRY_INTERVAL
            for _ in range(JOIN_RETRIES):
                self.log.debug(
                    "Fetching room members",
                    room=room,
                    partner_address=to_checksum_address(address),
                )
                try:
                    members = room.get_joined_members(force_resync=True)
                except MatrixRequestError as e:
                    if e.code < 500:
                        raise

                # The display name signatures have been validated already.
                partner_joined = any(member.user_id in partner_user_ids for member in members)

                if partner_joined:
                    break

                if self._stop_event.wait(retry_interval):
                    return None

                retry_interval *= ROOM_JOIN_RETRY_INTERVAL_MULTIPLIER

                self.log.error(
                    "Peer has not joined from invite yet, should join eventually",
                    room=room,
                    partner_address=to_checksum_address(address),
                    retry_interval=retry_interval,
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
                self.log.warning(
                    "Private room has unexpected participants, leaving...",
                    room=room,
                    participants=members,
                )
                room.leave()
                return None

            self._address_mgr.add_userids_for_address(
                address, {user.user_id for user in partner_users}
            )

            self._set_room_id_for_address(address, room.room_id)

            if not room.listeners:
                room.add_listener(self._handle_message, "m.room.message")

            self.log.debug("Channel room", peer_address=to_checksum_address(address), room=room)
            return room

    def _is_broadcast_room(self, room: Room) -> bool:
        return any(
            suffix in room_alias
            for suffix in self._config["broadcast_rooms"]
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
                f"Multiple rooms exist with peer",
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

    def _set_room_id_for_address(
        self, address: Address, room_id: Optional[_RoomID] = None
    ) -> None:
        """ Uses GMatrixClient.set_account_data to keep updated mapping of addresses->rooms

        If room_id is falsy, clean list of rooms. Else, push room_id to front of the list """

        assert not room_id or room_id in self._client.rooms, "Invalid room_id"
        address_hex: AddressHex = to_checksum_address(address)
        room_ids = self._get_room_ids_for_address(address)

        with self._account_data_lock:
            # no need to deepcopy, we don't modify lists in-place
            # cast generic Dict[str, Any] to types we expect, to satisfy mypy, runtime no-op
            _address_to_room_ids = cast(
                Dict[AddressHex, List[_RoomID]],
                self._client.account_data.get("network.raiden.rooms", {}).copy(),
            )

            changed = False
            if not room_id:  # falsy room_id => clear list
                changed = address_hex in _address_to_room_ids
                _address_to_room_ids.pop(address_hex, None)
            else:
                # push to front
                room_ids = [room_id] + [r for r in room_ids if r != room_id]
                if room_ids != _address_to_room_ids.get(address_hex):
                    _address_to_room_ids[address_hex] = room_ids
                    changed = True

            if changed:
                # dict will be set at the end of _clean_unused_rooms
                self._leave_unused_rooms(_address_to_room_ids)

    def _get_room_ids_for_address(self, address: Address) -> List[_RoomID]:
        """ Uses GMatrixClient.get_account_data to get updated mapping of address->rooms
        """
        address_hex: AddressHex = to_checksum_address(address)

        with self._account_data_lock:
            room_ids = self._client.account_data.get("network.raiden.rooms", {}).get(address_hex)

        self.log.debug("Room ids for address", for_address=address_hex, room_ids=room_ids)

        if not room_ids:
            return list()

        # `account_data` should be private to the user. These values will only
        # be invalid if there is a bug in Raiden to push invalid data or if the
        # Matrix server is corrupted/malicous.
        invalid_input = any(not isinstance(room_id, str) for room_id in room_ids)
        if invalid_input:
            log.error("Unexpected account data, ignoring.")
            return list()

        return [
            room_id
            for room_id in room_ids
            if room_id in self._client.rooms and self._client.rooms[room_id].invite_only
        ]

    def _leave_unused_rooms(self, _address_to_room_ids: Dict[AddressHex, List[_RoomID]]) -> None:
        """
        Checks for rooms we've joined and which partner isn't health-checked and leave.

        **MUST** be called from a context that holds the `_account_data_lock`.
        """
        _msg = "_leave_unused_rooms called without account data lock"
        assert self._account_data_lock.locked(), _msg

        # TODO: To be implemented, see https://github.com/raiden-network/raiden/issues/3262
        self._client.set_account_data(
            "network.raiden.rooms",  # back from cast in _set_room_id_for_address
            cast(Dict[str, Any], _address_to_room_ids),
        )

    def send_to_device(self, address: Address, message: Message) -> None:
        """ Sends send-to-device events to a all known devices of a peer without retries. """
        user_ids = self._address_mgr.get_userids_for_address(address)

        data = {user_id: {"*": MessageSerializer.serialize(message)} for user_id in user_ids}

        return self._client.api.send_to_device("m.to_device_message", data)

    def _handle_to_device_message(self, event: Dict[str, Any]) -> bool:
        """
        Handles to_device_message sent to us.
        - validates peer_whitelisted
        - validates userid_signature
        Todo: Currently doesnt do anything but logging when a to device message is received.
        """
        sender_id = event["sender"]

        if (
            event["type"] != "m.to_device_message"
            or self._stop_event.ready()
            or sender_id == self._user_id
        ):
            # Ignore non-messages and our own messages
            return False

        user = self._client.get_user(sender_id)
        self._displayname_cache.warm_users([user])

        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "To_device_message from invalid user displayName signature", peer_user=user.user_id
            )
            return False

        # don't proceed if user isn't whitelisted (yet)
        if not self._address_mgr.is_address_known(peer_address):
            # user not start_health_check'ed
            self.log.debug(
                "ToDevice Message from non-whitelisted peer - ignoring",
                sender=user,
                sender_address=to_checksum_address(peer_address),
            )
            return False

        messages = validate_and_parse_message(event["content"], peer_address)

        if not messages:
            return False

        self.log.debug(
            "Incoming ToDevice Messages",
            messages=messages,
            sender=to_checksum_address(peer_address),
            sender_user=user,
        )

        for message in messages:
            if isinstance(message, ToDevice):
                self._receive_to_device(message)
            else:
                log.warning(
                    "Received Message is not of type ToDevice, invalid",
                    message=redact_secret(DictSerializer.serialize(message)),
                    peer_address=to_checksum_address(peer_address),
                )
                continue

        return True
