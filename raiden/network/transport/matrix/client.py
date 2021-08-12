import itertools
import time
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from itertools import repeat
from typing import Any, Callable, Container, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import quote
from uuid import UUID, uuid4

import gevent
import structlog
from eth_typing import HexStr
from gevent import Greenlet
from gevent.event import Event
from gevent.lock import Semaphore
from gevent.pool import Pool
from matrix_client.api import MatrixHttpApi
from matrix_client.client import CACHE, MatrixClient
from matrix_client.errors import MatrixHttpLibError, MatrixRequestError
from matrix_client.user import User
from requests import Response
from requests.adapters import HTTPAdapter

from raiden.constants import Environment
from raiden.exceptions import MatrixSyncMaxTimeoutReached, TransportError
from raiden.messages.abstract import Message
from raiden.network.transport.matrix.sync_progress import SyncProgress
from raiden.utils.debugging import IDLE
from raiden.utils.notifying_queue import NotifyingQueue
from raiden.utils.typing import Address, AddressHex, AddressMetadata

log = structlog.get_logger(__name__)

SHUTDOWN_TIMEOUT = 35

MatrixMessage = Dict[str, Any]
JSONResponse = Dict[str, Any]


@dataclass
class _ReceivedMessageBase:
    sender: Address


@dataclass
class ReceivedRaidenMessage(_ReceivedMessageBase):
    message: Message
    sender_metadata: Optional[AddressMetadata] = None


@dataclass
class ReceivedCallMessage(_ReceivedMessageBase):
    message: MatrixMessage


def node_address_from_userid(user_id: Optional[str]) -> Optional[AddressHex]:
    if user_id:
        return AddressHex(HexStr(user_id.split(":", 1)[0][1:]))

    return None


class GMatrixHttpApi(MatrixHttpApi):
    """
    A wrapper around MatrixHttpApi to limit the number
    of concurrent requests we make to the number of connections
    available to us in requests.Session connection pool size.

    Args:
        pool_maxsize: max size of underlying/session connection pool
        retry_timeout: for how long should a single request be retried if it errors
        retry_delay: callable which returns an iterable of delays
    """

    def __init__(
        self,
        *args: Any,
        pool_maxsize: int = 10,
        retry_timeout: int = 60,
        retry_delay: Callable[[], Iterable[float]] = None,
        long_paths: Container[str] = (),
        user_agent: str = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.server_ident: Optional[str] = None

        http_adapter = HTTPAdapter(pool_maxsize=pool_maxsize)
        https_adapter = HTTPAdapter(pool_maxsize=pool_maxsize)
        self.session.mount("http://", http_adapter)
        self.session.mount("https://", https_adapter)
        self.session.hooks["response"].append(self._record_server_ident)
        if user_agent:
            self.session.headers.update({"User-Agent": user_agent})

        self._long_paths = long_paths
        if long_paths:
            self._semaphore = Semaphore(pool_maxsize - 1)
            self._priority_lock = Semaphore()
        else:
            self._semaphore = Semaphore(pool_maxsize)

        self.retry_timeout = retry_timeout
        if retry_delay is None:
            self.retry_delay: Callable[[], Iterable[float]] = lambda: repeat(1)
        else:
            self.retry_delay = retry_delay

    def _send(self, method: str, path: str, *args: Any, **kwargs: Any) -> Dict:
        # we use an infinite loop + time + sleep instead of gevent.Timeout
        # to be able to re-raise the last exception instead of declaring one beforehand
        started = time.monotonic()

        # paths in long_paths have a reserved slot in the pool, and aren't error-handled
        # to avoid them getting stuck when listener greenlet is killed
        if path in self._long_paths:
            with self._priority_lock:
                return super()._send(method, path, *args, **kwargs)
        last_ex = None
        for delay in self.retry_delay():
            try:
                with self._semaphore:
                    return super()._send(method, path, *args, **kwargs)
            except (MatrixRequestError, MatrixHttpLibError) as ex:
                # from MatrixRequestError, retry only 5xx http errors
                if isinstance(ex, MatrixRequestError) and ex.code < 500:
                    raise
                if time.monotonic() > started + self.retry_timeout:
                    raise
                last_ex = ex
                log.debug(
                    "Got http _send exception, waiting then retrying",
                    wait_for=delay,
                    _exception=ex,
                )
                gevent.sleep(delay)
        else:
            if last_ex:
                raise last_ex

        return {}  # Just for mypy, this will never be reached

    def _record_server_ident(
        self, response: Response, *args: Any, **kwargs: Any  # pylint: disable=unused-argument
    ) -> None:
        self.server_ident = response.headers.get("Server")

    def get_room_state_type(self, room_id: str, event_type: str, state_key: str) -> Dict[str, Any]:
        """Perform GET /rooms/$room_id/state/$event_type/$state_key"""
        return self._send("GET", f"/rooms/{room_id}/state/{event_type}/{state_key}")

    def create_room(
        self, alias: str = None, is_public: bool = False, invitees: List[str] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """Perform /createRoom
        Args:
            alias (str): Optional. The room alias name to set for this room.
            is_public (bool): Optional. The public/private visibility.
            invitees (list<str>): Optional. The list of user IDs to invite.
            kwargs: (dict<str, any>) additional request parameters
        """
        content = kwargs
        content["visibility"] = "public" if is_public else "private"
        if alias:
            content["room_alias_name"] = alias
        if invitees:
            content["invite"] = invitees
        return self._send("POST", "/createRoom", content)

    def get_presence(self, user_id: str) -> Dict[str, Any]:
        return self._send("GET", f"/presence/{quote(user_id)}/status")

    def get_aliases(self, room_id: str) -> Dict[str, Any]:
        """
        Perform GET /rooms/{room_id}/aliases.

        Requires Synapse >= 1.11.0 which implements the (as of yet) unstable MSC2432 room alias
        semantics change.
        """
        return self._send(
            "GET",
            f"/rooms/{room_id}/aliases",
            api_path="/_matrix/client/unstable/org.matrix.msc2432",
        )

    def __repr__(self) -> str:
        return f"<GMatrixHttpApi base_url={self.base_url}>"

    def disable_push_notifications(self) -> Dict[str, Any]:
        return self._send(
            "PUT",
            "/pushrules/global/override/.m.rule.master/enabled/",
            content={"enabled": True},
        )


class GMatrixClient(MatrixClient):
    """Gevent-compliant MatrixClient subclass"""

    sync_worker: Optional[Greenlet] = None
    message_worker: Optional[Greenlet] = None
    last_sync: float = float("inf")

    def __init__(
        self,
        handle_messages_callback: Callable[[List[MatrixMessage]], bool],
        base_url: str,
        token: str = None,
        user_id: str = None,
        valid_cert_check: bool = True,
        sync_filter_limit: int = 20,
        cache_level: CACHE = CACHE.ALL,
        http_pool_maxsize: int = 10,
        http_retry_timeout: int = 60,
        http_retry_delay: Callable[[], Iterable[float]] = lambda: repeat(1),
        environment: Environment = Environment.PRODUCTION,
        user_agent: str = None,
    ) -> None:

        self.token: Optional[str] = None
        self.environment = environment
        self.handle_messages_callback = handle_messages_callback
        self.response_queue: NotifyingQueue[Tuple[UUID, JSONResponse, datetime]] = NotifyingQueue()
        self.stop_event = Event()

        super().__init__(
            base_url, token, user_id, valid_cert_check, sync_filter_limit, cache_level
        )
        self.api = GMatrixHttpApi(
            base_url,
            token,
            pool_maxsize=http_pool_maxsize,
            retry_timeout=http_retry_timeout,
            retry_delay=http_retry_delay,
            long_paths=("/sync",),
            user_agent=user_agent,
        )
        self.api.validate_certificate(valid_cert_check)

        # Monotonically increasing id to ensure that presence updates are processed in order.
        self._presence_update_ids: Iterator[int] = itertools.count()
        self._worker_pool = Pool(size=20)
        # Gets incremented every time a sync loop is completed. This is useful since the sync token
        # can remain constant over multiple loops (if no events occur).
        self.sync_progress = SyncProgress(self.response_queue)
        self._sync_filter_id: Optional[int] = None

    @property
    def synced(self) -> Event:
        return self.sync_progress.synced_event

    @property
    def processed(self) -> Event:
        return self.sync_progress.processed_event

    @property
    def sync_iteration(self) -> int:
        return self.sync_progress.sync_iteration

    def create_sync_filter(self, limit: int) -> Optional[int]:
        """Create a matrix sync filter

        Ref. https://matrix.org/docs/spec/client_server/r0.6.0#api-endpoints

        Args:
            limit: maximum number of messages to return
        """
        sync_filter: Dict[str, Dict] = {
            # Get all presence updates
            "presence": {"types": ["m.presence"]},
            # filter account data
            "account_data": {"not_types": ["*"]},
            "room": {
                # Ignore "message receipts" from all rooms
                "ephemeral": {"not_types": ["m.receipt"]},
                # limit the number of messages
                "timeline": {"limit": limit},
            },
        }

        try:
            filter_response = self.api.create_filter(self.user_id, sync_filter)
        except MatrixRequestError as ex:
            raise TransportError(
                f"Failed to create filter: {sync_filter} for user {self.user_id}"
            ) from ex

        # 0 is a valid filter ID
        filter_id = filter_response.get("filter_id")
        log.debug("Sync filter created", filter_id=filter_id, filter=sync_filter)
        return filter_id

    def listen_forever(
        self,
        timeout_ms: int,
        latency_ms: int,
        exception_handler: Callable[[Exception], None] = None,
        bad_sync_timeout: int = 5,
    ) -> None:
        """
        Keep listening for events forever.

        Args:
            timeout_ms: How long to poll the Home Server for before retrying.
            exception_handler: Optional exception handler function which can
                be used to handle exceptions in the caller thread.
            bad_sync_timeout: Base time to wait after an error before retrying.
                Will be increased according to exponential backoff.
        """
        _bad_sync_timeout = bad_sync_timeout

        while not self.stop_event.is_set():
            try:
                # may be killed and raise exception from message_worker
                self._sync(timeout_ms, latency_ms)
                _bad_sync_timeout = bad_sync_timeout
            except MatrixRequestError as e:
                log.warning(
                    "A MatrixRequestError occurred during sync.",
                    node=node_address_from_userid(self.user_id),
                    user_id=self.user_id,
                )
                if e.code >= 500:
                    log.warning(
                        "Problem occurred serverside. Waiting",
                        node=node_address_from_userid(self.user_id),
                        user_id=self.user_id,
                        wait_for=_bad_sync_timeout,
                    )
                    gevent.sleep(_bad_sync_timeout)
                    _bad_sync_timeout = min(_bad_sync_timeout * 2, self.bad_sync_timeout_limit)
                else:
                    raise
            except MatrixHttpLibError:
                log.exception(
                    "A MatrixHttpLibError occurred during sync.",
                    node=node_address_from_userid(self.user_id),
                    user_id=self.user_id,
                )
                if not self.stop_event.is_set():
                    gevent.sleep(_bad_sync_timeout)
                    _bad_sync_timeout = min(_bad_sync_timeout * 2, self.bad_sync_timeout_limit)
            except Exception as e:
                log.exception(
                    "Exception thrown during sync",
                    node=node_address_from_userid(self.user_id),
                    user_id=self.user_id,
                )
                if exception_handler is not None:
                    exception_handler(e)
                else:
                    raise

    def start_listener_thread(
        self, timeout_ms: int, latency_ms: int, exception_handler: Callable = None
    ) -> None:
        """
        Start a listener greenlet to listen for events in the background.

        Args:
            timeout_ms: How long to poll the Home Server for before retrying.
            exception_handler: Optional exception handler function which can
                be used to handle exceptions in the caller thread.
        """
        assert self.sync_worker is None, "Already running"
        # Needs to be reset, otherwise we might run into problems when restarting
        self.last_sync = float("inf")

        self.sync_worker = gevent.spawn(
            self.listen_forever, timeout_ms, latency_ms, exception_handler
        )
        self.sync_worker.name = f"GMatrixClient.sync_worker user_id:{self.user_id}"
        self.message_worker = gevent.spawn(
            self._handle_message, self.response_queue, self.stop_event
        )
        self.message_worker.name = f"GMatrixClient.message_worker user_id:{self.user_id}"
        self.message_worker.link_exception(lambda g: self.sync_worker.kill(g.exception))

        # FIXME: This is just a temporary hack, this adds a race condition of the user pressing
        #     Ctrl-C before this is run, and Raiden newer shutting down.
        self.stop_event.clear()

    def stop_listener_thread(self) -> None:
        """Kills sync_thread greenlet before joining it"""
        # when stopping, `kill` will cause the `self.api.sync` call in _sync
        # to raise a connection error. This flag will ensure it exits gracefully then
        self.stop_event.set()

        if self.sync_worker:
            self.sync_worker.kill()
            log.debug(
                "Waiting on sync greenlet",
                node=node_address_from_userid(self.user_id),
                user_id=self.user_id,
            )
            exited = gevent.joinall({self.sync_worker}, timeout=SHUTDOWN_TIMEOUT, raise_error=True)
            if not exited:
                raise RuntimeError("Timeout waiting on sync greenlet during transport shutdown.")
            self.sync_worker.get()

        if self.message_worker is not None:
            log.debug(
                "Waiting on handle greenlet",
                node=node_address_from_userid(self.user_id),
                current_user=self.user_id,
            )
            exited = gevent.joinall(
                {self.message_worker}, timeout=SHUTDOWN_TIMEOUT, raise_error=True
            )
            if not exited:
                raise RuntimeError("Timeout waiting on handle greenlet during transport shutdown.")
            self.message_worker.get()

        log.debug(
            "Listener greenlet exited",
            node=node_address_from_userid(self.user_id),
            user_id=self.user_id,
        )
        self.sync_worker = None
        self.message_worker = None

    def stop(self) -> None:
        self.stop_listener_thread()
        self.sync_token = None
        self._worker_pool.join(raise_error=True)

    def logout(self) -> None:
        super().logout()
        self.api.session.close()

    def search_user_directory(self, term: str) -> List[User]:
        """
        Search user directory for a given term, returning a list of users
        Args:
            term: term to be searched for
        Returns:
            user_list: list of users returned by server-side search
        """
        try:
            response = self.api._send("POST", "/user_directory/search", {"search_term": term})
        except MatrixRequestError as ex:
            if ex.code >= 500:
                log.error(
                    "Ignoring Matrix error in `search_user_directory`",
                    exc_info=ex,
                    term=term,
                )
                return []
            else:
                raise ex
        try:
            return [
                User(self.api, _user["user_id"], _user["display_name"])
                for _user in response["results"]
            ]
        except KeyError:
            return []

    def set_presence_state(self, state: str) -> Dict:
        return self.api._send(
            "PUT",
            f"/presence/{quote(self.user_id)}/status",
            {"presence": state, "status_msg": str(time.time())},
        )

    def get_user_presence(self, user_id: str) -> Optional[str]:
        return self.api.get_presence(user_id).get("presence")

    def blocking_sync(self, timeout_ms: int, latency_ms: int) -> None:
        """Perform a /sync and process the response synchronously."""
        self._sync(timeout_ms=timeout_ms, latency_ms=latency_ms)

        pending_queue = []
        while len(self.response_queue) > 0:
            _, response, _ = self.response_queue.get()
            pending_queue.append(response)

        assert all(pending_queue), "Sync returned, None and empty are invalid values."

        self._handle_responses(pending_queue)

    def _sync(self, timeout_ms: int, latency_ms: int) -> None:
        """Reimplements MatrixClient._sync"""
        log.debug(
            "Sync called",
            node=node_address_from_userid(self.user_id),
            user_id=self.user_id,
            sync_iteration=self.sync_iteration,
            sync_filter_id=self._sync_filter_id,
            last_sync_time=self.last_sync,
        )

        time_before_sync = time.monotonic()
        time_since_last_sync_in_seconds = time_before_sync - self.last_sync

        # If it takes longer than `timeout_ms + latency_ms` to call `_sync`
        # again, we throw an exception.  The exception is only thrown when in
        # development mode.
        timeout_in_seconds = (timeout_ms + latency_ms) // 1_000
        timeout_reached = (
            time_since_last_sync_in_seconds >= timeout_in_seconds
            and self.environment == Environment.DEVELOPMENT
        )
        # The second sync is the first full sync and can be slow. This is
        # acceptable, we only want to know if we fail to sync quickly
        # afterwards.
        # As the runtime is evaluated in the subsequent run, we only run this
        # after the second iteration is finished.
        if timeout_reached:
            if IDLE:
                IDLE.log()

            raise MatrixSyncMaxTimeoutReached(
                f"Time between syncs exceeded timeout:  "
                f"{time_since_last_sync_in_seconds}s > {timeout_in_seconds}s. {IDLE}"
            )

        log.debug(
            "Calling api.sync",
            node=node_address_from_userid(self.user_id),
            user_id=self.user_id,
            sync_iteration=self.sync_iteration,
            time_since_last_sync_in_seconds=time_since_last_sync_in_seconds,
        )
        self.last_sync = time_before_sync
        response = self.api.sync(
            since=self.sync_token, timeout_ms=timeout_ms, filter=self._sync_filter_id
        )
        time_after_sync = time.monotonic()

        log.debug(
            "api.sync returned",
            node=node_address_from_userid(self.user_id),
            user_id=self.user_id,
            sync_iteration=self.sync_iteration,
            time_after_sync=time_after_sync,
            time_taken=time_after_sync - time_before_sync,
        )

        if response:
            token = uuid4()

            log.debug(
                "Sync returned",
                node=node_address_from_userid(self.user_id),
                token=token,
                elapsed=time_after_sync - time_before_sync,
                current_user=self.user_id,
                presence_events_qty=len(response["presence"]["events"]),
                to_device_events_qty=len(response["to_device"]["events"]),
            )

            # Updating the sync token should only be done after the response is
            # saved in the queue, otherwise the data can be lost in a stop/start.
            self.response_queue.put((token, response, datetime.now()))
            self.sync_token = response["next_batch"]
            self.sync_progress.set_synced(token)

    def _handle_message(
        self,
        response_queue: NotifyingQueue[Tuple[UUID, JSONResponse, datetime]],
        stop_event: Event,
    ) -> None:
        """Worker to process network messages from the asynchronous transport.

        Note that this worker will process the messages in the order of
        delivery. However, the underlying protocol may not guarantee that
        messages are delivered in-order in which they were sent. The transport
        layer has to implement retries to guarantee that a message is
        eventually processed. This introduces a cost in terms of latency.
        """
        while True:
            gevent.joinall({response_queue, stop_event}, count=1, raise_error=True)

            # Iterating over the Queue and adding to a separated list to
            # implement delivery at-least-once semantics. At-most-once would
            # also be acceptable because of message retries, however it has the
            # potential of introducing latency.
            #
            # The Queue's iterator cannot be used because it defaults do `get`.
            currently_queued_response_tokens = []
            currently_queued_responses = []
            for token, response, received_at in response_queue.queue.queue:
                assert response is not None, "None is not a valid value for a Matrix response."

                log.debug(
                    "Handling Matrix response",
                    token=token,
                    node=node_address_from_userid(self.user_id),
                    current_size=len(response_queue),
                    processing_lag=datetime.now() - received_at,
                )
                currently_queued_response_tokens.append(token)
                currently_queued_responses.append(response)

            if stop_event.is_set():
                log.debug(
                    "Handling worker exiting, stop is set",
                    node=node_address_from_userid(self.user_id),
                )
                return
            time_before_processing = time.monotonic()
            self._handle_responses(currently_queued_responses)
            time_after_processing = time.monotonic()
            log.debug(
                "Processed queued Matrix responses",
                node=node_address_from_userid(self.user_id),
                elapsed=time_after_processing - time_before_processing,
            )

            # Pop the processed messages, this relies on the fact the queue is
            # ordered to pop the correct messages. If the process is killed
            # right before this call, on the next transport start the same
            # message will be processed again, that is why this is
            # at-least-once semantics.
            for _ in currently_queued_responses:
                response_queue.get(block=False)

            self.sync_progress.set_processed(currently_queued_response_tokens)

    def _handle_responses(self, currently_queued_responses: List[JSONResponse]) -> None:
        messages: List[MatrixMessage] = []

        for response in currently_queued_responses:
            for presence_update in response["presence"]["events"]:
                for callback in list(self.presence_listeners.values()):
                    callback(presence_update, next(self._presence_update_ids))

            for to_device_message in response["to_device"]["events"]:
                for listener in self.listeners[:]:
                    if listener["event_type"] == "to_device":
                        listener["callback"](to_device_message)

            # Add toDevice messages to message queue
            messages.extend(response["to_device"]["events"])

        if messages:
            self.handle_messages_callback(messages)

    def set_access_token(self, user_id: str, token: Optional[str]) -> None:
        self.user_id = user_id
        self.token = self.api.token = token

    def set_sync_filter_id(self, sync_filter_id: Optional[int]) -> Optional[int]:
        """Sets the sync filter to the given id and returns previous filters id"""
        prev_id = self._sync_filter_id
        self._sync_filter_id = sync_filter_id
        return prev_id


# Monkey patch matrix User class to provide nicer repr
@wraps(User.__repr__)
def user__repr__(self: User) -> str:
    return f"<User id={self.user_id!r}>"


User.__repr__ = user__repr__
