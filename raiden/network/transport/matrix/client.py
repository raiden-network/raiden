import itertools
import json
import time
from functools import wraps
from itertools import repeat
from typing import Any, Callable, Container, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import quote

import gevent
import structlog
from gevent import Greenlet
from gevent.event import Event
from gevent.lock import Semaphore
from matrix_client.api import MatrixHttpApi
from matrix_client.client import CACHE, MatrixClient
from matrix_client.errors import MatrixHttpLibError, MatrixRequestError
from matrix_client.room import Room as MatrixRoom
from matrix_client.user import User
from requests import Response
from requests.adapters import HTTPAdapter

from raiden.constants import Environment
from raiden.exceptions import MatrixSyncMaxTimeoutReached
from raiden.utils.formatting import to_checksum_address
from raiden.utils.notifying_queue import NotifyingQueue, event_first_of
from raiden.utils.typing import AddressHex

log = structlog.get_logger(__name__)


SHUTDOWN_TIMEOUT = 35
SYNC_TIMEOUT_MS = 30_000

MatrixMessage = Dict[str, Any]
MatrixRoomMessages = Tuple["Room", List[MatrixMessage]]
MatrixSyncMessages = List[MatrixRoomMessages]
JSONResponse = Dict[str, Any]


def node_address_from_userid(user_id: Optional[str]) -> Optional[AddressHex]:
    if user_id:
        return to_checksum_address(user_id.split(":", 1)[0][1:])

    return None


class Room(MatrixRoom):
    """ Matrix `Room` subclass that invokes listener callbacks in separate greenlets """

    def __init__(self, client: "GMatrixClient", room_id: str) -> None:
        super().__init__(client, room_id)
        self._members: Dict[str, User] = {}
        self.canonical_alias: str
        self.aliases: List[str]

        # dict of 'type': 'content' key/value pairs
        self.account_data: Dict[str, Dict[str, Any]] = dict()

    def get_joined_members(self, force_resync: bool = False) -> List[User]:
        """ Return a list of members of this room. """
        if force_resync:
            response = self.client.api.get_room_members(self.room_id)
            for event in response["chunk"]:
                if event["content"]["membership"] == "join":
                    user_id = event["state_key"]
                    if user_id not in self._members:
                        self._mkmembers(
                            User(self.client.api, user_id, event["content"].get("displayname"))
                        )
        return list(self._members.values())

    def _mkmembers(self, member: User) -> None:
        if member.user_id not in self._members:
            self._members[member.user_id] = member

    def _rmmembers(self, user_id: str) -> None:
        self._members.pop(user_id, None)

    def __repr__(self) -> str:
        if self.canonical_alias:
            return f"<Room id={self.room_id!r} alias={self.canonical_alias!r}>"
        return f"<Room id={self.room_id!r} aliases={self.aliases!r}>"

    def update_aliases(self) -> bool:
        """ Get aliases information from room state

        Returns:
            boolean: True if the aliases changed, False if not
        """
        changed = False
        try:
            response = self.client.api.get_room_state(self.room_id)
        except MatrixRequestError:
            return False
        for chunk in response:
            content = chunk.get("content")
            if content:
                if "aliases" in content:
                    aliases = content["aliases"]
                    if aliases != self.aliases:
                        self.aliases = aliases
                        changed = True
                if chunk.get("type") == "m.room.canonical_alias":
                    canonical_alias = content["alias"]
                    if self.canonical_alias != canonical_alias:
                        self.canonical_alias = canonical_alias
                        changed = True
        if changed and self.aliases and not self.canonical_alias:
            self.canonical_alias = self.aliases[0]
        return changed

    def set_account_data(self, type_: str, content: Dict[str, Any]) -> dict:
        self.account_data[type_] = content
        return self.client.api.set_room_account_data(
            quote(self.client.user_id), quote(self.room_id), quote(type_), content
        )


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
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.server_ident: Optional[str] = None

        http_adapter = HTTPAdapter(pool_maxsize=pool_maxsize)
        https_adapter = HTTPAdapter(pool_maxsize=pool_maxsize)
        self.session.mount("http://", http_adapter)
        self.session.mount("https://", https_adapter)
        self.session.hooks["response"].append(self._record_server_ident)

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
        started = time.time()

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
                if time.time() > started + self.retry_timeout:
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
        """ Perform GET /rooms/$room_id/state/$event_type/$state_key """
        return self._send("GET", f"/rooms/{room_id}/state/{event_type}/{state_key}")


class GMatrixClient(MatrixClient):
    """ Gevent-compliant MatrixClient subclass """

    sync_filter: str
    sync_thread: Optional[Greenlet] = None
    message_worker: Optional[Greenlet] = None

    def __init__(
        self,
        handle_messages_callback: Callable[[MatrixSyncMessages], bool],
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
    ) -> None:
        # dict of 'type': 'content' key/value pairs
        self.account_data: Dict[str, Dict[str, Any]] = dict()
        self.token: Optional[str] = None
        self.environment = environment
        self.handle_messages_callback = handle_messages_callback
        self.response_queue = NotifyingQueue()
        self.event_stop = Event()

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
        )
        self.api.validate_certificate(valid_cert_check)
        self.synced = gevent.event.Event()  # Set at the end of every sync, then cleared
        # Monotonically increasing id to ensure that presence updates are processed in order.
        self._presence_update_ids: Iterator[int] = itertools.count()
        self._worker_pool = gevent.pool.Pool(size=20)
        # Gets incremented every time a sync loop is completed. This is useful since the sync token
        # can remain constant over multiple loops (if no events occur).
        self._sync_iteration = 0

    def listen_forever(
        self,
        timeout_ms: int = 20_000,
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
        self.should_listen = True
        while self.should_listen:
            try:
                # may be killed and raise exception from message_worker
                self._sync(timeout_ms)
                _bad_sync_timeout = bad_sync_timeout
            except MatrixRequestError as e:
                log.warning(
                    "A MatrixRequestError occured during sync.",
                    node=node_address_from_userid(self.user_id),
                    user_id=self.user_id,
                )
                if e.code >= 500:
                    log.warning(
                        "Problem occured serverside. Waiting",
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
                    "A MatrixHttpLibError occured during sync.",
                    node=node_address_from_userid(self.user_id),
                    user_id=self.user_id,
                )
                if self.should_listen:
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
        self, timeout_ms: int = 20_000, exception_handler: Callable = None
    ) -> None:
        """
        Start a listener greenlet to listen for events in the background.

        Args:
            timeout_ms: How long to poll the Home Server for before retrying.
            exception_handler: Optional exception handler function which can
                be used to handle exceptions in the caller thread.
        """
        assert not self.should_listen and self.sync_thread is None, "Already running"
        self.should_listen = True

        self.sync_thread = gevent.spawn(self.listen_forever, timeout_ms, exception_handler)
        self.sync_thread.name = f"GMatrixClient.listen_forever user_id:{self.user_id}"

        self.message_worker = gevent.spawn(
            self._handle_process_worker, self.response_queue, self.event_stop
        )
        self.message_worker.name = f"GMatrixClient._handle_process_worker user_id:{self.user_id}"
        self.message_worker.link_exception(lambda g: self.sync_thread.kill(g.exception))

    def stop_listener_thread(self) -> None:
        """ Kills sync_thread greenlet before joining it """
        # when stopping, `kill` will cause the `self.api.sync` call in _sync
        # to raise a connection error. This flag will ensure it exits gracefully then
        self.should_listen = False
        self.event_stop.set()

        if self.sync_thread:
            self.sync_thread.kill()
            log.debug(
                "Waiting on sync greenlet",
                node=node_address_from_userid(self.user_id),
                user_id=self.user_id,
            )
            exited = gevent.joinall({self.sync_thread}, timeout=SHUTDOWN_TIMEOUT, raise_error=True)
            if not exited:
                raise RuntimeError("Timeout waiting on sync greenlet during transport shutdown.")
            self.sync_thread.get()

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
        self.sync_thread = None
        self.message_worker = None

    def stop(self) -> None:
        self.stop_listener_thread()
        self.sync_token = None
        self.should_listen = False
        self.rooms: Dict[str, Room] = {}
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
        response = self.api._send("POST", "/user_directory/search", {"search_term": term})
        try:
            return [
                User(self.api, _user["user_id"], _user["display_name"])
                for _user in response["results"]
            ]
        except KeyError:
            return []

    def set_presence_state(self, state: str) -> Dict:
        return self.api._send(
            "PUT", f"/presence/{quote(self.user_id)}/status", {"presence": state}
        )

    def _mkroom(self, room_id: str) -> Room:
        """ Uses a geventified Room subclass """
        if room_id not in self.rooms:
            self.rooms[room_id] = Room(self, room_id)
        room = self.rooms[room_id]
        if not room.canonical_alias:
            room.update_aliases()
        return room

    def get_user_presence(self, user_id: str) -> Optional[str]:
        return self.api._send("GET", f"/presence/{quote(user_id)}/status").get("presence")

    def _sync(self, timeout_ms: int = SYNC_TIMEOUT_MS) -> None:
        """ Reimplements MatrixClient._sync, add 'account_data' support to /sync """
        log.debug("Sync called", node=node_address_from_userid(self.user_id), user_id=self.user_id)

        response = self.api.sync(self.sync_token, timeout_ms)
        prev_sync_token = self.sync_token

        is_first_sync = prev_sync_token is None
        log.debug(
            "Starting _handle_response",
            node=node_address_from_userid(self.user_id),
            first_sync=is_first_sync,
            sync_token=prev_sync_token,
            current_user=self.user_id,
            presence_events_qty=len(response["presence"]["events"]),
            to_device_events_qty=len(response["to_device"]["events"]),
            rooms_invites_qty=len(response["rooms"]["invite"]),
            rooms_leaves_qty=len(response["rooms"]["leave"]),
            rooms_joined_member_count=sum(
                room["summary"].get("m.joined_member_count", 0)
                for room in response["rooms"]["join"].values()
            ),
            rooms_invited_member_count=sum(
                room["summary"].get("m.invited_member_count", 0)
                for room in response["rooms"]["join"].values()
            ),
            rooms_join_state_qty=sum(
                len(room["state"]) for room in response["rooms"]["join"].values()
            ),
            rooms_join_state_events_qty=sum(
                len(room["state"]["events"]) for room in response["rooms"]["join"].values()
            ),
            rooms_join_ephemeral_events_qty=sum(
                len(room["ephemeral"]["events"]) for room in response["rooms"]["join"].values()
            ),
            rooms_join_account_data_events_qty=sum(
                len(room["account_data"]["events"]) for room in response["rooms"]["join"].values()
            ),
        )
        before_processing = time.time()
        self._handle_response(response=response, first_sync=is_first_sync)
        processing_time_in_seconds = time.time() - before_processing

        # If processing the matrix response takes longer than the poll timout, it cannot be
        # ensured that all messages have been processed.
        # Therefore an exception is thrown when in development mode.
        timeout_in_seconds = timeout_ms // 1_000
        timeout_reached = (
            processing_time_in_seconds >= timeout_in_seconds
            and self.environment == Environment.DEVELOPMENT
        )
        if timeout_reached:
            raise MatrixSyncMaxTimeoutReached(
                f"Processing Matrix response took {processing_time_in_seconds}s, "
                f"poll timeout is {timeout_in_seconds}s."
            )

        # Updating the sync token should only be done after the response is
        # saved in the queue, otherwise the data can be lost in a stop/start.
        self.response_queue.put(response)
        self.sync_token = response["next_batch"]
        self._sync_iteration += 1

    def _handle_process_worker(self, response_queue: NotifyingQueue, event_stop: Event) -> None:
        """Worker to process network messages from the asynchronous transport.

        Note that his worker will process the messages in the order of
        delivery, however, the underlying protocol may not guarantee that
        messages are delivered in-order in which they were sent. The transport
        layer has to implement retries to guarantee that a message will
        eventually processed. This introduces a cost in terms of latency.
        """
        data_or_stop = event_first_of(response_queue, event_stop)

        while True:
            data_or_stop.wait()

            # Clear the event's internal state for the next iteration.
            #
            # This *must* be done before any context switch, otherwise
            # cuncurrent actions can be missed. Examples:
            # - If a new element is added to the queue while `_handle_response`
            # is executing, and the `data_or_stop` is cleared after that
            # context-switch, then the new element will be missed.
            # - If the stop event is set while `_handle_response` is being
            # executed, because this only happens once the stop event be
            # missed.
            data_or_stop.clear()

            if event_stop.is_set():
                return

            # The queue is not empty at this point, so this won't raise Empty.
            #
            # Here `peek` is used to implement delivery at-least-once
            # semantics. At-most-once would also be acceptable because of
            # message retries, however has the pontential of introducing
            # latency.
            response: JSONResponse = response_queue.peek(block=False)

            # TODO: Respect the `event_stop` in `_handle_response`. With this
            # implementation if the event is set while `_handle_response` is
            # executing, and the handler takes a long time, the process will
            # take longer than necessary to exit.
            if response is not None:
                self._handle_response(response)

            # Pop up the processed message, if the process is kill right at
            # before this call, on the next transport start the same message
            # will be processed again, that is why this is at-least-once
            # semantics.
            response_queue.get(block=False)

    def _handle_response(self, response: JSONResponse, first_sync: bool = False) -> None:
        # We must ignore the stop flag during first_sync
        if not self.should_listen and not first_sync:
            log.warning(
                "Aborting handle response",
                node=node_address_from_userid(self.user_id),
                reason="Transport stopped",
                user_id=self.user_id,
            )
            return

        # Handle presence after rooms
        for presence_update in response["presence"]["events"]:
            for callback in list(self.presence_listeners.values()):
                self._worker_pool.spawn(callback, presence_update, next(self._presence_update_ids))
        # Collect finished greenlets and errors without blocking
        self._worker_pool.join(timeout=0, raise_error=True)

        for to_device_message in response["to_device"]["events"]:
            for listener in self.listeners[:]:
                if listener["event_type"] == "to_device":
                    listener["callback"](to_device_message)

        for room_id, invite_room in response["rooms"]["invite"].items():
            for listener in self.invite_listeners[:]:
                listener(room_id, invite_room["invite_state"])

        for room_id, left_room in response["rooms"]["leave"].items():
            for listener in self.left_listeners[:]:
                listener(room_id, left_room)
            if room_id in self.rooms:
                del self.rooms[room_id]

        all_messages: MatrixSyncMessages = []
        for room_id, sync_room in response["rooms"]["join"].items():
            if room_id not in self.rooms:
                self._mkroom(room_id)
            room = self.rooms[room_id]
            # TODO: the rest of this for loop should be in room object method
            room.prev_batch = sync_room["timeline"]["prev_batch"]

            for event in sync_room["state"]["events"]:
                event["room_id"] = room_id
                room._process_state_event(event)

            for event in sync_room["timeline"]["events"]:
                event["room_id"] = room_id
                room._put_event(event)

            all_messages.append((room, sync_room["timeline"]["events"]))

            for event in sync_room["ephemeral"]["events"]:
                event["room_id"] = room_id
                room._put_ephemeral_event(event)

                for listener in self.ephemeral_listeners:
                    should_call = (
                        listener["event_type"] is None or listener["event_type"] == event["type"]
                    )
                    if should_call:
                        listener["callback"](event)

            for event in sync_room["account_data"]["events"]:
                room.account_data[event["type"]] = event["content"]

        self.handle_messages_callback(all_messages)

        if first_sync:
            # Only update the local account data on first sync to avoid races.
            # We don't support running multiple raiden nodes for the same eth account,
            # therefore no situation where we would need to be updated from the server
            # can happen.
            for event in response["account_data"]["events"]:
                self.account_data[event["type"]] = event["content"]

        self.synced.set()
        self.synced.clear()

    def set_account_data(self, type_: str, content: Dict[str, Any]) -> Dict:
        """ Use this to set a key: value pair in account_data to keep it synced on server """
        self.account_data[type_] = content
        return self.api.set_account_data(quote(self.user_id), quote(type_), content)

    def set_access_token(self, user_id: str, token: Optional[str]) -> None:
        self.user_id = user_id
        self.token = self.api.token = token

    def set_sync_limit(self, limit: Optional[int]) -> Optional[int]:
        """ Sets the events limit per room for sync and return previous limit """
        try:
            prev_limit = json.loads(self.sync_filter)["room"]["timeline"]["limit"]
        except (json.JSONDecodeError, KeyError):
            prev_limit = None
        self.sync_filter = json.dumps({"room": {"timeline": {"limit": limit}}})
        return prev_limit


# Monkey patch matrix User class to provide nicer repr
@wraps(User.__repr__)
def user__repr__(self: User) -> str:
    return f"<User id={self.user_id!r}>"


User.__repr__ = user__repr__
