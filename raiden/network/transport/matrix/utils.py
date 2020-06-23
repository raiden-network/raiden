import json
import re
import time
from binascii import Error as DecodeError
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import lru_cache
from operator import attrgetter, itemgetter
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Union,
)
from urllib.parse import urlparse
from uuid import UUID

import gevent
import structlog
from cachetools import LRUCache, cached
from eth_utils import (
    decode_hex,
    encode_hex,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.event import Event
from gevent.lock import Semaphore
from matrix_client.errors import MatrixError, MatrixRequestError
from structlog._config import BoundLoggerLazyProxy

from raiden.exceptions import (
    InvalidSignature,
    RaidenUnrecoverableError,
    SerializationError,
    TransportError,
)
from raiden.messages.abstract import Message, RetrieableMessage, SignedMessage
from raiden.messages.synchronization import Processed
from raiden.network.transport.matrix.client import (
    GMatrixClient,
    MatrixSyncMessages,
    Room,
    User,
    node_address_from_userid,
)
from raiden.network.utils import get_average_http_response_time
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.utils.gevent import spawn_named
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import Address, ChainID, MessageID, Signature
from raiden_contracts.constants import ID_TO_CHAINNAME

log = structlog.get_logger(__name__)
cached_deserialize = lru_cache()(MessageSerializer.deserialize)

JOIN_RETRIES = 10
USERID_RE = re.compile(r"^@(0x[0-9a-f]{40})(?:\.[0-9a-f]{8})?(?::.+)?$")
DISPLAY_NAME_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")
ROOM_NAME_SEPARATOR = "_"
ROOM_NAME_PREFIX = "raiden"
# The maximum matrix event size is 65 kB. Since events are larger than just the message
# content we chose a conservative value
MATRIX_MAX_BATCH_SIZE = 50_000
JSONResponse = Dict[str, Any]


class UserPresence(Enum):
    ONLINE = "online"
    UNAVAILABLE = "unavailable"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    SERVER_ERROR = "server_error"


class AddressReachability(Enum):
    REACHABLE = 1
    UNREACHABLE = 2
    UNKNOWN = 3


@dataclass
class ReachabilityState:
    reachability: AddressReachability
    time: datetime


EPOCH = datetime(1970, 1, 1)
UNKNOWN_REACHABILITY_STATE = ReachabilityState(AddressReachability.UNKNOWN, EPOCH)


USER_PRESENCE_REACHABLE_STATES = {UserPresence.ONLINE, UserPresence.UNAVAILABLE}
USER_PRESENCE_TO_ADDRESS_REACHABILITY = {
    UserPresence.ONLINE: AddressReachability.REACHABLE,
    UserPresence.UNAVAILABLE: AddressReachability.REACHABLE,
    UserPresence.OFFLINE: AddressReachability.UNREACHABLE,
    UserPresence.UNKNOWN: AddressReachability.UNKNOWN,
    UserPresence.SERVER_ERROR: AddressReachability.UNKNOWN,
}


def address_from_userid(user_id: str) -> Optional[Address]:
    match = USERID_RE.match(user_id)
    if not match:
        return None

    encoded_address = match.group(1)
    address: Address = to_canonical_address(encoded_address)

    return address


class DisplayNameCache:
    def __init__(self) -> None:
        self.userid_to_displayname: Dict[str, str] = dict()

    def warm_users(self, users: List[User]) -> None:
        for user in users:
            user_id = user.user_id
            cached_displayname = self.userid_to_displayname.get(user_id)

            if cached_displayname is None:
                # The cache is cold, query and warm it.
                if not user.displayname:
                    # Handles an edge case where the Matrix federation does not
                    # have the profile for a given userid. The server response
                    # is roughly:
                    #
                    #   {"errcode":"M_NOT_FOUND","error":"Profile was not found"} or
                    #   {"errcode":"M_UNKNOWN","error":"Failed to fetch profile"}
                    try:
                        user.get_display_name()
                    except MatrixRequestError as ex:
                        # We ignore the error here and set user presence: SERVER_ERROR at the
                        # calling site
                        log.error(
                            f"Ignoring failed `get_display_name` for user {user}", exc_info=ex
                        )

                if user.displayname is not None:
                    self.userid_to_displayname[user.user_id] = user.displayname

            elif user.displayname is None:
                user.displayname = cached_displayname

            elif user.displayname != cached_displayname:
                log.debug(
                    "User displayname changed!",
                    cached=cached_displayname,
                    current=user.displayname,
                )
                self.userid_to_displayname[user.user_id] = user.displayname


class UserAddressManager:
    """ Matrix user <-> eth address mapping and user / address reachability helper.

    In Raiden the smallest unit of addressability is a node with an associated Ethereum address.
    In Matrix it's a user. Matrix users are (at the moment) bound to a specific homeserver.
    Since we want to provide resiliency against unavailable homeservers a single Raiden node with
    a single Ethereum address can be in control over multiple Matrix users on multiple homeservers.

    Therefore we need to perform a many-to-one mapping of Matrix users to Ethereum addresses.
    Each Matrix user has a presence state (ONLINE, OFFLINE).
    One of the preconditions of running a Raiden node is that there can always only be one node
    online for a particular address at a time.
    That means we can synthesize the reachability of an address from the user presence states.

    This helper internally tracks both the user presence and address reachability for addresses
    that have been marked as being 'interesting' (by calling the `.add_address()` method).
    Additionally it provides the option of passing callbacks that will be notified when
    presence / reachability change.
    """

    def __init__(
        self,
        client: GMatrixClient,
        displayname_cache: DisplayNameCache,
        address_reachability_changed_callback: Callable[[Address, AddressReachability], None],
        user_presence_changed_callback: Optional[Callable[[User, UserPresence], None]] = None,
        _log_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._client = client
        self._displayname_cache = displayname_cache
        self._address_reachability_changed_callback = address_reachability_changed_callback
        self._user_presence_changed_callback = user_presence_changed_callback
        self._stop_event = Event()

        self._reset_state()

        self._log_context = _log_context
        self._log = None
        self._listener_id: Optional[UUID] = None

    def start(self) -> None:
        """ Start listening for presence updates.

        Should be called before ``.login()`` is called on the underlying client. """
        assert self._listener_id is None, "UserAddressManager.start() called twice"
        self._stop_event.clear()
        self._listener_id = self._client.add_presence_listener(self._presence_listener)

    def stop(self) -> None:
        """ Stop listening on presence updates. """
        assert self._listener_id is not None, "UserAddressManager.stop() called before start"
        self._stop_event.set()
        self._client.remove_presence_listener(self._listener_id)
        self._listener_id = None
        self._log = None
        self._reset_state()

    @property
    def known_addresses(self) -> Set[Address]:
        """ Return all addresses we keep track of """
        # This must return a copy of the current keys, because the container
        # may be modified while these values are used. Issue: #5240
        return set(self._address_to_userids)

    def is_address_known(self, address: Address) -> bool:
        """ Is the given ``address`` reachability being monitored? """
        return address in self._address_to_userids

    def add_address(self, address: Address) -> None:
        """ Add ``address`` to the known addresses that are being observed for reachability. """
        # Since _address_to_userids is a defaultdict accessing the key creates the entry
        _ = self._address_to_userids[address]

    def add_userid_for_address(self, address: Address, user_id: str) -> None:
        """ Add a ``user_id`` for the given ``address``.

        Implicitly adds the address if it was unknown before.
        """
        self._address_to_userids[address].add(user_id)

    def add_userids_for_address(self, address: Address, user_ids: Iterable[str]) -> None:
        """ Add multiple ``user_ids`` for the given ``address``.

        Implicitly adds any addresses if they were unknown before.
        """
        self._address_to_userids[address].update(user_ids)

    def get_userids_for_address(self, address: Address) -> Set[str]:
        """ Return all known user ids for the given ``address``. """
        if not self.is_address_known(address):
            return set()
        return self._address_to_userids[address]

    def get_userid_presence(self, user_id: str) -> UserPresence:
        """ Return the current presence state of ``user_id``. """
        return self._userid_to_presence.get(user_id, UserPresence.UNKNOWN)

    def get_address_reachability(self, address: Address) -> AddressReachability:
        """ Return the current reachability state for ``address``. """
        return self._address_to_reachabilitystate.get(
            address, UNKNOWN_REACHABILITY_STATE
        ).reachability

    def get_address_reachability_state(self, address: Address) -> ReachabilityState:
        """ Return the current reachability state for ``address``. """
        return self._address_to_reachabilitystate.get(address, UNKNOWN_REACHABILITY_STATE)

    def force_user_presence(self, user: User, presence: UserPresence) -> None:
        """ Forcibly set the ``user`` presence to ``presence``.

        This method is only provided to cover an edge case in our use of the Matrix protocol and
        should **not** generally be used.
        """
        self._userid_to_presence[user.user_id] = presence

    def populate_userids_for_address(self, address: Address, force: bool = False) -> None:
        """ Populate known user ids for the given ``address`` from the server directory.

        If ``force`` is ``True`` perform the directory search even if there
        already are known users.
        """
        if force or not self.get_userids_for_address(address):
            self.add_userids_for_address(
                address,
                (
                    user.user_id
                    for user in self._client.search_user_directory(to_normalized_address(address))
                    if self._validate_userid_signature(user)
                ),
            )

    def track_address_presence(
        self, address: Address, user_ids: Union[Set[str], FrozenSet[str]] = None
    ) -> None:
        """
        Update synthesized address presence state.

        Triggers callback (if any) in case the state has changed.
        """
        # Is this address already tracked for all given user_ids?
        if user_ids is None:
            user_ids = frozenset()
        state_known = (
            self.get_address_reachability_state(address).reachability
            != AddressReachability.UNKNOWN
        )
        no_new_user_ids = user_ids.issubset(self._address_to_userids[address])
        if state_known and no_new_user_ids:
            return

        # Update presence
        self.add_userids_for_address(address, user_ids)
        userids_to_presence = {}
        for uid in user_ids:
            presence = self._fetch_user_presence(uid)
            userids_to_presence[uid] = presence
            # We assume that this is only used when no presence has been set,
            # yet. So let's use a presence_update_id that's smaller than the
            # usual ones, which start at 0.
            self._set_user_presence(uid, presence, presence_update_id=-1)

        log.debug(
            "Fetched user presences",
            address=to_checksum_address(address),
            userids_to_presence=userids_to_presence,
        )

        self._maybe_address_reachability_changed(address)

    def get_reachability_from_matrix(self, user_ids: Iterable[str]) -> AddressReachability:
        """ Get the current reachability without any side effects

        Since his does not even do any caching, don't use it for the normal
        communication between participants in a channel.
        """
        for uid in user_ids:
            presence = self._fetch_user_presence(uid)
            if USER_PRESENCE_TO_ADDRESS_REACHABILITY[presence] == AddressReachability.REACHABLE:
                return AddressReachability.REACHABLE

        return AddressReachability.UNREACHABLE

    def _maybe_address_reachability_changed(self, address: Address) -> None:
        # A Raiden node may have multiple Matrix users, this happens when
        # Raiden roams from a Matrix server to another. This loop goes over all
        # these users and uses the "best" presence. IOW, if there is a single
        # Matrix user that is reachable, then the Raiden node is considered
        # reachable.
        userids = self._address_to_userids[address].copy()
        composite_presence = {self._userid_to_presence.get(uid) for uid in userids}

        new_presence = UserPresence.UNKNOWN
        for presence in UserPresence.__members__.values():
            if presence in composite_presence:
                new_presence = presence
                break

        new_address_reachability = USER_PRESENCE_TO_ADDRESS_REACHABILITY[new_presence]

        prev_reachability_state = self.get_address_reachability_state(address)
        if new_address_reachability == prev_reachability_state.reachability:
            return

        now = datetime.now()

        self.log.debug(
            "Changing address reachability state",
            address=to_checksum_address(address),
            prev_state=prev_reachability_state.reachability,
            state=new_address_reachability,
            last_change=prev_reachability_state.time,
            change_after=now - prev_reachability_state.time,
        )

        self._address_to_reachabilitystate[address] = ReachabilityState(
            new_address_reachability, now
        )

        self._address_reachability_changed_callback(address, new_address_reachability)

    def _presence_listener(self, event: Dict[str, Any], presence_update_id: int) -> None:
        """
        Update cached user presence state from Matrix presence events.

        Due to the possibility of nodes using accounts on multiple homeservers a composite
        address state is synthesised from the cached individual user presence states.
        """
        if self._stop_event.ready():
            return

        user_id = event["sender"]

        if event["type"] != "m.presence" or user_id == self._user_id:
            return

        address = address_from_userid(user_id)

        # Not a user we've whitelisted, skip. This needs to be on the top of
        # the function so that we don't request they displayname of users that
        # are not important for the node. The presence is updated for every
        # user on the first sync, since every Raiden node is a member of a
        # broadcast room. This can result in thousands requests to the Matrix
        # server in the first sync which will lead to slow startup times and
        # presence problems.
        if address is None or not self.is_address_known(address):
            return

        user = self._user_from_id(user_id, event["content"].get("displayname"))

        if not user:
            return

        self._displayname_cache.warm_users([user])
        # If for any reason we cannot resolve the displayname, then there was a server error.
        # Any properly logged in user that joined a room, will have a displayname.
        # A reason for not resolving it could be rate limiting by the other server.
        if user.displayname is None:
            new_state = UserPresence.SERVER_ERROR
            self._set_user_presence(user_id, new_state, presence_update_id)
            return

        address = self._validate_userid_signature(user)
        if not address:
            return

        self.add_userid_for_address(address, user_id)

        new_state = UserPresence(event["content"]["presence"])

        self._set_user_presence(user_id, new_state, presence_update_id)
        self._maybe_address_reachability_changed(address)

    def _reset_state(self) -> None:
        self._address_to_userids: Dict[Address, Set[str]] = defaultdict(set)
        self._address_to_reachabilitystate: Dict[Address, ReachabilityState] = dict()
        self._userid_to_presence: Dict[str, UserPresence] = dict()
        self._userid_to_presence_update_id: Dict[str, int] = dict()

    @property
    def _user_id(self) -> str:
        user_id = getattr(self._client, "user_id", None)
        assert user_id, f"{self.__class__.__name__}._user_id accessed before client login"
        return user_id

    def _user_from_id(self, user_id: str, display_name: Optional[str] = None) -> Optional[User]:
        try:
            return User(self._client.api, user_id, display_name)
        except ValueError:
            log.error("Matrix server returned an invalid user_id.")
        return None

    def _fetch_user_presence(self, user_id: str) -> UserPresence:
        try:
            presence = UserPresence(self._client.get_user_presence(user_id))
        except MatrixRequestError:
            # The following exception will be raised if the local user and the
            # target user do not have a shared room:
            #
            #   MatrixRequestError: 403:
            #   {"errcode":"M_FORBIDDEN","error":"You are not allowed to see their presence."}
            presence = UserPresence.UNKNOWN
            log.exception("Could not fetch user presence")

        return presence

    def _set_user_presence(
        self, user_id: str, presence: UserPresence, presence_update_id: int
    ) -> None:
        user = self._user_from_id(user_id)
        if not user:
            return

        # -1 is used in track_address_presence, so we use -2 as a default.
        if self._userid_to_presence_update_id.get(user_id, -2) >= presence_update_id:
            # We've already received a more recent presence (or the same one)
            return

        old_presence = self._userid_to_presence.get(user_id)
        if old_presence == presence:
            # This can happen when force_user_presence is used. For most other
            # cased the presence_update_id check will return first.
            return

        self._userid_to_presence[user_id] = presence
        self._userid_to_presence_update_id[user_id] = presence_update_id
        self.log.debug(
            "Changing user presence state",
            user_id=user_id,
            prev_state=old_presence,
            state=presence,
        )
        if self._user_presence_changed_callback:
            self._displayname_cache.warm_users([user])
            self._user_presence_changed_callback(user, presence)

    @staticmethod
    def _validate_userid_signature(user: User) -> Optional[Address]:
        return validate_userid_signature(user)

    @property
    def log(self) -> BoundLoggerLazyProxy:
        if self._log:
            return self._log  # type: ignore

        context = self._log_context or {}

        # Only cache the logger once the user_id becomes available
        if hasattr(self._client, "user_id"):
            context["current_user"] = self._user_id
            context["node"] = node_address_from_userid(self._user_id)

            bound_log = log.bind(**context)
            self._log = bound_log
            return bound_log

        # Apply  the `_log_context` even if the user_id is not yet available
        return log.bind(**context)


class MessageAckTimingKeeper:
    def __init__(self) -> None:
        self._seen_messages: Set[MessageID] = set()
        self._messages_in_flight: Dict[MessageID, float] = {}
        self._durations: List[float] = []

    def add_message(self, message: RetrieableMessage) -> None:
        if message.message_identifier in self._seen_messages:
            return
        self._messages_in_flight[message.message_identifier] = time.monotonic()
        self._seen_messages.add(message.message_identifier)

    def finalize_message(self, message: Processed) -> None:
        start_time = self._messages_in_flight.pop(message.message_identifier, None)
        if start_time is None:
            # We received an unknown `Processed` message. This can happen after a restart. Ignore.
            return
        self._durations.append(time.monotonic() - start_time)

    def generate_report(self) -> List[float]:
        if not self._durations:
            return []
        return sorted(self._durations)


def join_broadcast_room(client: GMatrixClient, broadcast_room_alias: str) -> Room:
    """ Join the public broadcast through the alias `broadcast_room_alias`.

    When a new Matrix instance is deployed the broadcast room _must_ be created
    and aliased, Raiden will not use a server that does not have the discovery
    room properly set. Requiring the setup of the broadcast alias as part of
    the server setup fixes a serious race condition where multiple discovery
    rooms are created, which would break the presence checking.
    See: https://github.com/raiden-network/raiden-transport/issues/46
    """
    try:
        room = client.join_room(broadcast_room_alias)
        del client.rooms[room.room_id]
        return room
    except MatrixRequestError:
        raise RaidenUnrecoverableError(
            f"Could not join broadcast room {broadcast_room_alias}. "
            f"Make sure the Matrix server you're trying to connect to uses the recommended server "
            f"setup, esp. the server-side broadcast room creation. "
            f"See https://github.com/raiden-network/raiden-transport."
        )


def first_login(client: GMatrixClient, signer: Signer, username: str) -> User:
    """Login within a server.

    There are multiple cases where a previous auth token can become invalid and
    a new login is necessary:

    - The server is configured to automatically invalidate tokens after a while
      (not the default)
    - A server operator may manually wipe or invalidate existing access tokens
    - A node may have roamed to a different server (e.g. because the original
      server was temporarily unavailable) and is now 'returning' to the
      previously used server.

    This relies on the Matrix server having the `eth_auth_provider` plugin
    installed, the plugin will automatically create the user on the first
    login. The plugin requires the password to be the signature of the server
    hostname, verified by the server to prevent account creation spam.

    Displayname is the signature of the whole user_id (including homeserver),
    to be verified by other peers and prevent impersonation attacks.
    """
    server_url = client.api.base_url
    server_name = urlparse(server_url).netloc

    # The plugin `eth_auth_provider` expects a signature of the server_name as
    # the user's password.
    #
    # For a honest matrix server:
    #
    # - This prevents impersonation attacks / name squatting, since the plugin
    # will validate the username by recovering the address from the signature
    # and check the recovered address and the username matches.
    #
    # For a badly configured server (one without the plugin):
    #
    # - An attacker can front run and register the username before the honest
    # user:
    #    - Because the attacker cannot guess the correct password, when the
    #    honest node tries to login it will fail, which tells us the server is
    #    improperly configured and should be blacklisted.
    #    - The attacker cannot forge a signature to use as a display name, so
    #    the partner node can tell there is a malicious node trying to
    #    eavesdrop the conversation and that matrix server should be
    #    blacklisted.
    # - The username is available, but because the plugin is not installed the
    # login will fail since the user is not registered. Here too one can infer
    # the server is improperly configured and blacklist the server.
    password = encode_hex(signer.sign(server_name.encode()))

    # Disabling sync because login is done before the transport is fully
    # initialized, i.e. the inventory rooms don't have the callbacks installed.
    client.login(username, password, sync=False)

    # Because this is the first login, the display name has to be set, this
    # prevents the impersonation metioned above. subsequent calls will reuse
    # the authentication token and the display name will be properly set.
    signature_bytes = signer.sign(client.user_id.encode())
    signature_hex = encode_hex(signature_bytes)

    user = client.get_user(client.user_id)
    current_display_name = user.get_display_name()

    # Only set the display name if necessary, since this is a slow operation.
    if current_display_name != signature_hex:
        user.set_display_name(signature_hex)

    log.debug(
        "Logged in",
        node=to_checksum_address(username),
        homeserver=server_name,
        server_url=server_url,
    )
    return user


def is_valid_username(username: str, server_name: str, user_id: str) -> bool:
    _match_user = re.match(f"^@{re.escape(username)}:{re.escape(server_name)}$", user_id)
    return bool(_match_user)


def login_with_token(client: GMatrixClient, user_id: str, access_token: str) -> Optional[User]:
    """Reuse an existing authentication code.

    If this succeeds it means the user has logged in the past, so we assume the
    display name is properly set and that there may be rooms open from past
    executions.
    """
    client.set_access_token(user_id=user_id, token=access_token)

    try:
        # Test the credentials. Any API that requries authentication
        # would be enough.
        client.api.get_devices()
    except MatrixRequestError as ex:
        log.debug(
            "Couldn't use previous login credentials",
            node=node_address_from_userid(client.user_id),
            prev_user_id=user_id,
            _exception=ex,
        )
        return None

    log.debug(
        "Success. Valid previous credentials",
        node=node_address_from_userid(client.user_id),
        user_id=user_id,
    )
    return client.get_user(client.user_id)


def login(client: GMatrixClient, signer: Signer, prev_auth_data: Optional[str] = None) -> User:
    """ Login with a matrix server.

    Params:
        client: GMatrixClient instance configured with desired homeserver.
        signer: Signer used to sign the password and displayname.
        prev_auth_data: Previously persisted authentication using the format "{user}/{password}".
    """
    server_url = client.api.base_url
    server_name = urlparse(server_url).netloc

    username = str(to_normalized_address(signer.address))

    if prev_auth_data and prev_auth_data.count("/") == 1:
        user_id, _, access_token = prev_auth_data.partition("/")

        if is_valid_username(username, server_name, user_id):
            user = login_with_token(client, user_id, access_token)

            if user is not None:
                return user
        else:
            log.debug(
                "Auth data is invalid, discarding",
                node=username,
                user_id=user_id,
                server_name=server_name,
            )

    return first_login(client, signer, username)


@cached(cache=LRUCache(128), key=attrgetter("user_id", "displayname"), lock=Semaphore())
def validate_userid_signature(user: User) -> Optional[Address]:
    """ Validate a userId format and signature on displayName, and return its address"""
    # display_name should be an address in the USERID_RE format
    match = USERID_RE.match(user.user_id)
    if not match:
        return None

    msg = (
        "The User instance provided to validate_userid_signature must have the "
        "displayname attribute set. Make sure to warm the value using the "
        "DisplayNameCache."
    )
    displayname = user.displayname
    assert displayname is not None, msg

    encoded_address = match.group(1)
    address: Address = to_canonical_address(encoded_address)

    try:
        if DISPLAY_NAME_HEX_RE.match(displayname):
            signature_bytes = decode_hex(displayname)
        else:
            return None
        recovered = recover(data=user.user_id.encode(), signature=Signature(signature_bytes))
        if not (address and recovered and recovered == address):
            return None
    except (
        DecodeError,
        TypeError,
        InvalidSignature,
        MatrixRequestError,
        json.decoder.JSONDecodeError,
    ):
        return None
    return address


def sort_servers_closest(
    servers: Sequence[str],
    max_timeout: float = 3.0,
    samples_per_server: int = 3,
    sample_delay: float = 0.125,
) -> Dict[str, float]:
    """Sorts a list of servers by http round-trip time

    Params:
        servers: sequence of http server urls
    Returns:
        sequence of pairs of url,rtt in seconds, sorted by rtt, excluding failed and excessively
        slow servers (possibly empty)

    The default timeout was chosen after measuring the long tail of the development matrix servers.
    Under no stress, servers will have a very long tail of up to 2.5 seconds (measured 15/01/2020),
    which can lead to failure during startup if the timeout is too low.
    This increases the timeout so that the network hiccups won't cause Raiden startup failures.
    """
    if not {urlparse(url).scheme for url in servers}.issubset({"http", "https"}):
        raise TransportError("Invalid server urls")

    rtt_greenlets = set(
        spawn_named(
            "get_average_http_response_time",
            get_average_http_response_time,
            url=server_url,
            samples=samples_per_server,
            sample_delay=sample_delay,
        )
        for server_url in servers
    )

    total_timeout = samples_per_server * (max_timeout + sample_delay)

    results = []
    for greenlet in gevent.iwait(rtt_greenlets, timeout=total_timeout):
        result = greenlet.get()
        if result is not None:
            results.append(result)

    gevent.killall(rtt_greenlets)

    if not results:
        raise TransportError(
            f"No Matrix server available with good latency, requests takes more "
            f"than {max_timeout} seconds."
        )

    server_url_to_rtt = dict(sorted(results, key=itemgetter(1)))
    log.debug("Available Matrix homeservers", servers=server_url_to_rtt)
    return server_url_to_rtt


def make_client(
    handle_messages_callback: Callable[[MatrixSyncMessages], bool],
    handle_member_join_callback: Callable[[Room], None],
    servers: List[str],
    *args: Any,
    **kwargs: Any,
) -> GMatrixClient:
    """Given a list of possible servers, chooses the closest available and create a GMatrixClient

    Params:
        servers: list of servers urls, with scheme (http or https)
        Rest of args and kwargs are forwarded to GMatrixClient constructor
    Returns:
        GMatrixClient instance for one of the available servers
    """
    if len(servers) > 1:
        sorted_servers = sort_servers_closest(servers)
        log.debug("Selecting best matrix server", sorted_servers=sorted_servers)
    elif len(servers) == 1:
        sorted_servers = {servers[0]: 0}
    else:
        raise TransportError("No valid servers list given")

    last_ex = None
    for server_url, rtt in sorted_servers.items():
        client = GMatrixClient(
            handle_messages_callback, handle_member_join_callback, server_url, *args, **kwargs
        )

        retries = 3
        while retries:
            retries -= 1
            try:
                client.api._send("GET", "/versions", api_path="/_matrix/client")
            except MatrixRequestError as ex:
                log.warning(
                    "Matrix server returned an error, retrying",
                    server_url=server_url,
                    _exception=ex,
                )
                last_ex = ex
            except MatrixError as ex:
                log.warning("Selected server not usable", server_url=server_url, _exception=ex)
                last_ex = ex
                retries = 0
            else:
                log.info(
                    "Using Matrix server",
                    server_url=server_url,
                    server_ident=client.api.server_ident,
                    average_rtt=rtt,
                )
                return client

    raise TransportError(
        "Unable to find a reachable Matrix server. Please check your network connectivity."
    ) from last_ex


def make_room_alias(chain_id: ChainID, *suffixes: str) -> str:
    """Given a chain_id and any number of suffixes (broadcast room names, pair of addresses),
    compose and return the canonical room name for raiden network

    network name from raiden_contracts.constants.ID_TO_CHAINNAME is used for name, if available,
    else numeric id
    Params:
        chain_id: numeric blockchain id for that room, as raiden rooms are per-chain specific
        *suffixes: one or more suffixes for the name
    Returns:
        Qualified full room name. e.g.:
            make_room_alias(3, 'discovery') == 'raiden_ropsten_discovery'
    """
    network_name = ID_TO_CHAINNAME.get(chain_id, str(chain_id))
    return ROOM_NAME_SEPARATOR.join([ROOM_NAME_PREFIX, network_name, *suffixes])


def validate_and_parse_message(data: Any, peer_address: Address) -> List[Message]:
    messages: List[Message] = list()

    if not isinstance(data, str):
        log.warning(
            "Received Message body not a string",
            message_data=data,
            peer_address=to_checksum_address(peer_address),
        )
        return []

    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            message = cached_deserialize(line)
        except SerializationError as ex:
            log.warning(
                "Not a valid Message",
                message_data=line,
                peer_address=to_checksum_address(peer_address),
                _exc=ex,
            )
            continue
        if not isinstance(message, SignedMessage):
            log.warning(
                "Message not a SignedMessage!",
                message=message,
                peer_address=to_checksum_address(peer_address),
            )
            continue
        if message.sender != peer_address:
            log.warning(
                "Message not signed by sender!",
                message=message,
                signer=message.sender,
                peer_address=to_checksum_address(peer_address),
            )
            continue
        messages.append(message)

    return messages


def my_place_or_yours(our_address: Address, partner_address: Address) -> Address:
    """Convention to compare two addresses. Compares lexicographical
    order and returns the preceding address """

    if our_address == partner_address:
        raise ValueError("Addresses to compare must differ")
    sorted_addresses = sorted([our_address, partner_address])
    return sorted_addresses[0]


def make_message_batches(
    message_texts: Iterable[str], _max_batch_size: int = MATRIX_MAX_BATCH_SIZE
) -> Generator[str, None, None]:
    """ Group messages into newline separated batches not exceeding ``_max_batch_size``. """
    current_batch: List[str] = []
    size = 0
    for message_text in message_texts:
        if size + len(message_text) > _max_batch_size:
            if size == 0:
                # A single message exceeds the maximum batch size. This should not happen.
                raise TransportError(
                    f"Message exceeds batch size. Size: {len(message_text)}, "
                    f"Max: {MATRIX_MAX_BATCH_SIZE}, Message: {message_text}"
                )
            yield "\n".join(current_batch)
            current_batch = []
            size = 0
        current_batch.append(message_text)
        size += len(message_text)
    if current_batch:
        yield "\n".join(current_batch)
