import json
import re
import time
from binascii import Error as DecodeError
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import lru_cache
from operator import itemgetter
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

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
from gevent.lock import Semaphore
from matrix_client.errors import MatrixError, MatrixRequestError

from raiden.api.v1.encoding import CapabilitiesSchema
from raiden.constants import DeviceIDs
from raiden.exceptions import InvalidSignature, SerializationError, TransportError
from raiden.messages.abstract import Message, RetrieableMessage, SignedMessage
from raiden.messages.synchronization import Processed
from raiden.network.transport.matrix.client import (
    GMatrixClient,
    MatrixMessage,
    User,
    node_address_from_userid,
)
from raiden.network.utils import get_average_http_response_time
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.utils.gevent import spawn_named
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    MessageID,
    Signature,
    T_UserID,
    UserID,
    cast,
    typecheck,
)

log = structlog.get_logger(__name__)
cached_deserialize = lru_cache()(MessageSerializer.deserialize)

JOIN_RETRIES = 10
USERID_RE = re.compile(r"^@(0x[0-9a-f]{40})(?:\.[0-9a-f]{8})?(?::.+)?$")
DISPLAY_NAME_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")
# The maximum matrix event size is 65 kB. Since events are larger than just the message
# content we chose a conservative value
MATRIX_MAX_BATCH_SIZE = 50_000
JSONResponse = Dict[str, Any]
capabilities_schema = CapabilitiesSchema()


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


def is_valid_userid_for_address(user_id: Any, address: Address) -> bool:
    try:
        typecheck(user_id, T_UserID)
    except ValueError:
        return False
    user_id_address = address_from_userid(user_id)
    if not user_id_address:
        return False
    return address == user_id_address


def get_user_id_from_metadata(
    address: Address, address_metadata: AddressMetadata = None
) -> Optional[UserID]:
    """Get user-id from the address-metadata, if it is valid and present.

    This will take the information from an optional AddressMetadata dictionary.
    If the address_metadata is present and the user-id within that metadata is
    valid and present for the specified address, the user-id will get returned.
    """
    if address_metadata is not None:
        user_id = address_metadata.get("user_id")
        if is_valid_userid_for_address(user_id, address):
            user_id = cast(UserID, user_id)
            return user_id
    return None


class DisplayNameCache:
    def __init__(self) -> None:
        self.userid_to_displayname: Dict[str, str] = {}

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
                            "Ignoring Matrix error in `get_display_name`",
                            exc_info=ex,
                            user_id=user.user_id,
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


def first_login(
    client: GMatrixClient,
    signer: Signer,
    username: str,
    capabilities: Dict,
    device_id: DeviceIDs,
) -> User:
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
    client.login(username, password, sync=False, device_id=device_id.value)
    client.api.disable_push_notifications()

    # Because this is the first login, the display name has to be set, this
    # prevents the impersonation mentioned above. subsequent calls will reuse
    # the authentication token and the display name will be properly set.
    signature_bytes = signer.sign(client.user_id.encode())
    signature_hex = encode_hex(signature_bytes)

    user = client.get_user(client.user_id)

    try:
        current_display_name = user.get_display_name()
    except MatrixRequestError as ex:
        # calling site
        log.error(
            "Ignoring Matrix error in `get_display_name`",
            exc_info=ex,
            user_id=user.user_id,
        )
        current_display_name = ""

    # Only set the display name if necessary, since this is a slow operation.
    if current_display_name != signature_hex:
        user.set_display_name(signature_hex)

    try:
        current_capabilities = client.api.get_avatar_url(client.user_id) or ""
    except MatrixRequestError as ex:
        log.error(
            "Ignoring Matrix error in `get_avatar_url`",
            exc_info=ex,
            user_id=user.user_id,
        )
        current_capabilities = ""

    # Only set the capabilities if necessary.
    cap_str = capabilities.get("capabilities", "mxc://")
    if current_capabilities != cap_str:
        user.set_avatar_url(cap_str)

    log.debug(
        "Logged in",
        node=to_checksum_address(username),
        homeserver=server_name,
        server_url=server_url,
        capabilities=capabilities,
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


def login(
    client: GMatrixClient,
    signer: Signer,
    device_id: DeviceIDs,
    prev_auth_data: Optional[str] = None,
    capabilities: Dict[str, Any] = None,
) -> User:
    """Login with a matrix server.

    Params:
        client: GMatrixClient instance configured with desired homeserver.
        signer: Signer used to sign the password and displayname.
        prev_auth_data: Previously persisted authentication using the format "{user}/{password}".
    """
    if capabilities is None:
        capabilities = {}
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

    try:
        cap: Dict = capabilities_schema.dump({"capabilities": capabilities})
    except ValueError:
        raise Exception("error serializing")
    return first_login(client, signer, username, cap, device_id)


def validate_userid_signature(user: User) -> Optional[Address]:
    """Validate a userId format and signature on displayName, and return its address"""
    return validate_user_id_signature(user.user_id, user.displayname)


@cached(cache=LRUCache(128), lock=Semaphore())  # noqa E501
def validate_user_id_signature(user_id: UserID, displayname: Optional[str]) -> Optional[Address]:
    # display_name should be an address in the USERID_RE format
    match = USERID_RE.match(user_id)
    if not match:
        log.warning("Invalid user id", user=user_id)
        return None

    if displayname is None:
        log.warning("Displayname not set", user=user_id)
        return None

    encoded_address = match.group(1)
    address: Address = to_canonical_address(encoded_address)

    try:
        if DISPLAY_NAME_HEX_RE.match(displayname):
            signature_bytes = decode_hex(displayname)
        else:
            log.warning("Displayname invalid format", user=user_id, displayname=displayname)
            return None
        recovered = recover(data=user_id.encode(), signature=Signature(signature_bytes))
        if not (address and recovered and recovered == address):
            log.warning("Unexpected signer of displayname", user=user_id)
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
    handle_messages_callback: Callable[[List[MatrixMessage]], bool],
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
            handle_messages_callback,
            server_url,
            *args,
            **kwargs,
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


def validate_and_parse_message(data: Any, peer_address: Address) -> List[Message]:
    messages: List[Message] = []

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
            message = cached_deserialize(line, peer_address)
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
    order and returns the preceding address"""

    if our_address == partner_address:
        raise ValueError("Addresses to compare must differ")
    sorted_addresses = sorted([our_address, partner_address])
    return sorted_addresses[0]


def make_message_batches(
    message_texts: Iterable[str], _max_batch_size: int = MATRIX_MAX_BATCH_SIZE
) -> Generator[str, None, None]:
    """Group messages into newline separated batches not exceeding ``_max_batch_size``."""
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


def make_user_id(address: Address, home_server: str) -> UserID:
    return UserID(f"@{to_normalized_address(address)}:{home_server}")
