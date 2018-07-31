import json
import re
from collections import defaultdict
from enum import Enum
from json import JSONDecodeError
from binascii import Error as DecodeError
from operator import itemgetter
from random import Random
from urllib.parse import urlparse
from eth_utils import (
    is_binary_address,
    to_normalized_address,
    to_canonical_address,
    to_checksum_address,
    encode_hex,
    decode_hex,
)

import gevent
import structlog
from gevent.event import AsyncResult
from matrix_client.errors import MatrixError, MatrixRequestError
from matrix_client.user import User
from cachetools import cachedmethod
from operator import attrgetter
from weakref import WeakKeyDictionary, WeakValueDictionary

from raiden import messages
from raiden.constants import ID_TO_NETWORKNAME
from raiden.encoding import signing
from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    UnknownTokenAddress,
    TransportError,
)
from raiden.messages import (
    decode as message_from_bytes,
    from_dict as message_from_dict,
    Delivered,
    Ping,
    Pong,
    SignedMessage,
    Message,
    Processed,
)
from raiden.network.transport.udp import udp_utils
from raiden.network.utils import get_http_rtt
from raiden.raiden_service import RaidenService
from raiden.transfer import events as transfer_events
from raiden.transfer.architecture import Event
from raiden.transfer.mediated_transfer import events as mediated_transfer_events
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NODE_NETWORK_UNKNOWN,
)
from raiden.transfer.state_change import ActionChangeNodeNetworkState, ReceiveDelivered
from raiden.message_handler import on_message
from raiden.utils import (
    eth_sign_sha3,
    pex,
)
from raiden.utils.typing import (
    Dict,
    Set,
    Tuple,
    List,
    Optional,
    Address,
    Callable,
    Mapping,
    TypeVar,
    Union,
    Type,
)
from raiden_libs.network.matrix import GMatrixClient, Room


log = structlog.get_logger(__name__)

_CT = TypeVar('CT')  # class type
_CIT = Union[_CT, Type[_CT]]  # class or instance type
_RT = TypeVar('RT')  # return type
_CacheT = Mapping[Tuple, _RT]  # cache type (mapping)


def _cachegetter(
        attr: str,
        cachefactory: Callable[[], _CacheT] = WeakKeyDictionary,  # WeakKewDict best for properties
) -> Callable[[_CIT], _CacheT]:
    """Returns a safer attrgetter which constructs the missing object with cachefactory

    May be used for normal methods, classmethods and properties, as default
    factory is a WeakKeyDictionary (good for storing weak-refs for self or cls).
    It may also safely be used with staticmethods, if first parameter is an object
    on which the cache will be stored.
    Better when used with key getter. If it's a tuple, you should use e.g. cachefactory=dict
    Example usage with cachetools.cachedmethod:
    class Foo:
        @property
        @cachedmethod(_cachegetter("__bar_cache"))
        def bar(self) -> _RT:
            return 2+3
    """
    def cachegetter(cls_or_obj: _CIT) -> _CacheT:
        cache = getattr(cls_or_obj, attr, None)
        if cache is None:
            cache = cachefactory()
            setattr(cls_or_obj, attr, cache)
        return cache
    return cachegetter


class UserPresence(Enum):
    ONLINE = 'online'
    UNAVAILABLE = 'unavailable'
    OFFLINE = 'offline'
    UNKNOWN = 'unknown'


class MatrixTransport:
    _room_prefix = 'raiden'
    _room_sep = '_'
    _userid_re = re.compile(r'^@(0x[0-9a-f]{40})(?:\.[0-9a-f]{8})?(?::.+)?$')

    def __init__(self, config: dict):
        self._bound_logger = None
        self._raiden_service: RaidenService = None
        while True:
            self._server_url: str = self._select_server(config)
            self._server_name = config.get('server_name', urlparse(self._server_url).hostname)
            client_class = config.get('client_class', GMatrixClient)
            self._client: GMatrixClient = client_class(
                self._server_url,
                max_retries=5,
                pool_maxsize=4,
            )
            try:
                self._client.api._send('GET', '/versions', api_path='/_matrix/client')
                break
            except MatrixError as ex:
                if config['server'] != 'auto':
                    raise TransportError(
                        f"Could not connect to requested server '{config['server']}'",
                    ) from ex

                config['available_servers'].remove(self._server_url)
                if len(config['available_servers']) == 0:
                    raise TransportError(
                        f"Unable to find a reachable Matrix server. "
                        f"Please check your network connectivity.",
                    ) from ex
                log.warning(f"Selected server '{self._server_url}' not usable. Retrying.")

        self.greenlets = list()

        self._discovery_room: Room = None

        self._messageids_to_asyncresult: Dict[Address, AsyncResult] = dict()
        # partner need to be in this dict to be listened on
        self._address_to_userids: Dict[Address, Set[str]] = defaultdict(set)
        self._address_to_presence: Dict[Address, UserPresence] = dict()
        self._userid_to_presence: Dict[str, UserPresence] = dict()

        self._discovery_room_alias = None
        self._discovery_room_alias_full = None
        self._login_retry_wait = config.get('login_retry_wait', 0.5)
        self._logout_timeout = config.get('logout_timeout', 10)

        self._running = False
        self._health_semaphore = gevent.lock.Semaphore()

        self._client.add_invite_listener(self._handle_invite)
        self._client.add_presence_listener(self._handle_presence_change)

    def start(
        self,
        raiden_service: RaidenService,
        queueids_to_queues: Dict[Tuple[Address, str], List[Event]],
    ):
        self._running = True
        self._raiden_service = raiden_service
        config = raiden_service.config['matrix']

        self._discovery_room_alias = self._make_room_alias(
            config['discovery_room']['alias_fragment'],
        )
        self._discovery_room_alias_full = (
            f'#{self._discovery_room_alias}:{config["discovery_room"]["server"]}'
        )

        self._login_or_register()
        self._inventory_rooms()

        self._join_discovery_room()
        if not self._discovery_room.listeners:
            self._discovery_room.add_listener(
                self._handle_discovery_membership_event,
                'm.room.member',
            )

        # TODO: Add (better) error handling strategy
        self._client.start_listener_thread()
        self._client.sync_thread.link_exception(self._client_exception_handler)
        self.greenlets.append(self._client.sync_thread)

        # TODO: Add greenlet that regularly refreshes our presence state
        self._client.set_presence_state(UserPresence.ONLINE.value)

        gevent.spawn_later(1, self._ensure_room_peers)
        gevent.spawn_later(2, self._send_queued_messages, queueids_to_queues)
        self.log.info('TRANSPORT STARTED')

    def start_health_check(self, node_address):
        if not self._running:
            return
        node_address_hex = to_normalized_address(node_address)
        self.log.debug('HEALTHCHECK', peer_address=node_address_hex)
        with self._health_semaphore:
            candidates = [
                self._get_user(user)
                for user in self._client.search_user_directory(node_address_hex)
            ]
            user_ids = {
                user.user_id
                for user in candidates
                if self._validate_userid_signature(user) == node_address
            }
            self._address_to_userids[node_address].update(user_ids)

            # Ensure network state is updated in case we already know about the user presences
            # representing the target node
            self._update_address_presence(node_address)

    def send_async(
        self,
        receiver_address: Address,
        queue_name: bytes,
        message: Message,
    ):
        if not self._running:
            return
        self.log.info(
            'SEND ASYNC',
            receiver_address=to_normalized_address(receiver_address),
            message=message,
            queue_name=queue_name,
        )
        if not is_binary_address(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError(
                'Do not use send_async for {} messages'.format(message.__class__.__name__),
            )

        message_id = message.message_identifier
        async_result = AsyncResult()
        if isinstance(message, Processed):
            async_result.set(True)  # processed messages shouldn't get a Delivered reply
            self._send_immediate(receiver_address, json.dumps(message.to_dict()))
        else:
            self._messageids_to_asyncresult[message_id] = async_result
            self._send_with_retry(receiver_address, async_result, json.dumps(message.to_dict()))

    def stop_and_wait(self):
        if not self._running:
            return
        self._running = False
        self._client.set_presence_state(UserPresence.OFFLINE.value)
        self._client.stop_listener_thread()

        # Set all the pending results to False, this will also
        # cause pending retries to be aborted
        for async_result in self._messageids_to_asyncresult.values():
            async_result.set(False)

        try:
            self._client.join_and_logout(self.greenlets, timeout=self._logout_timeout)
        except RuntimeError as error:
            self.log.critical(str(error))

    @property
    def log(self):
        if self._bound_logger:
            return self._bound_logger
        if not getattr(self, '_client', None) or not getattr(self._client, 'user_id', None):
            return log
        self._bound_logger = log.bind(current_user=self._client.user_id)
        return self._bound_logger

    @property
    def _network_name(self) -> str:
        return ID_TO_NETWORKNAME.get(
            self._raiden_service.chain.network_id,
            str(self._raiden_service.chain.network_id),
        )

    def _login_or_register(self):
        # password is signed server address
        password = encode_hex(self._sign(self._server_name.encode()))
        seed = int.from_bytes(self._sign(b'seed')[-32:], 'big')
        rand = Random()  # deterministic, random secret for username suffixes
        rand.seed(seed)
        # try login and register on first 5 possible accounts
        for i in range(5):
            base_username = to_normalized_address(self._raiden_service.address)
            username = base_username
            if i:
                username = f'{username}.{rand.randint(0, 0xffffffff):08x}'

            try:
                self._client.sync_token = None
                self._client.login(username, password)
                self.log.info(
                    'LOGIN',
                    homeserver=self._server_name,
                    server_url=self._server_url,
                    username=username,
                )
                break
            except MatrixRequestError as ex:
                if ex.code != 403:
                    raise
                self.log.debug(
                    'Could not login. Trying register',
                    homeserver=self._server_name,
                    server_url=self._server_url,
                    username=username,
                )
                try:
                    self._client.register_with_password(username, password)
                    self.log.info(
                        'REGISTER',
                        homeserver=self._server_name,
                        server_url=self._server_url,
                        username=username,
                    )
                    break
                except MatrixRequestError as ex:
                    if ex.code != 400:
                        raise
                    self.log.debug('Username taken. Continuing')
                    continue
        else:
            raise ValueError('Could not register or login!')
        # TODO: persist access_token, to avoid generating a new login every time
        name = encode_hex(self._sign(self._client.user_id.encode()))
        self._get_user(self._client.user_id).set_display_name(name)

    def _join_discovery_room(self):
        discovery_cfg = self._raiden_service.config['matrix']['discovery_room']
        try:
            discovery_room = self._client.join_room(self._discovery_room_alias_full)
        except MatrixRequestError as ex:
            if ex.code != 404:
                raise
            # Room doesn't exist
            if discovery_cfg['server'] != self._server_name:
                raise RuntimeError(
                    f"Discovery room {self._discovery_room_alias_full} not found and can't be "
                    f"created on a federated homeserver {self._server_name!r}.",
                )
            discovery_room = self._client.create_room(self._discovery_room_alias, is_public=True)
        self._discovery_room = discovery_room
        # Populate initial members
        self._discovery_room.get_joined_members()

    def _inventory_rooms(self):
        for room in self._client.rooms.values():
            if any(self._discovery_room_alias in alias for alias in room.aliases):
                continue
            # we add listener for all valid rooms, _handle_message should ignore them
            # if msg sender weren't start_health_check'ed yet
            if not room.listeners:
                room.add_listener(self._handle_message, 'm.room.message')
            self.log.debug(
                'ROOM',
                room=room,
                aliases=room.aliases,
            )

    def _handle_invite(self, room_id: str, state: dict):
        """ Join all invited rooms """
        if not self._running:
            return
        invite_event = [
            event
            for event in state['events']
            if event['type'] == 'm.room.member' and
            event['content'].get('membership') == 'invite'
        ]
        if not invite_event:
            return
        invite_event = invite_event[0]
        user = self._get_user(invite_event['sender'])
        peer_address = self._validate_userid_signature(user)
        if not peer_address:
            self.log.warning(
                'Got invited to a room by invalid signed user - ignoring',
                room_id=room_id,
                user=user,
            )
            return
        # one must join to be able to fetch room alias
        room = self._client.join_room(room_id)
        if not room.listeners:
            room.add_listener(self._handle_message, 'm.room.message')
        self._set_room_id_for_address(peer_address, room_id)
        self.log.debug(
            'Invited and joined a room',
            room_id=room_id,
            aliases=room.aliases,
            peer=to_checksum_address(peer_address),
        )

    def _handle_message(self, room, event):
        """ Handle text messages sent to listening rooms """
        if (
                event['type'] != 'm.room.message' or
                event['content']['msgtype'] != 'm.text' or
                not self._running
        ):
            # Ignore non-messages and non-text messages
            return

        sender_id = event['sender']

        if sender_id == self._client.user_id:
            # Ignore our own messages
            return

        user = self._get_user(sender_id)
        peer_address = self._validate_userid_signature(user)
        if not peer_address:
            # invalid user displayName signature
            return
        old_room = self._get_room_id_for_address(peer_address)
        if old_room != room.room_id:
            self.log.debug(
                'received message triggered new room for peer',
                peer_user=user.user_id,
                peer_address=to_checksum_address(peer_address),
                old_room=old_room,
                room=room,
            )
            self._set_room_id_for_address(peer_address, room.room_id)

        if peer_address not in self._address_to_userids:
            # user not start_health_check'ed
            return

        data = event['content']['body']
        if data.startswith('0x'):
            try:
                message = message_from_bytes(decode_hex(data))
                assert message
            except (DecodeError, AssertionError) as ex:
                self.log.warning(
                    "Can't parse message binary data",
                    message_data=data,
                    peer_address=pex(peer_address),
                    exception=ex,
                )
                return
        else:
            try:
                message_dict = json.loads(data)
                self.log.debug('MESSAGE_DATA', data=message_dict)
                message = message_from_dict(message_dict)
            except (UnicodeDecodeError, JSONDecodeError) as ex:
                self.log.warning(
                    "Can't parse message data JSON",
                    message_data=data,
                    peer_address=pex(peer_address),
                    exception=ex,
                )
                return

        if isinstance(message, Delivered):
            self._receive_delivered(message)
        elif isinstance(message, Ping):
            self.log.warning(
                'Not required Ping received',
                message=data,
            )
        elif isinstance(message, SignedMessage):
            if message.sender != peer_address:
                self.log.warning(
                    'Message not signed by sender!',
                    message=message,
                    signer=message.sender,
                    peer_address=peer_address,
                )
                return
            self._receive_message(message)
        else:
            self.log.error(
                'Invalid message',
                message=data,
            )

    def _receive_delivered(self, delivered: Delivered):
        # FIXME: The signature doesn't seem to be verified - check in UDPTransport as well
        self._raiden_service.handle_state_change(
            ReceiveDelivered(delivered.delivered_message_identifier),
        )

        async_result = self._messageids_to_asyncresult.pop(
            delivered.delivered_message_identifier,
            None,
        )

        if async_result is not None:
            async_result.set(True)
            self.log.debug(
                'DELIVERED MESSAGE RECEIVED',
                node=pex(self._raiden_service.address),
                receiver=pex(delivered.sender),
                message_identifier=delivered.delivered_message_identifier,
            )

        else:
            self.log.debug(
                'DELIVERED MESSAGE UNKNOWN',
                node=pex(self._raiden_service.address),
                message_identifier=delivered.delivered_message_identifier,
            )

    def _receive_message(self, message):
        self.log.info(
            'MESSAGE RECEIVED',
            node=pex(self._raiden_service.address),
            message=message,
            sender=pex(message.sender),
        )

        try:
            if on_message(self._raiden_service, message) and not isinstance(message, Processed):
                # TODO: Maybe replace with Matrix read receipts.
                #       Unfortunately those work on an 'up to' basis, not on individual messages
                #       which means that message order is important which isn't guaranteed between
                #       federated servers.
                #       See: https://matrix.org/docs/spec/client_server/r0.3.0.html#id57
                delivered_message = Delivered(message.message_identifier)
                self._raiden_service.sign(delivered_message)
                self._send_immediate(message.sender, json.dumps(delivered_message.to_dict()))

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            self.log.warn('Exception while processing message', exc_info=True)
            return

    def _send_queued_messages(
        self,
        queueids_to_queues: Dict[Tuple[Address, str], List[Event]],
    ):
        for (address, queue_name), events in queueids_to_queues.items():
            node_address = self._raiden_service.address
            for event in events:
                message = _event_to_message(event, node_address)
                self._raiden_service.sign(message)
                self.start_health_check(address)
                self.send_async(address, queue_name, message)

    def _send_with_retry(
        self,
        receiver_address: Address,
        async_result: AsyncResult,
        data: str,
    ):
        def retry():
            if not self._running:
                return
            timeout_generator = udp_utils.timeout_exponential_backoff(
                self._raiden_service.config['transport']['retries_before_backoff'],
                self._raiden_service.config['transport']['retry_interval'],
                self._raiden_service.config['transport']['retry_interval'] * 10,
            )
            while async_result.value is None:
                self._send_immediate(receiver_address, data)
                gevent.sleep(next(timeout_generator))

        self.greenlets.append(gevent.spawn(retry))

    def _send_immediate(self, receiver_address, data):
        # FIXME: Send message to all matching rooms
        if not self._running:
            return
        room = self._get_room_for_address(receiver_address)
        if not room:
            return
        self.log.debug('SEND', room=room, data=data)
        room.send_text(data)

    def _get_room_for_address(
        self,
        address: Address,
        allow_missing_peers=False,
    ) -> Optional[Room]:
        if not self._running:
            return
        address_hex = to_normalized_address(address)
        assert address and address in self._address_to_userids,\
            f'address not health checked: me: {self._client.user_id}, peer: {address_hex}'
        room_id = self._get_room_id_for_address(address)
        if room_id:
            return self._client.rooms[room_id]

        # The addresses are being sorted to ensure the same channel is used for both directions
        # of communication.
        # e.g.: raiden_ropsten_0xaaaa_0xbbbb
        address_pair = sorted([
            to_normalized_address(address)
            for address in [address, self._raiden_service.address]
        ])
        room_name = self._make_room_alias(*address_pair)

        # no room with expected name => create one and invite peer
        candidates = [
            self._get_user(user)
            for user in self._client.search_user_directory(address_hex)
        ]

        # filter candidates
        peers = [
            user
            for user in candidates
            if self._validate_userid_signature(user) == address
        ]
        if not peers and not allow_missing_peers:
            self.log.error('No valid peer found', peer_address=address_hex)
            return

        self._address_to_userids[address].update({user.user_id for user in peers})

        room = self._get_unlisted_room(room_name, invitees=peers)
        self._set_room_id_for_address(address, room.room_id)

        for user in peers:
            self._maybe_invite_user(user)

        if not room.listeners:
            room.add_listener(self._handle_message, 'm.room.message')

        self.log.info(
            'CHANNEL ROOM',
            peer_address=to_normalized_address(address),
            room=room,
        )
        return room

    def _get_unlisted_room(self, room_name, invitees):
        """Obtain a room that cannot be found by search_room_directory."""
        room_name_full = f'#{room_name}:{self._server_name}'
        room_not_found = False

        for _ in range(10):
            if room_not_found:
                try:
                    room = self._client.create_room(
                        room_name,
                        invitees=[user.user_id for user in invitees],
                        is_public=True,  # FIXME: debug only
                    )
                except MatrixRequestError as error:
                    if error.code == 409:
                        message = 'seems to have been created by peer meanwhile.'
                    else:
                        message = f'{error.code} {error.content}'
                    self.log.info(f'Error creating room {room_name}: {message}. '
                                  f'Retrying to join...')
                    room_not_found = False
                else:
                    self.log.info('Room created successfully', room=room, invitees=invitees)
                    return room
            else:
                try:
                    room = self._client.join_room(room_name_full)
                except MatrixRequestError as error:
                    if error.code == 404:
                        self.log.info(
                            f'Room {room_name_full} not found, trying to create it.',
                            error=error,
                        )
                        room_not_found = True
                    else:
                        self.log.info(f'Error joining room {room_name}: '
                                      f'{error.content} {error.code}')
                else:
                    self.log.info('Room joined successfully', room=room)
                    return room
            gevent.sleep(self._login_retry_wait)

        room = self._client.create_room(
            None,
            invitees=[user.user_id for user in invitees],
            is_public=True,  # FIXME: debug only
        )
        log.warning(
            'Could not create nor join a named room. Successfuly created an unnamed one',
            room=room,
            invitees=invitees,
        )
        return room

    def _make_room_alias(self, *parts):
        return self._room_sep.join([self._room_prefix, self._network_name, *parts])

    def _handle_presence_change(self, event):
        """
        Update node network reachability from presence events.

        Due to the possibility of nodes using accounts on multiple homeservers a composite
        address state is synthesised from the cached individual user presence state.
        """
        if not self._running:
            return
        user_id = event['sender']
        if event['type'] != 'm.presence' or user_id == self._client.user_id:
            return

        user = self._get_user(user_id)
        address = self._validate_userid_signature(user)
        if not address:
            # Malformed address - skip
            return

        # not a user we've started healthcheck, skip
        if address not in self._address_to_userids:
            return
        self._address_to_userids[address].add(user_id)
        # maybe inviting user used to also possibly invite user's from discovery presence changes
        self._maybe_invite_user(user)

        new_state = UserPresence(event['content']['presence'])
        if new_state == self._userid_to_presence.get(user_id):
            return

        self._userid_to_presence[user_id] = new_state
        self._update_address_presence(address)

    def _get_user_presence(self, user_id: str) -> UserPresence:
        if user_id not in self._userid_to_presence:
            self._userid_to_presence[user_id] = UserPresence(
                self._client.get_user_presence(user_id),
            )
        return self._userid_to_presence[user_id]

    def _update_address_presence(self, address):
        """ Update synthesized address presence state from user presence state """
        composite_presence = {
            self._get_user_presence(uid)
            for uid
            in self._address_to_userids.get(address, set())
        }

        # Iterate over UserPresence in definition order and pick first matching state
        new_state = UserPresence.UNKNOWN
        for presence in UserPresence.__members__.values():
            if presence in composite_presence:
                new_state = presence
                break

        if new_state == self._address_to_presence.get(address):
            return
        self.log.debug(
            'Changing address presence state',
            address=to_normalized_address(address),
            prev_state=self._address_to_presence.get(address),
            state=new_state,
        )
        self._address_to_presence[address] = new_state

        if new_state is UserPresence.UNKNOWN:
            reachability = NODE_NETWORK_UNKNOWN
        elif new_state is UserPresence.OFFLINE:
            reachability = NODE_NETWORK_UNREACHABLE
        else:
            reachability = NODE_NETWORK_REACHABLE
            # The Matrix presence status 'unavailable' just means that the user has been inactive
            # for a while. So a user with UserPresence.UNAVAILABLE is still 'reachable' to us.

        state_change = ActionChangeNodeNetworkState(address, reachability)
        self._raiden_service.handle_state_change(state_change)

    def _handle_discovery_membership_event(self, room, event):
        if event['type'] != 'm.room.member' or not self._running:
            return

        state = event['content']['membership']
        if state != 'join':
            return
        user_id = event['sender']
        user = self._get_user(user_id)
        address = self._validate_userid_signature(user)
        if not address:
            # Malformed address - skip
            return

        # not a user we've started healthcheck, skip
        if address not in self._address_to_userids:
            return
        self._address_to_userids[address].add(user_id)
        self.log.debug('discovery member change', state=state, user=user)
        self._maybe_invite_user(user)

    def _ensure_room_peers(self):
        """ Check all members of discovery channel for matches to existing rooms """
        for member in self._discovery_room.get_joined_members():
            member = self._get_user(member)
            self._maybe_invite_user(member)

    def _maybe_invite_user(self, user):
        address = self._validate_userid_signature(user)
        if not address:
            return

        room_id = self._get_room_id_for_address(address)
        if not room_id:
            return

        room = self._client.rooms[room_id]
        if not room._members:
            room.get_joined_members()
        if user.user_id not in room._members:
            self.log.debug('INVITE', user=user, room=room)
            room.invite_user(user.user_id)

    def _select_server(self, config):
        server = config['server']
        if server.startswith('http'):
            return server
        elif server != 'auto':
            raise TransportError('Invalid matrix server specified (valid values: "auto" or a URL)')

        def _get_rtt(server_name):
            return server_name, get_http_rtt(server_name)

        get_rtt_jobs = [
            gevent.spawn(_get_rtt, server_name)
            for server_name
            in config['available_servers']
        ]
        gevent.joinall(get_rtt_jobs)
        sorted_servers = sorted(
            (job.value for job in get_rtt_jobs if job.value[1] is not None),
            key=itemgetter(1),
        )
        self.log.debug('Matrix homeserver RTT times', rtt_times=sorted_servers)
        if not sorted_servers:
            raise TransportError(
                'Could not select a Matrix server. No candidates remaining. '
                'Please check your network connectivity.',
            )
        best_server, rtt = sorted_servers[0]
        self.log.info(
            'Automatically selecting matrix homeserver based on RTT',
            homeserver=best_server,
            rtt=rtt,
        )
        return best_server

    def _client_exception_handler(self, greenlet):
        self._running = False
        try:
            greenlet.get()
        except MatrixError as ex:
            gevent.get_hub().handle_system_error(
                TransportError,
                TransportError(
                    f'Unexpected error while communicating with Matrix homeserver: {ex}',
                ),
            )

    def _sign(self, data: bytes) -> bytes:
        """ Use eth_sign compatible hasher to sign matrix data """
        return signing.sign(
            data,
            self._raiden_service.private_key,
            hasher=eth_sign_sha3,
        )

    @staticmethod
    def _recover(data: bytes, signature: bytes) -> Address:
        """ Use eth_sign compatible hasher to recover address from signed data """
        return signing.recover_address(
            data,
            signature=signature,
            hasher=eth_sign_sha3,
        )

    @staticmethod
    @cachedmethod(_cachegetter('__address_cache', dict), key=attrgetter('user_id', 'displayname'))
    def _validate_userid_signature(user: User) -> Optional[Address]:
        """ Validate a userId format and signature on displayName, and return its address"""
        # display_name should be an address in the self._userid_re format
        match = MatrixTransport._userid_re.match(user.user_id)
        if not match:
            return
        encoded_address: str = match.group(1)
        address: Address = to_canonical_address(encoded_address)
        try:
            recovered = MatrixTransport._recover(
                user.user_id.encode(),
                decode_hex(user.get_display_name()),
            )
            if not address or not recovered or recovered != address:
                return
        except (DecodeError, TypeError):
            return
        return address

    @cachedmethod(
        _cachegetter('__users_cache', WeakValueDictionary),
        key=lambda _, user: user.user_id if isinstance(user, User) else user,
    )
    def _get_user(self, user: Union[User, str]) -> User:
        """ Creates an User from an user_id, if none, or fetch a cached User """
        if not isinstance(user, User):
            user = self._client.get_user(user)
            user.get_display_name()
        return user

    def _set_room_id_for_address(self, address: Address, room_id: Optional[str]):
        """ Uses GMatrixClient.set_account_data to keep updated mapping of addresses->rooms """
        address_hex = to_checksum_address(address)
        _address_to_room_id = self._client.account_data.get('network.raiden.rooms', {})
        if room_id != _address_to_room_id.get(address_hex):
            if room_id:
                _address_to_room_id[address_hex] = room_id
            else:
                _address_to_room_id.pop(address_hex, None)
            self._client.set_account_data('network.raiden.rooms', _address_to_room_id)

    def _get_room_id_for_address(self, address: Address) -> Optional[str]:
        """ Uses GMatrixClient.get_account_data to get updated mapping of addresses->rooms """
        address_hex = to_checksum_address(address)
        room_id = self._client.account_data.get('network.raiden.rooms', {}).get(address_hex)
        if room_id and room_id not in self._client.rooms:
            self._set_room_id_for_address(address, None)
            return None
        return room_id


def _event_to_message(event, node_address):
    # FIXME: Replace with raiden-network/raiden#1424 once it's merged
    eventtypes_to_messagetype = {
        mediated_transfer_events.SendBalanceProof: messages.Secret,
        mediated_transfer_events.SendLockedTransfer: messages.LockedTransfer,
        mediated_transfer_events.SendRefundTransfer: messages.RefundTransfer,
        mediated_transfer_events.SendRevealSecret: messages.RevealSecret,
        mediated_transfer_events.SendSecretRequest: messages.SecretRequest,
        transfer_events.SendDirectTransfer: messages.DirectTransfer,
        transfer_events.SendProcessed: messages.Processed,
    }
    message_class = eventtypes_to_messagetype.get(type(event))
    if message_class is None:
        raise TypeError(f'Event type {type(event)} is not supported.')
    return message_class.from_event(event)
