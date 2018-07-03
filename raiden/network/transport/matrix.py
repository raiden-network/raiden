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
    encode_hex,
    decode_hex,
)

import gevent
import structlog
from gevent.event import AsyncResult
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User
from cachetools import cachedmethod
from operator import attrgetter
from weakref import WeakKeyDictionary

from raiden import messages
from raiden.constants import ID_TO_NETWORKNAME
from raiden.encoding import signing
from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    UnknownTokenAddress,
)
from raiden.messages import (
    decode as message_from_bytes,
    Delivered,
    from_dict as message_from_dict,
    Ping,
    SignedMessage,
    Pong,
    Message,
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
        self._raiden_service: RaidenService = None
        self._server_url: str = self._select_server(config)
        self._server_name = config.get('server_name', urlparse(self._server_url).hostname)
        client_class = config.get('client_class', GMatrixClient)
        self._client: GMatrixClient = client_class(self._server_url)

        self.greenlets = list()

        self._discovery_room: Room = None

        self._messageids_to_asyncresult: Dict[Address, AsyncResult] = dict()
        self._address_to_userids: Dict[Address, Set[str]] = defaultdict(set)
        self._address_to_presence: Dict[Address, UserPresence] = dict()
        self._userid_to_presence: Dict[str, UserPresence] = dict()
        self._address_to_roomid: Dict[Address, str] = dict()

        self._discovery_room_alias = None
        self._discovery_room_alias_full = None
        self._room_alias_re = None
        self._login_retry_wait = config.get('login_retry_wait', 0.5)
        self._logout_timeout = config.get('logout_timeout', 10)

        self._bound_logger = None
        self._running = False
        self._health_semaphore = gevent.lock.Semaphore()

    def start(
        self,
        raiden_service: RaidenService,
        queueids_to_queues: Dict[Tuple[Address, str], List[Event]],
    ):
        self._raiden_service = raiden_service
        room_alias_re = self._make_room_alias(
            '(?P<peer1>0x[a-zA-Z0-9]{40})',
            '(?P<peer2>0x[a-zA-Z0-9]{40})',
        )
        self._room_alias_re = re.compile(f'^#{room_alias_re}:(?P<server_name>.*)$')

        discovery_cfg = self._raiden_service.config['matrix']['discovery_room']
        self._discovery_room_alias = self._make_room_alias(discovery_cfg['alias_fragment'])
        self._discovery_room_alias_full = (
            f'#{self._discovery_room_alias}:{discovery_cfg["server"]}'
        )

        self._login_or_register()
        self._running = True
        self._inventory_rooms()

        self._client.add_invite_listener(self._handle_invite)
        self._client.add_presence_listener(self._handle_presence_change)
        # TODO: Add (better) error handling strategy
        self._client.start_listener_thread(exception_handler=lambda e: None)
        self.greenlets.append(self._client.sync_thread)

        # TODO: Add greenlet that regularly refreshes our presence state
        self._client.set_presence_state(UserPresence.ONLINE.value)

        # Important: Join the discovery room last to ensure we can react to invites
        self._join_discovery_room()
        self._discovery_room.add_listener(self._handle_discovery_membership_event, 'm.room.member')

        gevent.spawn_later(1, self._inventory_rooms)
        gevent.spawn_later(2, self._ensure_room_peers)
        gevent.spawn_later(3, self._send_queued_messages, queueids_to_queues)
        self.log.info('TRANSPORT STARTED')

    def start_health_check(self, node_address):
        if not self._running:
            return
        self.log.debug('HEALTHCHECK', peer_address=pex(node_address))
        node_address_hex = to_normalized_address(node_address)
        with self._health_semaphore:
            user_ids = {
                user.user_id
                for user
                in self._client.search_user_directory(node_address_hex)
                if self._validate_userid_signature(user)
            }
            self._address_to_userids[node_address].update(user_ids)

            # Ensure network state is updated in case we already know about the user presences
            # representing the target node
            self._update_address_presence(node_address)
            room = self._get_room_for_address(node_address, allow_missing_peers=True)
            if not room:
                self.log.warning('No room found or created for peer', peer=node_address_hex)

    def send_async(
        self,
        receiver_address: Address,
        queue_name: bytes,
        message: Message,
    ) -> AsyncResult:
        if not self._running:
            return
        self.log.debug(
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

        # Ignore duplicated messages
        message_id = message.message_identifier
        if message_id not in self._messageids_to_asyncresult:
            async_result = self._messageids_to_asyncresult[message_id] = AsyncResult()
            self._send_with_retry(receiver_address, async_result, json.dumps(message.to_dict()))

        return self._messageids_to_asyncresult[message_id]

    def stop_and_wait(self):
        if self._running:
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
        if not getattr(self._client, 'user_id', None):
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
        self._client.get_user(self._client.user_id).set_display_name(name)

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
        # Iterate over a copy so we can modify the room list
        for room_id, room in list(self._client.rooms.items()):
            if not room.canonical_alias:
                # Leave any rooms that don't have a canonical alias as they are not part of the
                # protocol
                self.log.warning('Leaving room without canonical alias', room=room)
                room.leave()
                continue
            # Don't listen for messages in the discovery room
            should_listen = room.canonical_alias != self._discovery_room_alias_full
            if should_listen:
                peer_address = self._get_peer_address_from_room(room.canonical_alias)
                if not peer_address:
                    self.log.warning(
                        "Member of a room we're not supposed to be a member of - ignoring",
                        room=room,
                        discovery=self._discovery_room_alias_full,
                    )
                    return
                self._address_to_roomid[peer_address] = room.room_id
                room.add_listener(self._handle_message)
            self.log.debug(
                'ROOM',
                room_id=room_id,
                aliases=room.aliases,
                listening=should_listen,
            )

    def _handle_invite(self, room_id: str, state: dict):
        """ Join all invited rooms """
        if not self._running:
            return
        # one must join to be able to fetch room alias
        room = self._client.join_room(room_id)
        if not room.canonical_alias:
            self.log.warning('Got invited to a room without canonical alias - ignoring', room=room)
            room.leave()
            return
        peer_address = self._get_peer_address_from_room(room.canonical_alias)
        if not peer_address:
            self.log.warning(
                'Got invited to a room we\'re not supposed to be a member of - ignoring',
                room=room,
            )
            room.leave()
            return
        self._address_to_roomid[peer_address] = room.room_id
        room.add_listener(self._handle_message, 'm.room.message')
        self.log.debug(
            'Invited to a room',
            room_id=room_id,
            aliases=room.aliases,
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

        user = self._client.get_user(sender_id)
        peer_address = self._validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                'INVALID SIGNATURE',
                user=user,
                name=user.get_display_name(),
            )
            return

        data = event['content']['body']
        if data.startswith('0x'):
            message = message_from_bytes(decode_hex(data))
            if not message:
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
            message_sender=pex(message.sender),
        )

        try:
            if on_message(self._raiden_service, message):
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
        self.log.debug(
            'DELIVERED',
            node=pex(self._raiden_service.address),
            to=pex(message.sender),
            message_identifier=message.message_identifier,
        )

    def _send_queued_messages(
        self,
        queueids_to_queues: Dict[Tuple[Address, str], List[Event]],
    ):
        def send_queue(address, events):
            if not self._running:
                return
            node_address = self._raiden_service.address
            for event in events:
                self.send_async('', address, _event_to_message(event, node_address))

        for (address, _queue_name), events in queueids_to_queues.items():
            # TODO: Check if we need to separate this by queue_name
            gevent.spawn(send_queue, address, events)

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
        receiver_address: Address,
        allow_missing_peers=False,
    ) -> Optional[Room]:
        if not self._running:
            return
        room_id = self._address_to_roomid.get(receiver_address)
        if room_id:
            room = self._client.rooms.get(room_id)
            if room:
                return room
            else:
                # Room is gone - remove from cache
                self._address_to_roomid.pop(receiver_address)

        # The addresses are being sorted to ensure the same channel is used for both directions
        # of communication.
        # e.g.: raiden_ropsten_0xaaaa_0xbbbb
        address_pair = sorted([
            to_normalized_address(address)
            for address in [receiver_address, self._raiden_service.address]
        ])
        room_name = self._make_room_alias(*address_pair)

        room_candidates = self._client.search_room_directory(room_name)
        if room_candidates:
            room = room_candidates[0]
            if room.room_id not in self._client.rooms:
                room = self._client.join_room(room.room_id)
        else:
            # no room with expected name => create one and invite peer
            address = to_normalized_address(receiver_address)
            candidates = self._client.search_user_directory(address)

            # filter candidates
            peers = [user for user in candidates if self._validate_userid_signature(user)]
            if not peers and not allow_missing_peers:
                self.log.error('No valid peer found', peer_address=address)
                return

            room = self._get_unlisted_room(room_name, invitees=[user.user_id for user in peers])

        room.add_listener(self._handle_message, 'm.room.message')
        self.log.info(
            'CHANNEL ROOM',
            peer_address=to_normalized_address(receiver_address),
            room=room,
        )
        self._address_to_roomid[receiver_address] = room.room_id
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
                        invitees=invitees,
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
                    self.log.info(f'Room {room_name} created successfully.')
                    return room
            else:
                try:
                    room = self._client.join_room(room_name_full)
                except MatrixRequestError as error:
                    if error.code == 404:
                        self.log.info(f'Room {room_name} not found, trying to create it.')
                        room_not_found = True
                    else:
                        self.log.info(f'Error joining room {room_name}: '
                                      f'{error.content} {error.code}')
                else:
                    self.log.info(f'Room {room_name} joined successfully.')
                    return room
            gevent.sleep(self._login_retry_wait)

        raise RuntimeError(f'Could not join or create room {room_name}.')

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

        user = self._client.get_user(user_id)
        address = self._validate_userid_signature(user)
        if not address:
            # Malformed address - skip
            return

        # not a user we've started healthcheck, skip
        if address not in self._address_to_userids:
            return
        self._address_to_userids[address].add(user_id)

        new_state = UserPresence(event['content']['presence'])
        if new_state == self._userid_to_presence.get(user_id):
            return

        self.log.debug(
            'Changing user presence state',
            user_id=user_id,
            prev_state=self._userid_to_presence.get(user_id),
            state=new_state,
        )
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
        self.log.debug('Address to userids', address_to_userids=self._address_to_userids)

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
        if new_state is None:
            return

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
        user_id = event['state_key']
        self.log.debug('discovery member change', state=state, user_id=user_id)
        if state != 'join':
            return
        self._maybe_invite_user(self._client.get_user(user_id))

    def _ensure_room_peers(self):
        """ Check all members of discovery channel for matches to existing rooms """
        for member in self._discovery_room.get_joined_members():
            self._maybe_invite_user(member)

    def _maybe_invite_user(self, user):
        address = self._validate_userid_signature(user)
        if not address:
            return

        room_id = self._address_to_roomid.get(address)
        if not room_id:
            return
        if room_id not in self._client.rooms:
            self._address_to_roomid.pop(address)
            return

        room = self._client.rooms.get(room_id)
        # Refresh members
        room.get_joined_members()
        if user.user_id not in room._members.keys():
            self.log.debug('INVITE', user=user, room=room)
            room.invite_user(user.user_id)

    def _select_server(self, config):
        server = config['server']
        if server.startswith('http'):
            return server
        elif server != 'auto':
            raise ValueError('Invalid matrix server specified (valid values: "auto" or a URL)')

        def _get_rtt(server_name):
            return server_name, get_http_rtt(server_name)

        get_rtt_jobs = [
            gevent.spawn(_get_rtt, server_name)
            for server_name
            in config['available_servers']
        ]
        gevent.joinall(get_rtt_jobs)
        sorted_servers = sorted((job.value for job in get_rtt_jobs), key=itemgetter(1))
        self.log.debug('Matrix homeserver RTT times', rtt_times=sorted_servers)
        best_server, rtt = sorted_servers[0]
        self.log.info(
            'Automatically selecting matrix homeserver based on RTT',
            homeserver=best_server,
            rtt=rtt,
        )
        return best_server

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

    def _get_peer_address_from_room(self, room_alias) -> Optional[Address]:
        """ Given a room name/alias which contains our address on it, return the other address """
        match = self._room_alias_re.match(room_alias)
        if match:
            addresses = {
                to_canonical_address(address)
                for address in (match.group('peer1', 'peer2'))
            }
            addresses = addresses - {self._raiden_service.address}
            if len(addresses) == 1:
                return addresses.pop()

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

    if message_class is messages.Processed:
        return message_class.from_event(event, node_address)
    return message_class.from_event(event)
