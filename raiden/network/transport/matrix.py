import json
import re
from collections import defaultdict
from enum import Enum
from json import JSONDecodeError
from binascii import Error as DecodeError
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
from matrix_client.errors import MatrixError, MatrixRequestError
from matrix_client.user import User
from cachetools import cachedmethod, TTLCache
from operator import attrgetter, itemgetter
from weakref import WeakKeyDictionary, WeakValueDictionary

from raiden import messages
from raiden.constants import ID_TO_NETWORKNAME
from raiden.encoding import signing
from raiden.exceptions import (
    InvalidAddress,
    InvalidProtocolMessage,
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
from raiden.transfer import events as transfer_events, views
from raiden.transfer.mediated_transfer import events as mediated_transfer_events
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NODE_NETWORK_UNKNOWN,
    QueueIdsToQueues,
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
    QueueIdentifier,
    Type,
    Iterable,
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
        self._config = config

        def _http_retry_delay() -> Iterable[float]:
            # below constants are defined in raiden.app.App.DEFAULT_CONFIG
            return udp_utils.timeout_exponential_backoff(
                self._config['retries_before_backoff'],
                self._config['retry_interval'] / 5,
                self._config['retry_interval'],
            )

        while True:
            self._server_url: str = self._select_server(config)
            self._server_name = config.get('server_name', urlparse(self._server_url).hostname)
            client_class = config.get('client_class', GMatrixClient)
            self._client: GMatrixClient = client_class(
                self._server_url,
                http_pool_maxsize=4,
                http_retry_timeout=40,
                http_retry_delay=_http_retry_delay,
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

        # partner need to be in this dict to be listened on
        self._address_to_userids: Dict[Address, Set[str]] = defaultdict(set)
        self._address_to_presence: Dict[Address, UserPresence] = dict()
        self._userid_to_presence: Dict[str, UserPresence] = dict()

        self._discovery_room_alias = None

        self._running = False
        self._health_semaphore = gevent.lock.Semaphore()

        self._client.add_invite_listener(self._handle_invite)
        self._client.add_presence_listener(self._handle_presence_change)

    def start(
        self,
        raiden_service: RaidenService,
        initial_queues: QueueIdsToQueues,
    ):
        self._running = True
        self._raiden_service = raiden_service

        self._login_or_register()
        self._join_discovery_room()
        self._inventory_rooms()

        # TODO: Add (better) error handling strategy
        self._client.start_listener_thread()

        # TODO: Add greenlet that regularly refreshes our presence state
        self._client.set_presence_state(UserPresence.ONLINE.value)
        self._send_queued_messages()  # uses property instead of initial_queues

        self.log.info('TRANSPORT STARTED', config=self._config)

    def start_health_check(self, node_address):
        if not self._running:
            return

        with self._health_semaphore:
            if node_address in self._address_to_userids:
                return  # already healthchecked

            node_address_hex = to_normalized_address(node_address)
            self.log.debug('HEALTHCHECK', peer_address=node_address_hex)

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
        queue_identifier: QueueIdentifier,
        message: Message,
    ):
        if not self._running:
            return

        message_id = message.message_identifier
        receiver_address = queue_identifier.recipient

        assert queue_identifier in self._queueids_to_queues
        message_in_queue = any(
            message_id == event.message_identifier
            for event in self._queueids_to_queues[queue_identifier]
        )
        if not message_in_queue:
            self.log.warning(
                'Message not in queue',
                message=message,
                queue=queue_identifier,
            )

        if not is_binary_address(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError(
                'Do not use send_async for {} messages'.format(message.__class__.__name__),
            )

        self.log.info(
            'SEND ASYNC',
            receiver_address=pex(receiver_address),
            message=message,
            queue_identifier=queue_identifier,
        )

        if isinstance(message, Processed):
            self._send_immediate(queue_identifier, message)
        else:
            self._send_with_retry(queue_identifier, message)

    def stop_and_wait(self):
        if not self._running:
            return
        self._running = False

        # this should simply raise GrenletExit on the retry's gevent.sleep
        gevent.killall(self.greenlets)
        self.greenlets.clear()

        self._client.set_presence_state(UserPresence.OFFLINE.value)
        self._client.stop_listener_thread()
        self._client.logout()

    @property
    def _queueids_to_queues(self) -> QueueIdsToQueues:
        chain_state = views.state_from_raiden(self._raiden_service)
        return views.get_all_messagequeues(chain_state)

    @property
    def _user_id(self) -> Optional[str]:
        return getattr(self, '_client', None) and getattr(self._client, 'user_id', None)

    @property
    @cachedmethod(_cachegetter('__log_cache', dict), key=attrgetter('_user_id'))
    def log(self):
        if not self._user_id:
            return log
        return log.bind(current_user=self._user_id)

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
        name = encode_hex(self._sign(self._user_id.encode()))
        self._get_user(self._user_id).set_display_name(name)

    def _join_discovery_room(self):
        discovery_cfg = self._config['discovery_room']
        self._discovery_room_alias = self._make_room_alias(discovery_cfg['alias_fragment'])
        discovery_room_alias_full = (
            f'#{self._discovery_room_alias}:{discovery_cfg["server"]}'
        )

        last_ex = None
        for _ in range(5):
            # try join room
            try:
                discovery_room = self._client.join_room(discovery_room_alias_full)
                break
            except MatrixRequestError as ex:
                if ex.code not in (404, 403):
                    raise
                last_ex = ex

            # if can't, room doesn't exist, try creating
            if discovery_cfg['server'] != self._server_name:
                raise RuntimeError(
                    f"Discovery room {discovery_room_alias_full} not found and can't be "
                    f"created on a federated homeserver {self._server_name!r}.",
                ) from last_ex
            try:
                discovery_room = self._client.create_room(
                    self._discovery_room_alias,
                    is_public=True,
                )
                break
            except MatrixRequestError as ex:
                if ex.code not in (400, 409):
                    raise
                last_ex = ex
        else:
            raise last_ex

        self._discovery_room = discovery_room
        # Populate initial members
        for user in self._discovery_room.get_joined_members():
            self._get_user(user)  # cache known users
            self._maybe_invite_user(user)

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

    @cachedmethod(
        _cachegetter('__messages_cache', lambda: TTLCache(32, 4)),
        key=lambda _, room, event: (room.room_id, event['type'], event['content'].get('body')),
    )
    def _handle_message(self, room, event) -> bool:
        """ Handle text messages sent to listening rooms """
        if (
                event['type'] != 'm.room.message' or
                event['content']['msgtype'] != 'm.text' or
                not self._running
        ):
            # Ignore non-messages and non-text messages
            return False

        sender_id = event['sender']

        if sender_id == self._user_id:
            # Ignore our own messages
            return False

        user = self._get_user(sender_id)
        peer_address = self._validate_userid_signature(user)
        if not peer_address:
            self.log.warning(
                'At received message -- invalid user displayName signature',
                peer_user=user.user_id,
                room=room,
            )
            return False
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
            return False

        data = event['content']['body']
        if not isinstance(data, str):
            self.log.warning(
                'Received message body not a string',
                peer_user=user.user_id,
                peer_address=to_checksum_address(peer_address),
                room=room,
            )
            return False

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
                return False
            except InvalidProtocolMessage as ex:
                self.log.warning(
                    "Received message binary data is not a valid message",
                    message_data=data,
                    peer_address=pex(peer_address),
                    exception=ex,
                )
                return False

        else:
            try:
                message_dict = json.loads(data)
                message = message_from_dict(message_dict)
            except (UnicodeDecodeError, JSONDecodeError) as ex:
                self.log.warning(
                    "Can't parse message data JSON",
                    message_data=data,
                    peer_address=pex(peer_address),
                    exception=ex,
                )
                return False
            except InvalidProtocolMessage as ex:
                self.log.warning(
                    "Message data JSON are not a valid message",
                    message_data=data,
                    peer_address=pex(peer_address),
                    exception=ex,
                )
                return False

        self.log.debug(
            'MESSAGE_DATA',
            data=data,
            sender=pex(peer_address),
            sender_user=user,
            room=room,
        )

        if isinstance(message, Ping):
            self.log.warning(
                'Not required Ping received',
                message=data,
            )
            return False
        elif isinstance(message, SignedMessage):
            if message.sender != peer_address:
                self.log.warning(
                    'Message not signed by sender!',
                    message=message,
                    signer=message.sender,
                    peer_address=peer_address,
                )
                return False
            if isinstance(message, Delivered):
                self._receive_delivered(message)
            else:
                self._receive_message(message)
        else:
            self.log.warning(
                'Received Invalid message',
                message=data,
            )
            return False

        return True

    def _receive_delivered(self, delivered: Delivered):
        # FIXME: check if UDPTransport also checks Delivered sender and message presence
        # checks there's a respective message on sender's queue
        for queue_identifier, events in self._queueids_to_queues.items():
            if delivered.sender != queue_identifier.recipient:
                continue
            if any(delivered.sender == event.recipient for event in events):
                break
        else:
            self.log.debug(
                'DELIVERED MESSAGE UNKNOWN',
                sender=pex(delivered.sender),
                message=delivered,
            )
            return

        self._raiden_service.handle_state_change(
            ReceiveDelivered(delivered.delivered_message_identifier),
        )

        self.log.debug(
            'DELIVERED MESSAGE RECEIVED',
            sender=pex(delivered.sender),
            message=delivered,
        )

    def _receive_message(self, message: SignedMessage):
        self.log.info(
            'MESSAGE RECEIVED',
            node=pex(self._raiden_service.address),
            message=message,
            sender=pex(message.sender),
        )

        def send_delivered_for(message: SignedMessage):
            delivered_message = Delivered(message.message_identifier)
            self._raiden_service.sign(delivered_message)
            self._send_raw(message.sender, json.dumps(delivered_message.to_dict()))

        try:
            # TODO: Maybe replace with Matrix read receipts.
            #       Unfortunately those work on an 'up to' basis, not on individual messages
            #       which means that message order is important which isn't guaranteed between
            #       federated servers.
            #       See: https://matrix.org/docs/spec/client_server/r0.3.0.html#id57
            if not isinstance(message, Processed):
                self.greenlets.append(gevent.spawn(send_delivered_for, message))

            on_message(self._raiden_service, message)

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            self.log.warning('Exception while processing message', exc_info=True)
            return

    def _send_queued_messages(self):
        for queue_identifier, events in self._queueids_to_queues.items():
            node_address = self._raiden_service.address
            for event in events:
                message = _event_to_message(event, node_address)
                self._raiden_service.sign(message)
                self.start_health_check(queue_identifier.recipient)
                self.send_async(queue_identifier, message)

    def _send_with_retry(
        self,
        queue_identifier: QueueIdentifier,
        message: Message,
    ):
        data = json.dumps(message.to_dict())
        message_id = message.message_identifier
        receiver_address = queue_identifier.recipient
        reachable = {UserPresence.ONLINE, UserPresence.UNAVAILABLE}

        def retry():
            timeout_generator = udp_utils.timeout_exponential_backoff(
                self._config['retries_before_backoff'],
                self._config['retry_interval'],
                self._config['retry_interval'] * 10,
            )
            for delay in timeout_generator:
                status = self._address_to_presence.get(receiver_address)
                if status in reachable:
                    self._send_raw(receiver_address, data)
                else:
                    self.log.debug(
                        'Skipping SEND to unreachable node',
                        receiver=pex(receiver_address),
                        status=status,
                        message=message,
                        queue=queue_identifier,
                    )
                gevent.sleep(delay)  # kill should exit here
                if not self._running:
                    return
                # retry while our queue is valid
                if queue_identifier not in self._queueids_to_queues:
                    self.log.debug(
                        'Queue cleaned, stop retrying',
                        message=message,
                        queue=queue_identifier,
                        queueids_to_queues=self._queueids_to_queues,
                    )
                    break
                # retry while the message is in queue
                # Delivered and Processed messages should eventually remove them
                message_in_queue = any(
                    message_id == event.message_identifier
                    for event in self._queueids_to_queues[queue_identifier]
                )
                if not message_in_queue:
                    break

        self.greenlets.append(gevent.spawn(retry))

    def _send_immediate(
        self,
        queue_identifier: QueueIdentifier,
        message: Message,
    ):
        data = json.dumps(message.to_dict())
        receiver_address = queue_identifier.recipient

        self._send_raw(receiver_address, data)

    def _send_raw(self, receiver_address, data):
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
            f'address not health checked: me: {self._user_id}, peer: {address_hex}'
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

    def _get_unlisted_room(self, room_name, invitees: List[User]):
        """Obtain a room that cannot be found by search_room_directory."""
        room_name_full = f'#{room_name}:{self._server_name}'
        invitees_uids = [user.user_id for user in invitees]

        for _ in range(5):
            # try joining room
            try:
                room = self._client.join_room(room_name_full)
            except MatrixRequestError as error:
                if error.code == 404:
                    self.log.info(
                        f'Room {room_name_full} not found, trying to create it.',
                        error=error,
                    )
                else:
                    self.log.info(f'Error joining room {room_name}: '
                                  f'{error.content} {error.code}')
            else:
                self.log.info('Room joined successfully', room=room)
                break

            # if can't, try creating it
            try:
                room = self._client.create_room(
                    room_name,
                    invitees=invitees_uids,
                    is_public=True,  # FIXME: debug only
                )
            except MatrixRequestError as error:
                if error.code == 409:
                    message = 'seems to have been created by peer meanwhile.'
                else:
                    message = f'{error.code} {error.content}'
                self.log.info(f'Error creating room {room_name}: {message}. '
                              f'Retrying to join...')
            else:
                self.log.info('Room created successfully', room=room, invitees=invitees)
                break
        else:
            # if can't join nor create, create an unnamed one
            room = self._client.create_room(
                None,
                invitees=invitees_uids,
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
        if event['type'] != 'm.presence' or user_id == self._user_id:
            return

        user = self._get_user(user_id)
        user.displayname = event['content'].get('displayname') or user.displayname
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
            try:
                presence = UserPresence(
                    self._client.get_user_presence(user_id),
                )
            except MatrixRequestError:
                presence = UserPresence.UNKNOWN
            self._userid_to_presence[user_id] = presence
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
            return None
        encoded_address: str = match.group(1)
        address: Address = to_canonical_address(encoded_address)
        try:
            displayname = user.get_display_name()
            recovered = MatrixTransport._recover(
                user.user_id.encode(),
                decode_hex(displayname),
            )
            if not (address and recovered and recovered == address):
                return None
        except (DecodeError, TypeError, MatrixRequestError, json.decoder.JSONDecodeError):
            return None
        return address

    @cachedmethod(
        _cachegetter('__users_cache', WeakValueDictionary),
        key=lambda _, user: user.user_id if isinstance(user, User) else user,
    )
    def _get_user(self, user: Union[User, str]) -> User:
        """ Creates an User from an user_id, if none, or fetch a cached User """
        if not isinstance(user, User):
            user = self._client.get_user(user)
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
