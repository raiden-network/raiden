import binascii
import json
import logging
import re
from collections import namedtuple
from enum import Enum
from operator import itemgetter
from random import Random
from typing import Dict, Set, Tuple, List
from urllib.parse import urlparse

import gevent
from ethereum import slogging
from gevent.event import AsyncResult
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

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
    Message
)
from raiden.network.protocol import timeout_exponential_backoff
from raiden.network.utils import get_http_rtt
from raiden.raiden_service import RaidenService
from raiden.transfer import events as transfer_events
from raiden.transfer.architecture import Event
from raiden.transfer.mediated_transfer import events as mediated_transfer_events
from raiden.transfer.state import NODE_NETWORK_REACHABLE, NODE_NETWORK_UNREACHABLE
from raiden.transfer.state_change import ActionChangeNodeNetworkState, ReceiveDelivered
from raiden.udp_message_handler import on_udp_message
from raiden.utils import (
    address_decoder,
    address_encoder,
    data_decoder,
    data_encoder,
    eth_sign_sha3,
    isaddress,
    pex,
    typing
)
from raiden_libs.network.matrix import GMatrixClient, Room


log = slogging.get_logger(__name__)

SentMessageState = namedtuple('SentMessageState', (
    'async_result',
    'receiver_address',
))


class UserPresence(Enum):
    ONLINE = 'online'
    UNAVAILABLE = 'unavailable'
    OFFLINE = 'offline'


class MatrixTransport:
    _room_prefix = 'raiden'
    _room_sep = '_'

    def __init__(self, config: dict):
        self._raiden_service: RaidenService = None
        self._server_url: str = self._select_server(config)
        self._server_name = urlparse(self._server_url).hostname
        client_class = config.get('client_class', GMatrixClient)
        self._client: GMatrixClient = client_class(self._server_url)

        self.greenlets = list()

        self._discovery_room: Room = None

        self._messageids_to_asyncresult: Dict[typing.Address, AsyncResult] = dict()
        self._addresses_of_interest: Set[typing.Address] = set()
        self._address_to_userids: Dict[typing.Address, Set[str]] = dict()
        self._userid_to_presence: Dict[str, UserPresence] = dict()
        self._address_to_presence: Dict[typing.Address, UserPresence] = dict()
        self._userids_to_address: Dict[str, typing.Address] = dict()
        self._address_to_roomid: Dict[typing.Address, str] = dict()

        self._discovery_room_alias = None
        self._discovery_room_alias_full = None
        self._room_alias_re = None

    def start(
        self,
        raiden_service: RaidenService,
        queueids_to_queues: Dict[Tuple[typing.Address, str], List[Event]]
    ):
        self._raiden_service = raiden_service
        room_alias_re = self._make_room_alias(
            '(?P<peer1>0x[a-zA-Z0-9]{40})',
            '(?P<peer2>0x[a-zA-Z0-9]{40})'
        )
        self._room_alias_re = re.compile(f'^#{room_alias_re}:(?P<server_name>.*)$')

        discovery_cfg = self._raiden_service.config['matrix']['discovery_room']
        self._discovery_room_alias = self._make_room_alias(discovery_cfg['alias_fragment'])
        self._discovery_room_alias_full = (
            f'#{self._discovery_room_alias}:{discovery_cfg["server"]}'
        )

        self._login_or_register()
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

        gevent.spawn_later(2, self._ensure_room_peers)
        gevent.spawn_later(5, self._send_queued_messages, queueids_to_queues)
        log.info('TRANSPORT STARTED')

    def start_health_check(self, node_address):
        log.debug('HEALTHCHECK', peer_address=pex(node_address))
        node_address_hex = address_encoder(node_address)
        users = [
            user
            for user
            in self._client.search_user_directory(node_address_hex)
            if _validate_userid_signature(user)
        ]
        existing = {presence['user_id'] for presence in self._client.get_presence_list()}
        user_ids_to_add = {u.user_id for u in users}
        user_ids = user_ids_to_add - existing
        if user_ids:
            log.debug('Add to presence list', added_users=user_ids)
            self._client.modify_presence_list(add_user_ids=list(user_ids))
        self._address_to_userids.setdefault(node_address, set()).update(user_ids_to_add)
        # Ensure there is a room for the peer node
        # We use spawn_later to avoid races if the peer is already expecting us and sent an invite
        gevent.spawn_later(1, self._get_room_for_address, node_address, allow_missing_peers=True)

    def send_async(
        self,
        queue_name: str,
        receiver_address: typing.Address,
        message: Message
    ) -> AsyncResult:
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        # These are not protocol messages, but transport specific messages
        if isinstance(message, (Delivered, Ping, Pong)):
            raise ValueError(
                'Do not use send_async for {} messages'.format(message.__class__.__name__)
            )

        if isinstance(message, SignedMessage) and not message.sender:
            # FIXME: This can't be right
            message.sender = self._client.user_id

        # Ignore duplicated messages
        message_id = message.message_identifier
        if message_id not in self._messageids_to_asyncresult:
            async_result = self._messageids_to_asyncresult[message_id] = AsyncResult()
            self._send_with_retry(receiver_address, async_result, json.dumps(message.to_dict()))

        return self._messageids_to_asyncresult[message_id]

    def stop_and_wait(self):
        self._client.set_presence_state(UserPresence.OFFLINE.value)
        self._client.stop_listener_thread()
        self._client.logout()

        # Set all the pending results to False, this will also cause pending retries to be aborted
        for async_result in self._messageids_to_asyncresult.values():
            async_result.set(False)

        gevent.wait(self.greenlets)

    @property
    def _network_name(self) -> str:
        return ID_TO_NETWORKNAME.get(
            self._raiden_service.chain.network_id,
            str(self._raiden_service.chain.network_id)
        )

    def _login_or_register(self):
        # password is signed server address
        password = data_encoder(self._sign(self._server_url.encode()))
        seed = int.from_bytes(self._sign(b'seed')[-32:], 'big')
        rand = Random()  # deterministic, random secret for username suffixes
        rand.seed(seed)
        # try login and register on first 5 possible accounts
        for i in range(5):
            base_username = address_encoder(self._raiden_service.address)
            username = base_username
            if i:
                username = f'{username}.{rand.randint(0, 0xffffffff):08x}'

            try:
                self._client.login_with_password(username, password)
                log.info(
                    'LOGIN',
                    homeserver=self._server_url,
                    username=username
                )
                break
            except MatrixRequestError as ex:
                if ex.code != 403:
                    raise
                log.debug(
                    'Could not login. Trying register',
                    homeserver=self._server_url,
                    username=username,
                )
                try:
                    self._client.register_with_password(username, password)
                    log.info(
                        'REGISTER',
                        homeserver=self._server_url,
                        username=username,
                    )
                    break
                except MatrixRequestError as ex:
                    if ex.code != 400:
                        raise
                    log.debug('Username taken. Continuing')
                    continue
        else:
            raise ValueError('Could not register or login!')
        # TODO: persist access_token, to avoid generating a new login every time
        name = data_encoder(self._sign(self._client.user_id.encode()))
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
                    f"created on a federated homeserver."
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
                room.leave()
                continue
            # Don't listen for messages in the discovery room
            should_listen = room.canonical_alias != self._discovery_room_alias_full
            if should_listen:
                peer_address = self._get_peer_address_from_room(room.canonical_alias)
                if not peer_address:
                    log.warning(
                        'Member of a room we\'re not supposed to be a member of - ignoring',
                        room=room
                    )
                    return
                self._address_to_roomid[peer_address] = room.room_id
                room.add_listener(self._handle_message)
            log.debug(
                'ROOM',
                room_id=room_id,
                aliases=room.aliases,
                listening=should_listen
            )

    def _handle_invite(self, room_id: str, state: dict):
        """ Join all invited rooms """
        room = self._client.join_room(room_id)
        if not room.canonical_alias:
            log.warning('Got invited to a room without canonical alias - ignoring', room=room)
            return
        peer_address = self._get_peer_address_from_room(room.canonical_alias)
        if not peer_address:
            log.warning(
                'Got invited to a room we\'re not supposed to be a member of - ignoring',
                room=room
            )
            return
        self._address_to_roomid[peer_address] = room.room_id
        room.add_listener(self._handle_message, 'm.room.message')
        log.debug(
            'Invited to a room',
            room_id=room_id,
            aliases=room.aliases
        )

    def _handle_message(self, room, event):
        """ Handle text messages sent to listening rooms """
        if event['type'] != 'm.room.message' or event['content']['msgtype'] != 'm.text':
            # Ignore non-messages and non-text messages
            return

        sender_id = event['sender']

        if sender_id == self._client.user_id:
            # Ignore our own messages
            return

        user = self._client.get_user(sender_id)

        peer_address = self._userids_to_address.get(sender_id)
        if not peer_address:
            try:
                # recover displayname signature
                peer_address = signing.recover_address(
                    sender_id.encode(),
                    signature=data_decoder(user.get_display_name()),
                    hasher=eth_sign_sha3
                )
            except AssertionError:
                log.warning('INVALID MESSAGE', sender_id=sender_id)
                return
            node_address_hex = address_encoder(peer_address)
            if node_address_hex.lower() not in sender_id:
                log.warning(
                    'INVALID SIGNATURE',
                    peer_address=node_address_hex,
                    sender_id=sender_id
                )
                return
            self._userids_to_address[sender_id] = peer_address

        data = event['content']['body']
        if data.startswith('0x'):
            message = message_from_bytes(data_decoder(data))
        else:
            message_dict = json.loads(data)
            log.trace('MESSAGE_DATA', data=message_dict)
            message = message_from_dict(message_dict)

        if isinstance(message, SignedMessage) and not message.sender:
            # FIXME: This can't be right
            message.sender = peer_address

        if isinstance(message, Delivered):
            self._receive_delivered(message)
        elif isinstance(message, Ping):
            log.warning(
                'Not required Ping received',
                message=data,
            )
        elif isinstance(message, SignedMessage):
            self._receive_message(message)
        elif log.isEnabledFor(logging.ERROR):
            log.error(
                'Invalid message',
                message=data,
            )

    def _receive_delivered(self, delivered: Delivered):
        # FIXME: The signature doesn't seem to be verified - check in UDPTransport as well
        self._raiden_service.handle_state_change(
            ReceiveDelivered(delivered.delivered_message_identifier)
        )

        async_result = self._messageids_to_asyncresult.pop(
            delivered.delivered_message_identifier,
            None
        )

        if async_result is not None:
            async_result.set(True)
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'DELIVERED MESSAGE RECEIVED',
                    node=pex(self._raiden_service.address),
                    receiver=pex(delivered.sender),
                    message_identifier=delivered.delivered_message_identifier,
                )

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'DELIVERED MESSAGE UNKNOWN',
                    node=pex(self._raiden_service.address),
                    message_identifier=delivered.delivered_message_identifier,
                )

    def _receive_message(self, message):
        is_debug_log_enabled = log.isEnabledFor(logging.DEBUG)

        if is_debug_log_enabled:
            log.info(
                'MESSAGE RECEIVED',
                node=pex(self._raiden_service.address),
                message=message,
                message_sender=pex(message.sender)
            )

        try:
            if on_udp_message(self._raiden_service, message):
                # TODO: Maybe replace with Matrix read receipts.
                #       Unfortunately those work on an 'up to' basis, not on individual messages
                #       which means that message order is important which isn't guaranteed between
                #       federated servers.
                #       See: https://matrix.org/docs/spec/client_server/r0.3.0.html#id57
                delivered_message = Delivered(message.message_identifier)
                self._raiden_service.sign(delivered_message)
                self._send_immediate(message.sender, json.dumps(delivered_message.to_dict()))

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            if is_debug_log_enabled:
                log.warn('Exception while processing message', exc_info=True)
        if is_debug_log_enabled:
            log.debug(
                'DELIVERED',
                node=pex(self._raiden_service.address),
                to=pex(message.sender),
                message_identifier=message.message_identifier
            )

    def _send_queued_messages(
        self,
        queueids_to_queues: Dict[Tuple[typing.Address, str], List[Event]]
    ):
        def send_queue(address, events):
            node_address = self._raiden_service.address
            for event in events:
                self.send_async('', address, _event_to_message(event, node_address))

        for (address, queue_name), events in queueids_to_queues.items():
            # TODO: Check if we need to separate this by queue_name
            gevent.spawn(send_queue, address, events)

    def _send_with_retry(
        self,
        receiver_address: typing.Address,
        async_result: AsyncResult,
        data: str
    ):
        def retry():
            timeout_generator = timeout_exponential_backoff(
                self._raiden_service.config['protocol']['retries_before_backoff'],
                self._raiden_service.config['protocol']['retry_interval'],
                self._raiden_service.config['protocol']['retry_interval'] * 10
            )
            while async_result.value is None:
                self._send_immediate(receiver_address, data)
                gevent.sleep(next(timeout_generator))

        self.greenlets.append(gevent.spawn(retry))

    def _send_immediate(self, receiver_address, data):
        # FIXME: Send message to all matching rooms
        room = self._get_room_for_address(receiver_address)
        log.debug('SEND: %r => %r', room, data)
        room.send_text(data)

    def _get_room_for_address(
        self,
        receiver_address: typing.Address,
        allow_missing_peers=False
    ) -> Room:
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
            address_encoder(address).lower()
            for address in [receiver_address, self._raiden_service.address]
        ])
        room_name = self._make_room_alias(*address_pair)

        room_candidates = self._client.search_room_directory(room_name)
        if room_candidates:
            room = room_candidates[0]
        else:
            # no room with expected name => create one and invite peer
            address = address_encoder(receiver_address)
            candidates = self._client.search_user_directory(address)
            if not candidates and not allow_missing_peers:
                raise ValueError('No candidates found for given address: {}'.format(address))

            # filter candidates
            peers = [user for user in candidates if _validate_userid_signature(user)]
            if not peers and not allow_missing_peers:
                raise ValueError('No valid peer found for given address: {}'.format(address))

            try:
                # Try join first to avoid races
                room_name_full = f'#{room_name}:{self._server_name}'
                log.trace('Trying to join', room_name=room_name_full)
                room = self._client.join_room(room_name_full)
                for user in peers:
                    room.invite_user(user.user_id)
            except MatrixRequestError:
                room = self._client.create_room(
                    room_name,
                    invitees=[user.user_id for user in peers],
                    is_public=True  # FIXME: This is for debugging purposes only
                )
            offline_peers = [
                user for user in peers
                if self._userid_to_presence.get(user.user_id) is UserPresence.OFFLINE
            ]
            if offline_peers:
                log.warning('Inviting offline peers', offline_peers=offline_peers, room=room)

        room.add_listener(self._handle_message, 'm.room.message')
        log.info('CHANNEL ROOM', peer_address=address_encoder(receiver_address), room=room)
        self._address_to_roomid[receiver_address] = room.room_id
        return room

    def _make_room_alias(self, *parts):
        return self._room_sep.join([self._room_prefix, self._network_name, *parts])

    def _handle_presence_change(self, event):
        """
        Update node network reachability from presence events.

        Due to the possibility of nodes using accounts on multiple homeservers a composite
        address state is synthesised from the cached individual user presence state.
        """
        if event['type'] != 'm.presence':
            return
        user_id = event['sender']
        new_state = UserPresence(event['content']['presence'])
        if new_state == self._userid_to_presence.get(user_id):
            return

        log.trace(
            'Changing user presence state',
            user_id=user_id,
            prev_state=self._userid_to_presence.get(user_id),
            state=new_state
        )
        self._userid_to_presence[user_id] = new_state

        # User should be re-validated after presence change
        self._userids_to_address.pop(user_id, None)

        try:
            # FIXME: This should probably use ecrecover instead
            address = self._address_from_user_id(user_id)
        except (binascii.Error, AssertionError):
            # Malformed address - skip
            log.debug('Malformed address, probably not a raiden node', user_id=user_id)
            return

        composite_presence = {
            self._userid_to_presence.get(uid)
            for uid
            in self._address_to_userids.get(address, set())
        }

        # Iterate over UserPresence in definition order and pick first matching state
        new_state = UserPresence.OFFLINE
        for presence in UserPresence.__members__.values():
            if presence in composite_presence:
                new_state = presence
                break

        if new_state == self._address_to_presence.get(address):
            return

        log.debug(
            'Changing address presence state',
            address=address_encoder(address),
            user_id=user_id,
            prev_state=self._address_to_presence.get(address),
            state=new_state
        )
        self._address_to_presence[address] = new_state

        state_change = ActionChangeNodeNetworkState(
            address,
            NODE_NETWORK_UNREACHABLE
            if new_state is UserPresence.OFFLINE
            else NODE_NETWORK_REACHABLE
        )
        self._raiden_service.handle_state_change(state_change)

    def _handle_discovery_membership_event(self, room, event):
        if event['type'] != 'm.room.member':
            return

        state = event['content']['membership']
        user_id = event['state_key']
        log.trace('discovery member change', state=state, user_id=user_id)
        if state != 'join':
            return
        self._maybe_invite_user(self._client.get_user(user_id))

    def _ensure_room_peers(self):
        """ Check all members of discovery channel for matches to existing rooms """
        for member in self._discovery_room.get_joined_members():
            self._maybe_invite_user(member)

    def _maybe_invite_user(self, user):
        try:
            address = self._address_from_user_id(user.user_id)
        except (binascii.Error, AssertionError):
            return

        room_id = self._address_to_roomid.get(address)
        if not room_id:
            return

        # This is an address we care about - add new user to health check
        if user.user_id not in self._address_to_userids.get(address, set()):
            self.start_health_check(address)

        # Health check will ensure room exists
        room = self._client.rooms.get(room_id)
        # Refresh members
        room.get_joined_members()
        if user.user_id not in room._members.keys():
            log.trace('INVITE', user=user, room=room)
            room.invite_user(user.user_id)

    @staticmethod
    def _address_from_user_id(user_id):
        return address_decoder(user_id.partition(':')[0].replace('@', '').partition('.')[0])

    @staticmethod
    def _select_server(config):
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
        log.debug('Matrix homeserver RTT times', rtt_times=sorted_servers)
        best_server, rtt = sorted_servers[0]
        log.info(
            'Automatically selecting matrix homeserver based on RTT',
            homeserver=best_server,
            rtt=rtt
        )
        return best_server

    def _sign(self, data: bytes) -> bytes:
        """Use eth_sign compatible hasher to sign matrix data"""
        return signing.sign(
            data,
            self._raiden_service.private_key,
            hasher=eth_sign_sha3
        )

    def _get_peer_address_from_room(self, room_alias):
        match = self._room_alias_re.match(room_alias)
        if match:
            addresses = {address_decoder(address) for address in (match.group('peer1', 'peer2'))}
            addresses = addresses - {self._raiden_service.address}
            if len(addresses) == 1:
                return addresses.pop()


def _validate_userid_signature(user: User) -> bool:
    # display_name should be an address present in the user_id
    recovered = signing.recover_address(
        user.user_id.encode(),
        signature=data_decoder(user.get_display_name()),
        hasher=eth_sign_sha3
    )
    return address_encoder(recovered).lower() in user.user_id


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
