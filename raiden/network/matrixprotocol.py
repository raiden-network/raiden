import logging
import json
from ethereum import slogging
from random import Random
from collections import namedtuple
from gevent.event import AsyncResult

from raiden.encoding import signing
from raiden.utils import (
    sha3,
    pex,
    eth_sign_sha3,
    address_encoder,
    data_encoder,
    data_decoder,
    isaddress,
    typing
)
from raiden.messages import (
    from_dict as message_from_dict,
    decode as message_from_bytes,
    Ack,
    Ping,
    Processed,
    SignedMessage,
)
from raiden.exceptions import (
    InvalidAddress,
    UnknownAddress,
    UnknownTokenAddress,
)
from raiden.udp_message_handler import on_udp_message
from raiden.constants import ID_TO_NETWORKNAME

from matrix_client.errors import MatrixRequestError
from matrix_client.room import Room
from gmatrixclient import GMatrixClient


log = slogging.get_logger(__name__)

SentMessageState = namedtuple('SentMessageState', (
    'async_result',
    'receiver_address',
))


class RaidenMatrixProtocol:
    _room_prefix = 'raiden'
    _room_sep = '_'

    def __init__(self, raiden: 'RaidenService'):
        self.raiden = raiden

        self.senthashes_to_states = dict()

    @property
    def network_name(self):
        return ID_TO_NETWORKNAME.get(
            self.raiden.network_id,
            str(self.raiden.network_id)
        )

    def start(self):
        self.client = GMatrixClient(self.server)
        # password is signed server address
        password = data_encoder(signing.sign(self.server, self.raiden.private_key))
        seed = int.from_bytes(signing.sign('seed', self.raiden.private_key)[-32:], 'big')
        rand = Random()  # deterministic, random secret for username suffixes
        rand.seed(seed)
        # try login and register on first 5 possible accounts
        for i in range(5):
            username = self.raiden.address.lower()
            if i:
                username += '.' + hex(rand.randint(0, 0xffffffff))[2:]

            try:
                token = self.client.login_with_password(username, password)
                log.info(
                    'LOGIN: %r => %r',
                    (username, password),
                    token,
                )
                break
            except MatrixRequestError as e:
                if e.code != 403:
                    raise
                log.debug(
                    'Could not login. Trying register: %r',
                    (username, password),
                    exc_info=True
                )
                try:
                    token = self.client.register_with_password(username, password)
                    log.info(
                        'REGISTER: %r => %r',
                        (username, password),
                        token,
                    )
                    break
                except MatrixRequestError as e:
                    if e.code != 400:
                        raise
                    log.debug('Username taken. Continuing', exc_info=True)
                    continue
        else:
            raise ValueError('Could not register or login!')

        # TODO: persist access_token, to avoid generating a new login every time
        user = {
            'user_id': self.client.user_id,
            'access_token': self.client.token,
            'home_server': self.client.hs,
        }

        name = data_encoder(signing.sign(user['user_id'].encode(), self.raiden.private_key))
        self.client.get_user(user['user_id']).set_display_name(name)

        # TODO: get initial rooms from config
        for alias in self.config['matrix:rooms']:
            self.client.join_room(alias)

        for room_id, room in self.client.get_rooms().items():
            self._ensure_room_alias(room)
            room.add_listener(self._handle_message)
            log.debug(
                'ROOM: %r => %r',
                room_id,
                room.aliases
            )
            # TODO: add room monitoring to invite coming users peers that matches
            # any room we participate in

        self.client.add_invite_listener(self._handle_invite)
        self.client.start_listener_thread()  # greenlet "thread"

    def _handle_invite(self, room_id, state):
        """Join all invited rooms"""
        room = self.client.join_room(room_id)
        self._ensure_room_alias(room)
        room.add_listener(self._handle_message)
        log.debug(
            'Invited to room: %r => %r',
            room_id,
            room.aliases
        )

    def _handle_message(self, room, event):
        """Handle text messages sent to listening rooms"""
        if event['type'] != 'm.room.message' or event['content']['msgtype'] != 'm.text':
            return

        sender_id = event['sender']
        user = self.client.get_user(sender_id)

        # recover displayname signature
        addr_display = signing.recover(
            sender_id.encode(),
            signature=data_decoder(user.get_display_name()),
            hasher=eth_sign_sha3
        )
        if address_encoder(addr_display).lower() not in sender_id:
            log.debug(
                'INVALID SIGNATURE %r %r',
                address_encoder(addr_display),
                sender_id
            )
            return

        data = event['content']['body']
        if data.startswith('0x'):
            message = message_from_bytes(data_decoder(data))
        else:  # json
            message = message_from_dict(json.loads(data))

        echohash = sha3(data.encode() + self.raiden.address)
        if echohash in self.receivedhashes_to_acks:
            self._maybe_send_ack(*self.receivedhashes_to_acks[echohash])
            return

        if isinstance(message, Ack):
            self._receive_processed(message)
        elif isinstance(message, Ping):
            log.warning(
                'Not required Ping received',
                message=data,
            )
        elif isinstance(message, SignedMessage):
            self._receive_message(message, echohash)
        elif log.isEnabledFor(logging.ERROR):
            log.error(
                'Invalid message',
                message=data,
            )

    def _receive_processed(self, processed):
        waitprocessed = self.senthashes_to_states.pop(processed.echo, None)

        if waitprocessed is None:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    '`Processed` MESSAGE UNKNOWN ECHO',
                    node=pex(self.raiden.address),
                    echohash=pex(processed.echo),
                )

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    '`Processed` MESSAGE RECEIVED',
                    node=pex(self.raiden.address),
                    receiver=pex(waitprocessed.receiver_address),
                    echohash=pex(processed.echo),
                )

            waitprocessed.async_result.set(True)

    def _receive_message(self, message, echohash):
        is_debug_log_enabled = log.isEnabledFor(logging.DEBUG)

        if is_debug_log_enabled:
            log.info(
                'MESSAGE RECEIVED',
                node=pex(self.raiden.address),
                echohash=pex(echohash),
                message=message,
                message_sender=pex(message.sender)
            )

        try:
            on_udp_message(self.raiden, message)

            # only send the Processed message if the message was handled without exceptions
            processed_message = Processed(
                self.raiden.address,
                echohash,
            )

            self.maybe_send_processed(
                message.sender,
                processed_message,
            )
        except (InvalidAddress, UnknownAddress, UnknownTokenAddress) as e:
            if is_debug_log_enabled:
                log.warn(str(e))
        else:
            if is_debug_log_enabled:
                log.debug(
                    'PROCESSED',
                    node=pex(self.raiden.address),
                    to=pex(message.sender),
                    echohash=pex(echohash),
                )

    def send_async(self, receiver_address: typing.Address, message: 'Message') -> AsyncResult:
        if not isaddress(receiver_address):
            raise ValueError('Invalid address {}'.format(pex(receiver_address)))

        if isinstance(message, (Processed, Ping)):
            raise ValueError('Do not use send for `Processed` or `Ping` messages')

        # Messages that are not unique per receiver can result in hash
        # collision, e.g. Secret messages. The hash collision has the undesired
        # effect of aborting message resubmission once /one/ of the nodes
        # replied with an Ack, adding the receiver address into the echohash to
        # avoid these collisions.
        data = json.dumps(message.to_dict())
        if isinstance(data, bytes):
            echohash = sha3(data + receiver_address)
            data = data_encoder(data)
        else:
            data = json.dumps(data)
            echohash = sha3(data.encode() + receiver_address)

        # Ignore duplicated messages
        if echohash not in self.senthashes_to_states:
            async_result = AsyncResult()
            self.senthashes_to_states[echohash] = SentMessageState(
                async_result,
                receiver_address,
            )
            room = self._get_room_for_address(receiver_address)

            log.debug('_SEND: %r => %r', room, data)
            room.send_text(data)

        else:
            async_result = self.senthashes_to_states[echohash].async_result

        return async_result

    def _get_room_for_address(self, receiver_address: typing.Address) -> Room:
        room_name = self._room_sep.join(
            (self._room_prefix, self.network_name) +
            (address_encoder(addr).lower()
             for addr in sorted((receiver_address, self.raiden.address)))
        )  # e.g.: raiden_ropsten_0xaaaa_0xbbbb
        for room_id, _room in self.client.get_rooms().items():
            # search for a room with given name
            self._ensure_room_alias(_room)
            if not _room.canonical_alias:
                continue
            if _room.canonical_alias != room_name:
                continue
            else:
                room = _room
                break
        else:  # no room with expected name => create one and invite peer
            address = address_encoder(receiver_address).lower()
            candidates = self.client.search_user_directory(address)

            if not candidates:
                raise ValueError('No candidates found for given address: {}'.format(address))

            def valid_sig(user: 'User') -> bool:
                # display_name should be an address present in the user_id
                return address_encoder(signing.recover(
                    user.user_id.encode(),
                    signature=data_decoder(user.get_display_name()),
                    hasher=eth_sign_sha3
                )).lower() in user.user_id

            # filter candidates
            peers = [user for user in candidates if valid_sig(user)]
            if not peers:
                raise ValueError('No valid peer found for given address: {}'.format(address))

            room = self.client.create_room(
                room_name,
                invitees=[user.user_id for user in peers]
            )

        return room

    @staticmethod
    def _ensure_room_alias(room):
        if not room.canonical_alias:
            room.update_aliases()
            if room.aliases:
                room.canonical_alias = room.aliases[0]
