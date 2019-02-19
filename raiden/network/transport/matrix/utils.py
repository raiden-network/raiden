import json
import re
from binascii import Error as DecodeError
from operator import attrgetter, itemgetter
from random import Random
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import gevent
import structlog
from cachetools import LRUCache, cached
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_normalized_address
from gevent.lock import Semaphore
from matrix_client.errors import MatrixError, MatrixRequestError

from raiden.exceptions import InvalidSignature, TransportError
from raiden.network.transport.matrix.client import GMatrixClient, Room, User
from raiden.network.utils import get_http_rtt
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import Address, ChainID
from raiden_contracts.constants import ID_TO_NETWORKNAME

log = structlog.get_logger(__name__)

JOIN_RETRIES = 5
USERID_RE = re.compile(r'^@(0x[0-9a-f]{40})(?:\.[0-9a-f]{8})?(?::.+)?$')
ROOM_NAME_SEPARATOR = '_'
ROOM_NAME_PREFIX = 'raiden'


def join_global_room(client: GMatrixClient, name: str, servers: Sequence[str] = ()) -> Room:
    """Join or create a global public room with given name

    First, try to join room on own server (client-configured one)
    If can't, try to join on each one of servers, and if able, alias it in our server
    If still can't, create a public room with name in our server

    Params:
        client: matrix-python-sdk client instance
        name: name or alias of the room (without #-prefix or server name suffix)
        servers: optional: sequence of known/available servers to try to find the room in
    Returns:
        matrix's Room instance linked to client
    """
    our_server_name = urlparse(client.api.base_url).netloc
    assert our_server_name, 'Invalid client\'s homeserver url'
    servers = [our_server_name] + [  # client's own server first
        urlparse(s).netloc
        for s in servers
        if urlparse(s).netloc not in {None, '', our_server_name}
    ]

    our_server_global_room_alias_full = f'#{name}:{servers[0]}'

    # try joining a global room on any of the available servers, starting with ours
    for server in servers:
        global_room_alias_full = f'#{name}:{server}'
        try:
            global_room = client.join_room(global_room_alias_full)
        except MatrixRequestError as ex:
            if ex.code not in (403, 404, 500):
                raise
            log.debug(
                'Could not join global room',
                room_alias_full=global_room_alias_full,
                _exception=ex,
            )
        else:
            if our_server_global_room_alias_full not in global_room.aliases:
                # we managed to join a global room, but it's not aliased in our server
                global_room.add_room_alias(our_server_global_room_alias_full)
                global_room.aliases.append(our_server_global_room_alias_full)
            break
    else:
        log.debug('Could not join any global room, trying to create one')
        for _ in range(JOIN_RETRIES):
            try:
                global_room = client.create_room(name, is_public=True)
            except MatrixRequestError as ex:
                if ex.code not in (400, 409):
                    raise
                try:
                    global_room = client.join_room(
                        our_server_global_room_alias_full,
                    )
                except MatrixRequestError as ex:
                    if ex.code not in (404, 403):
                        raise
                else:
                    break
            else:
                break
        else:
            raise TransportError('Could neither join nor create a global room')

    return global_room


def login_or_register(
        client: GMatrixClient,
        signer: Signer,
        prev_user_id: str = None,
        prev_access_token: str = None,
) -> User:
    """Login to a Raiden matrix server with password and displayname proof-of-keys

    - Username is in the format: 0x<eth_address>(.<suffix>)?, where the suffix is not required,
    but a deterministic (per-account) random 8-hex string to prevent DoS by other users registering
    our address
    - Password is the signature of the server hostname, verified by the server to prevent account
    creation spam
    - Displayname currently is the signature of the whole user_id (including homeserver), to be
    verified by other peers. May include in the future other metadata such as protocol version

    Params:
        client: GMatrixClient instance configured with desired homeserver
        signer: raiden.utils.signer.Signer instance for signing password and displayname
        prev_user_id: (optional) previous persisted client.user_id. Must match signer's account
        prev_access_token: (optional) previous persistend client.access_token for prev_user_id
    Returns:
        Own matrix_client.User
    """
    server_url = client.api.base_url
    server_name = urlparse(server_url).netloc

    base_username = to_normalized_address(signer.address)
    _match_user = re.match(
        f'^@{re.escape(base_username)}.*:{re.escape(server_name)}$',
        prev_user_id or '',
    )
    if _match_user:  # same user as before
        log.debug('Trying previous user login', user_id=prev_user_id)
        client.set_access_token(user_id=prev_user_id, token=prev_access_token)

        try:
            client.api.get_devices()
        except MatrixRequestError as ex:
            log.debug(
                'Couldn\'t use previous login credentials, discarding',
                prev_user_id=prev_user_id,
                _exception=ex,
            )
        else:
            prev_sync_limit = client.set_sync_limit(0)
            client._sync()  # initial_sync
            client.set_sync_limit(prev_sync_limit)
            log.debug('Success. Valid previous credentials', user_id=prev_user_id)
            return client.get_user(client.user_id)
    elif prev_user_id:
        log.debug(
            'Different server or account, discarding',
            prev_user_id=prev_user_id,
            current_address=base_username,
            current_server=server_name,
        )

    # password is signed server address
    password = encode_hex(signer.sign(server_name.encode()))
    rand = None
    # try login and register on first 5 possible accounts
    for i in range(JOIN_RETRIES):
        username = base_username
        if i:
            if not rand:
                rand = Random()  # deterministic, random secret for username suffixes
                # initialize rand for seed (which requires a signature) only if/when needed
                rand.seed(int.from_bytes(signer.sign(b'seed')[-32:], 'big'))
            username = f'{username}.{rand.randint(0, 0xffffffff):08x}'

        try:
            client.login(username, password, sync=False)
            prev_sync_limit = client.set_sync_limit(0)
            client._sync()  # when logging, do initial_sync with limit=0
            client.set_sync_limit(prev_sync_limit)
            log.debug(
                'Login',
                homeserver=server_name,
                server_url=server_url,
                username=username,
            )
            break
        except MatrixRequestError as ex:
            if ex.code != 403:
                raise
            log.debug(
                'Could not login. Trying register',
                homeserver=server_name,
                server_url=server_url,
                username=username,
            )
            try:
                client.register_with_password(username, password)
                log.debug(
                    'Register',
                    homeserver=server_name,
                    server_url=server_url,
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

    name = encode_hex(signer.sign(client.user_id.encode()))
    user = client.get_user(client.user_id)
    user.set_display_name(name)
    return user


@cached(cache=LRUCache(128), key=attrgetter('user_id', 'displayname'), lock=Semaphore())
def validate_userid_signature(user: User) -> Optional[Address]:
    """ Validate a userId format and signature on displayName, and return its address"""
    # display_name should be an address in the USERID_RE format
    match = USERID_RE.match(user.user_id)
    if not match:
        return None

    encoded_address = match.group(1)
    address: Address = to_canonical_address(encoded_address)

    try:
        displayname = user.get_display_name()
        recovered = recover(
            data=user.user_id.encode(),
            signature=decode_hex(displayname),
        )
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


def sort_servers_closest(servers: Sequence[str]) -> Sequence[Tuple[str, float]]:
    """Sorts a list of servers by http round-trip time

    Params:
        servers: sequence of http server urls
    Returns:
        sequence of pairs of url,rtt in seconds, sorted by rtt, excluding failed servers
        (possibly empty)
    """
    if not {urlparse(url).scheme for url in servers}.issubset({'http', 'https'}):
        raise TransportError('Invalid server urls')

    get_rtt_jobs = [
        gevent.spawn(lambda url: (url, get_http_rtt(url)), server_url)
        for server_url
        in servers
    ]
    # these tasks should never raise, returns None on errors
    gevent.joinall(get_rtt_jobs, raise_error=False)  # block and wait tasks
    sorted_servers: List[Tuple[str, float]] = sorted(
        (job.value for job in get_rtt_jobs if job.value[1] is not None),
        key=itemgetter(1),
    )
    log.debug('Matrix homeserver RTT times', rtt_times=sorted_servers)
    return sorted_servers


def make_client(servers: Sequence[str], *args, **kwargs) -> GMatrixClient:
    """Given a list of possible servers, chooses the closest available and create a GMatrixClient

    Params:
        servers: list of servers urls, with scheme (http or https)
        Rest of args and kwargs are forwarded to GMatrixClient constructor
    Returns:
        GMatrixClient instance for one of the available servers
    """
    if len(servers) > 1:
        sorted_servers = [
            server_url
            for (server_url, _) in sort_servers_closest(servers)
        ]
        log.info(
            'Automatically selecting matrix homeserver based on RTT',
            sorted_servers=sorted_servers,
        )
    elif len(servers) == 1:
        sorted_servers = servers
    else:
        raise TransportError('No valid servers list given')

    last_ex = None
    for server_url in sorted_servers:
        server_url: str = server_url
        client = GMatrixClient(server_url, *args, **kwargs)
        try:
            client.api._send('GET', '/versions', api_path='/_matrix/client')
        except MatrixError as ex:
            log.warning('Selected server not usable', server_url=server_url, _exception=ex)
            last_ex = ex
        else:
            break
    else:
        raise TransportError(
            'Unable to find a reachable Matrix server. Please check your network connectivity.',
        ) from last_ex
    return client


def make_room_alias(chain_id: ChainID, *suffixes: str) -> str:
    """Given a chain_id and any number of suffixes (global room names, pair of addresses),
    compose and return the canonical room name for raiden network

    network name from raiden_contracts.constants.ID_TO_NETWORKNAME is used for name, if available,
    else numeric id
    Params:
        chain_id: numeric blockchain id for that room, as raiden rooms are per-chain specific
        *suffixes: one or more suffixes for the name
    Returns:
        Qualified full room name. e.g.:
            make_room_alias(3, 'discovery') == 'raiden_ropsten_discovery'
    """
    network_name = ID_TO_NETWORKNAME.get(chain_id, str(chain_id))
    return ROOM_NAME_SEPARATOR.join([ROOM_NAME_PREFIX, network_name, *suffixes])
