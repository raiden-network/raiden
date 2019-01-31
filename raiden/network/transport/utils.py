from collections import OrderedDict
from matrix_client.errors import MatrixRequestError
from raiden_libs.network.matrix import GMatrixClient, Room
from raiden.exceptions import TransportError
from typing import Sequence
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

JOIN_RETRIES = 5


def matrix_join_global_room(client: GMatrixClient, name: str, servers: Sequence[str] = ()) -> Room:
    """Join or create a global public room with given name

    First, try to join room on own server (client-configured one)
    If can't, try to join on each one of servers, and if able, alias it in our server
    If still can't, create a public room with name in our server

    Params:
        client: matrix-python-sdk client instance
        name: name or alias of the room (without #-prefix or server's name suffix)
        servers: optional: sequence of known/available servers to try to find the room in
    Returns:
        matrix's Room instance linked to client
    """
    assert urlparse(client.api.base_url).netloc, 'Invalid client\'s homeserver url'
    servers = [
        urlparse(s).netloc
        for s in ([client.api.base_url] + list(servers))  # client's own server first
        if urlparse(s).netloc
    ]
    servers = list(OrderedDict.fromkeys(servers))  # dedupe, keep order

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
