# -*- coding: utf-8 -*-
import socket
from contextlib import contextmanager

import stun
from ethereum import slogging as logging

from raiden.exceptions import STUNUnavailableException


log = logging.getLogger(__name__)


@contextmanager
def stun_socket(
    source_ip='0.0.0.0',
    source_port=4200,
    stun_host=None,
    stun_port=3478
):
    with open_bare_socket(source_ip=source_ip, source_port=source_port) as sock:
        timeout = sock.gettimeout()
        sock.settimeout(2)
        log.debug('Initiating STUN')
        nat_type, nat = stun.get_nat_type(
            sock,
            source_ip,
            source_port,
            stun_host=stun_host,
            stun_port=stun_port
        )
        external_ip = nat['ExternalIP']
        if isinstance(external_ip, tuple):
            external_ip = external_ip[0]
        if external_ip is None:
            log.error('STUN failed', nat=nat)
            raise STUNUnavailableException()
        external_port = nat['ExternalPort']
        log.debug(
            'STUN-socket ready:',
            external_ip=external_ip,
            external_port=external_port,
            nat_type=nat_type,
            nat=nat,
            internal_ip=sock.getsockname()[0],
            internal_port=sock.getsockname()[1],
        )
        nat['type'] = nat_type
        sock.settimeout(timeout)
        yield (sock, external_ip, external_port, nat)


@contextmanager
def open_bare_socket(
    source_ip='0.0.0.0',
    source_port=42000
):
    sock = socket.socket(
        socket.AF_INET,  # Internet
        socket.SOCK_DGRAM  # UDP
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:
        sock.bind(
            (source_ip, source_port)
        )
        log.debug(
            'opened socket',
            ip=sock.getsockname()[0],
            port=sock.getsockname()[1],
        )
        yield sock
    finally:
        sock.close()
