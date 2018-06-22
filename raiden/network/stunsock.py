import stun
import structlog as structlog

from raiden.exceptions import STUNUnavailableException


log = structlog.get_logger(__name__)


def stun_socket(
    socket,
    source_ip='0.0.0.0',
    source_port=4200,
    stun_host=None,
    stun_port=3478,
):
    timeout = socket.gettimeout()
    socket.settimeout(2)
    log.debug('Initiating STUN', source_ip=source_ip, source_port=source_port)
    nat_type, nat = stun.get_nat_type(
        socket,
        source_ip,
        source_port,
        stun_host=stun_host,
        stun_port=stun_port,
    )
    external_ip = nat['ExternalIP']
    if isinstance(external_ip, tuple):
        external_ip = external_ip[0]
    if external_ip is None:
        log.warning('STUN failed', nat=nat)
        raise STUNUnavailableException()
    external_port = nat['ExternalPort']
    log.debug(
        'STUN-socket ready:',
        external_ip=external_ip,
        external_port=external_port,
        nat_type=nat_type,
        nat=nat,
        internal_ip=socket.getsockname()[0],
        internal_port=socket.getsockname()[1],
    )
    nat['type'] = nat_type
    socket.settimeout(timeout)
    return external_ip, external_port, nat
