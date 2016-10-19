# -*- coding: utf-8 -*-
import miniupnpc
from ethereum import slogging

MAX_PORT = 65535
RAIDEN_IDENTIFICATOR = "raiden-network udp service"

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def connect():
    """Try to connect to the router.
    Returns:
        u (miniupnc.UPnP): the connected upnp-instance
        router (string): the connection information
    """
    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 200
    providers = upnp.discover()
    if providers > 1:
        log.warning("multiple upnp providers found", num_providers=providers)
    elif providers < 1:
        log.error("no upnp providers found")
        return

    router = upnp.selectigd()
    log.debug("connected", router=router)

    if upnp.lanaddr == '0.0.0.0':
        log.error("could not query your lanaddr")
        return
    if upnp.externalipaddress() == '0.0.0.0' or upnp.externalipaddress() is None:
        log.error("could not query your externalipaddress")
        return
    return upnp, router


def open_port(internal_port, external_start_port=None):
    """Open a port for the raiden service (listening at `internal_port`) through
    UPnP.
    Args:
        internal_port (int): the target port of the raiden service
        external_start_port (int): query for an external port starting here
            (default: internal_port)
    Returns:
        external_ip_address, external_port (tuple(str, int)): if successful or None
    """
    if external_start_port is None:
        external_start_port = internal_port

    upnp, _ = connect()

    if upnp is None:
        return

    def register(internal, external):
        return upnp.addportmapping(
            internal,
            'UDP',
            upnp.lanaddr,
            external,
            RAIDEN_IDENTIFICATOR,
            '',
        )

    external_port = external_start_port
    success = register(internal_port, external_port)
    while not success and external_port <= MAX_PORT:
        external_port += 1
        success = register(internal_port, external_port)

    if success:
        internal = '{}:{}'.format(upnp.lanaddr, internal_port)
        external = '{}:{}'.format(upnp.externalipaddress(), external_port)

        log.info(
            'registered port-mapping per upnp',
            internal=internal,
            external=external,
        )

        return (upnp.externalipaddress(), external_port)

    log.error(
        'could not register a port-mapping',
        router='FIXME',
    )
    return


def release_port(internal_port):
    """Try to release the port mapping for `internal_port`.

    Args:
        internal_port (int): the port that was previously forwarded to.

    Returns:
        success (boolean): if the release was successful.
    """
    upnp, router = connect()
    mapping = upnp.getspecificportmapping(internal_port, 'UDP')

    if mapping is None:
        log.error('could not find a port mapping', router=router)
        return False

    if upnp.deleteportmapping(internal_port, 'UDP'):
        log.info('successfully released port mapping', router=router)
        return True

    log.warning(
        'could not release port mapping, check your router for stale mappings',
        router=router,
    )
    return False
