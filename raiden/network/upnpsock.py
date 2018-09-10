import ipaddress

import miniupnpc
import structlog

MAX_PORT = 65535
RAIDEN_IDENTIFICATOR = 'raiden-network udp service'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

NON_MAPPABLE = [
    '127.0.0.1',
    '0.0.0.0',
]


def valid_mappable_ipv4(address):
    try:
        address_uni = str(address, errors='ignore')
    except TypeError:
        address_uni = address

    if address_uni in NON_MAPPABLE:
        return False

    try:
        parsed = ipaddress.ip_address(address_uni)
    except ValueError:
        log.debug('invalid IPv4 address', input=address)
        return False
    if parsed is not None and parsed.version == 4:
        return True
    else:
        return False


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
        log.debug('multiple upnp providers found', num_providers=providers)
    elif providers < 1:
        log.error('no upnp providers found')
        return

    try:
        location = upnp.selectigd()
        log.debug('connected', upnp=upnp)
    except Exception as e:
        log.error('Error when connecting to uPnP provider', exception_info=e)
        return None

    if not valid_mappable_ipv4(upnp.lanaddr):
        log.error('could not query your lanaddr', reported=upnp.lanaddr)
        return
    try:  # this can fail if router advertises uPnP incorrectly
        if not valid_mappable_ipv4(upnp.externalipaddress()):
            log.error('could not query your externalipaddress', reported=upnp.externalipaddress())
            return
        return upnp, location
    except Exception:
        log.error('error when connecting with uPnP provider', location=location)
        return None


def open_port(upnp, internal_port, external_start_port=None):
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

    if upnp is None:
        return

    def register(internal, external):
        # test existing mappings
        mapping = upnp.getspecificportmapping(external, 'UDP')
        if mapping is not None:
            # FIXME: figure out semantics of attr1 and attr2
            lanaddr, internal_mapped, name, attr1, attr2 = mapping
            if (
                lanaddr == upnp.lanaddr and
                name == RAIDEN_IDENTIFICATOR and
                internal_mapped == internal
            ):
                log.debug(
                    'keeping pre-existing portmapping',
                    internal=internal,
                    external=external,
                    lanaddr=lanaddr,
                )
                return True
            elif lanaddr != upnp.lanaddr:
                # don't touch other people's mappings
                log.debug(
                    'ignoring existing mapping for other IP',
                    internal=internal,
                    external=external,
                    other_ip=lanaddr,
                    our_ip=upnp.lanaddr,
                )
                return False
            elif (
                internal_mapped != internal and
                name != RAIDEN_IDENTIFICATOR
            ):
                log.debug(
                    'ignoring existing mapping for other program',
                    name=name,
                )
                # some other program uses our port
                return False
            elif (
                internal_mapped != internal and
                name == RAIDEN_IDENTIFICATOR and
                lanaddr == upnp.lanaddr
            ):
                # we ran before on a different internal port
                log.debug('releasing previous port mapping')
                upnp.deleteportmapping(external, 'UDP')

        log.debug('trying to create new port mapping', internal=internal, external=external)
        return upnp.addportmapping(
            external,
            'UDP',
            upnp.lanaddr,
            internal,
            RAIDEN_IDENTIFICATOR,
            '',
        )

    external_port = external_start_port
    success = register(internal_port, external_port)
    while not success and external_port <= MAX_PORT:
        external_port += 1
        log.debug('trying', external=external_port)
        success = register(internal_port, external_port)

    if success:
        return upnp.externalipaddress(), external_port
    else:
        log.error(
            'could not register a port-mapping',
            location='FIXME',
        )
        return


def release_port(upnp, external_port):
    """Try to release the port mapping for `external_port`.

    Args:
        external_port (int): the port that was previously forwarded to.

    Returns:
        success (boolean): if the release was successful.
    """
    mapping = upnp.getspecificportmapping(external_port, 'UDP')

    if mapping is None:
        log.error('could not find a port mapping', external=external_port)
        return False
    else:
        log.debug('found existing port mapping', mapping=mapping)

    if upnp.deleteportmapping(external_port, 'UDP'):
        log.info('successfully released port mapping', external=external_port)
        return True

    log.warning(
        'could not release port mapping, check your router for stale mappings',
    )
    return False
