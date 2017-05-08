from contextlib import contextmanager
from raiden.network import upnpsock, stunsock


class PortMappedSocket(object):
    """Wrapper around a socket instance with port mapping information.
    """
    def __init__(self, sock, method, external_ip, external_port, **meta):
        self.socket = sock
        self.method = method
        self.external_ip = external_ip
        self.external_port = external_port
        self.meta = meta

    def __repr__(self):
        return 'PortMappedSocket<{} mapping: {}:{} ({})>'.format(
            self.socket.__repr__(),
            self.external_ip,
            self.external_port,
            self.method
        )


@contextmanager
def socket_factory(source_ip, source_port, *args, **kwargs):
    """
    Create a port mapped socket via uPnP or STUN.
    Args:
        source_ip (ip string): the network interface/ip to bind
        source_port (int): the local port to bind
        *args: generic args that are passed to the below implementations
        **kargs: generic kwargs that are passed to the below implementations
    Return:
        PortMappedSocket
    """
    # prefer uPnP over STUN
    upnp = upnpsock.connect()
    if upnp is not None:
        router, location = upnp
        result = upnpsock.open_port(
            router,
            source_port,
        )
        if result is not None:
            with stunsock.open_bare_socket(source_ip, source_port, *args, **kwargs) as sock:
                try:
                    yield PortMappedSocket(sock, 'uPnP', result[0], result[1], **dict(
                        router_location=location
                    ))
                finally:
                    upnpsock.release_port(router, source_port)

    else:
        with stunsock.stun_socket(source_ip, source_port, *args, **kwargs) as (
            sock,
            external_ip,
            external_port,
            nat
        ):
            if external_port is not None:
                yield PortMappedSocket(sock, 'STUN', external_ip, external_port, **nat)
