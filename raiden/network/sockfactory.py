import errno
import netifaces
import socket
import structlog

from raiden.exceptions import STUNUnavailableException, RaidenServicePortInUseError
from raiden.network import upnpsock, stunsock

log = structlog.get_logger(__name__)


class PortMappedSocket:
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
            self.method,
        )


class SocketFactory:
    STRATEGY_TO_METHODS = {
        'auto': ['upnp', 'stun', 'none'],
        'upnp': ['upnp', 'none'],
        'stun': ['stun', 'none'],
        'none': ['none'],
        'ext': ['ext'],
    }

    def __init__(self, source_ip, source_port, strategy='auto', **kwargs):
        """
        Create a port mapped socket via selectable strategy.
        Args:
            source_ip (ip string): the network interface/ip to bind
            source_port (int): the local port to bind
            strategy (str, tuple): Strategy to use to traverse NAT (auto, upnp, stun, none,
                                   (ip, port))
            **kwargs: generic kwargs that are passed to the underlying implementations

        The traversal methods are implemented in the `map_<method>` and `unmap_<method>` methods.
        """
        self.source_ip = source_ip
        self.source_port = source_port
        self.method_args = None
        if isinstance(strategy, tuple):
            if strategy[1] is None:
                # If no external port was provided use local one
                strategy = strategy[0], source_port
            self.strategy_args = strategy
            strategy = 'ext'
        self.strategy = strategy
        self.kwargs = kwargs
        self.method = None
        self.socket = None
        self.storage = {}

    def __enter__(self):
        log.debug('Acquiring socket', strategy=self.strategy_description)

        self._open_socket()

        for method in self.STRATEGY_TO_METHODS[self.strategy]:
            log.debug('Trying', method=method)

            mapped_socket = getattr(self, 'map_{}'.format(method))()
            if mapped_socket:
                assert isinstance(mapped_socket, PortMappedSocket)
                self.method = method
                log.debug('Success', method=method)
                break
            log.debug('Unavailable', method=method)
        else:
            # This should not happen unless the method mapping has been broken (e.g. by
            # removing the 'none' fallback)
            raise RuntimeError("Couldn't create PortMappedSocket!")

        if method == 'ext':
            method = 'ext:{}'.format(
                ':'.join(str(s) for s in self.strategy_args),
            )
        log.info(
            'Network port opened',
            method=method,
            internal='{}:{}'.format(self.source_ip, self.source_port),
            external='{}:{}'.format(mapped_socket.external_ip, mapped_socket.external_port),
        )
        return mapped_socket

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.method:
            try:
                getattr(self, 'unmap_{}'.format(self.method))()
            finally:
                if self.socket:
                    self.socket.close()

    def map_upnp(self):
        upnp = upnpsock.connect()
        if upnp is None:
            return

        try:
            router, location = upnp
            result = upnpsock.open_port(
                router,
                self.source_port,
            )
            if result is not None:
                self.storage['router'] = router
                self.storage['external_port'] = result[1]
                return PortMappedSocket(self.socket, 'UPnP', result[0], result[1],
                                        router_location=location)
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                raise RaidenServicePortInUseError()
            raise

    def unmap_upnp(self):
        upnpsock.release_port(self.storage['router'], self.storage['external_port'])

    def map_stun(self):
        try:
            external_ip, external_port, nat = stunsock.stun_socket(
                self.socket,
                self.source_ip,
                self.source_port,
                **self.kwargs,
            )
            if external_port is not None:
                return PortMappedSocket(self.socket, 'STUN', external_ip, external_port, **nat)
        except STUNUnavailableException:
            pass

    def unmap_stun(self):
        pass

    def map_none(self):
        if self.source_ip == '0.0.0.0':
            try:
                default_gw_if = netifaces.gateways()['default'][netifaces.AF_INET][1]
                self.source_ip = netifaces.ifaddresses(default_gw_if)[netifaces.AF_INET][0]['addr']
            except (OSError, IndexError, KeyError):
                log.critical("Couldn't get interface address. "
                             "Try specifying with '--nat ext:<ip>'.")
                raise
        log.warning('Using internal interface address. Connectivity issues are likely.')
        return PortMappedSocket(self.socket, 'NONE', self.source_ip, self.source_port)

    def unmap_none(self):
        pass

    def map_ext(self):
        return PortMappedSocket(self.socket, 'EXT', self.strategy_args[0], self.strategy_args[1])

    def unmap_ext(self):
        pass

    def _open_socket(self):
        sock = socket.socket(
            socket.AF_INET,  # Internet
            socket.SOCK_DGRAM,  # UDP
        )

        try:
            sock.bind((self.source_ip, self.source_port))
            log.debug(
                'Socket opened',
                ip=sock.getsockname()[0],
                port=sock.getsockname()[1],
            )
            self.socket = sock
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                raise RaidenServicePortInUseError()
            raise

    @property
    def strategy_description(self):
        if self.strategy != 'ext':
            return self.strategy
        return '{}:{}'.format(self.strategy, ':'.join(str(s) for s in self.strategy_args))
