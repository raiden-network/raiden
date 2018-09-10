import socket

import structlog
from eth_utils import is_binary_address

from raiden.exceptions import InvalidAddress, UnknownAddress
from raiden.network import proxies
from raiden.utils import host_port_to_endpoint, pex, split_endpoint

log = structlog.get_logger(__name__)


class Discovery:
    """ Mock mapping address: host, port """

    def __init__(self):
        self.nodeid_to_hostport = dict()

    def register(self, node_address: bytes, host: str, port: int):
        if not is_binary_address(node_address):
            raise ValueError('node_address must be a valid address')

        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raise ValueError('invalid ip address provided: {}'.format(host))

        if not isinstance(port, int):
            raise ValueError('port must be a valid number')

        self.nodeid_to_hostport[node_address] = (host, port)

    def get(self, node_address: bytes):
        try:
            return self.nodeid_to_hostport[node_address]
        except KeyError:
            raise InvalidAddress('Unknown address {}'.format(pex(node_address)))


class ContractDiscovery(Discovery):
    """ Raiden node discovery.

    Allows registering and looking up by endpoint (host, port) for node_address.
    """

    def __init__(
            self,
            node_address: bytes,
            discovery_proxy: proxies.Discovery,
    ):

        super().__init__()

        self.node_address = node_address
        self.discovery_proxy = discovery_proxy

    def register(self, node_address: bytes, host: str, port: int):
        if node_address != self.node_address:
            raise ValueError('You can only register your own endpoint.')

        if not is_binary_address(node_address):
            raise ValueError('node_address must be a valid address')

        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raise ValueError('invalid ip address provided: {}'.format(host))

        if not isinstance(port, int):
            raise ValueError('port must be a valid number')

        try:
            current_value = self.get(node_address)
        except UnknownAddress:
            current_value = None

        if current_value == (host, port):
            log.info(
                'endpoint already registered',
                node_address=pex(node_address),
                host=host,
                port=port,
            )
        else:
            endpoint = host_port_to_endpoint(host, port)
            self.discovery_proxy.register_endpoint(node_address, endpoint)
            log.info(
                'registered endpoint in discovery',
                node_address=pex(node_address),
                host=host,
                port=port,
            )

    def get(self, node_address: bytes):
        endpoint = self.discovery_proxy.endpoint_by_address(node_address)
        host_port = split_endpoint(endpoint)
        return host_port

    def version(self):
        return self.discovery_proxy.version()
