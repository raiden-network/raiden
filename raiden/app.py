import filelock
import sys
import structlog
from binascii import unhexlify
from eth_utils import to_normalized_address
from typing import Dict

import gevent

from raiden.network.blockchain_service import BlockChainService
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NAT_INVITATION_TIMEOUT,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NAT_KEEPALIVE_TIMEOUT,
    DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
    DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
    DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
    DEFAULT_TRANSPORT_RETRY_INTERVAL,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_SHUTDOWN_TIMEOUT,
    INITIAL_PORT,
)
from raiden.utils import (
    pex,
    privatekey_to_address,
)
from raiden.network.proxies import (
    Registry,
    SecretRegistry,
    Discovery,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


gevent.get_hub().SYSTEM_ERROR = (BaseException,)
gevent.get_hub().NOT_ERROR = (gevent.GreenletExit,)


class App:  # pylint: disable=too-few-public-methods
    DEFAULT_CONFIG = {
        'host': '',
        'port': INITIAL_PORT,
        'external_ip': '',
        'external_port': INITIAL_PORT,
        'privatekey_hex': '',
        'reveal_timeout': DEFAULT_REVEAL_TIMEOUT,
        'settle_timeout': DEFAULT_SETTLE_TIMEOUT,
        'database_path': '',
        'msg_timeout': 100.0,
        'transport': {
            'retry_interval': DEFAULT_TRANSPORT_RETRY_INTERVAL,
            'retries_before_backoff': DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
            'throttle_capacity': DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
            'throttle_fill_rate': DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
            'nat_invitation_timeout': DEFAULT_NAT_INVITATION_TIMEOUT,
            'nat_keepalive_retries': DEFAULT_NAT_KEEPALIVE_RETRIES,
            'nat_keepalive_timeout': DEFAULT_NAT_KEEPALIVE_TIMEOUT,
        },
        'rpc': True,
        'console': False,
        'shutdown_timeout': DEFAULT_SHUTDOWN_TIMEOUT,
        'transport_type': 'udp',
        'matrix': {
            'server': 'auto',
            'available_servers': [
                'https://transport01.raiden.network',
                'https://transport02.raiden.network',
                'https://transport03.raiden.network',
            ],
            'discovery_room': {
                'alias_fragment': 'discovery',
                'server': 'transport01.raiden.network',
            },
        },
    }

    def __init__(
            self,
            config: Dict,
            chain: BlockChainService,
            default_registry: Registry,
            default_secret_registry: SecretRegistry,
            transport,
            discovery: Discovery = None,
    ):
        self.config = config
        self.discovery = discovery

        try:
            self.raiden = RaidenService(
                chain,
                default_registry,
                default_secret_registry,
                unhexlify(config['privatekey_hex']),
                transport,
                config,
                discovery,
            )
        except filelock.Timeout:
            pubkey = to_normalized_address(
                privatekey_to_address(unhexlify(self.config['privatekey_hex'])),
            )
            print(
                f'FATAL: Another Raiden instance already running for account {pubkey} on '
                f'network id {chain.network_id}',
            )
            sys.exit(1)
        self.start_console = self.config['console']

        # raiden.ui.console:Console assumes that a services
        # attribute is available for auto-registration
        self.services = dict()

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def stop(self, leave_channels=False):
        """
        Stop the raiden app.

        Args:
            leave_channels (bool): if True, also close and settle all channels before stopping
        """
        if leave_channels:
            self.raiden.close_and_settle()

        self.raiden.stop()
