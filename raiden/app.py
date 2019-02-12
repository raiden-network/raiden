import structlog
from eth_utils import to_checksum_address

from raiden.constants import DISCOVERY_DEFAULT_ROOM
from raiden.exceptions import InvalidSettleTimeout
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import Discovery, SecretRegistry, TokenNetworkRegistry
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NAT_INVITATION_TIMEOUT,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NAT_KEEPALIVE_TIMEOUT,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_SHUTDOWN_TIMEOUT,
    DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL,
    DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
    DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
    DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
    DEFAULT_TRANSPORT_UDP_RETRY_INTERVAL,
    INITIAL_PORT,
    RED_EYES_CONTRACT_VERSION,
)
from raiden.utils import pex, typing
from raiden_contracts.contract_manager import contracts_precompiled_path

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class App:  # pylint: disable=too-few-public-methods
    DEFAULT_CONFIG = {
        'reveal_timeout': DEFAULT_REVEAL_TIMEOUT,
        'settle_timeout': DEFAULT_SETTLE_TIMEOUT,
        'contracts_path': contracts_precompiled_path(RED_EYES_CONTRACT_VERSION),
        'database_path': '',
        'transport_type': 'udp',
        'blockchain': {
            'confirmation_blocks': DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        },
        'transport': {
            'udp': {
                'external_ip': '',
                'external_port': INITIAL_PORT,
                'host': '',
                'nat_invitation_timeout': DEFAULT_NAT_INVITATION_TIMEOUT,
                'nat_keepalive_retries': DEFAULT_NAT_KEEPALIVE_RETRIES,
                'nat_keepalive_timeout': DEFAULT_NAT_KEEPALIVE_TIMEOUT,
                'port': INITIAL_PORT,
                'retries_before_backoff': DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
                'retry_interval': DEFAULT_TRANSPORT_UDP_RETRY_INTERVAL,
                'throttle_capacity': DEFAULT_TRANSPORT_THROTTLE_CAPACITY,
                'throttle_fill_rate': DEFAULT_TRANSPORT_THROTTLE_FILL_RATE,
            },
            'matrix': {
                # None causes fetching from url in raiden.settings.py::DEFAULT_MATRIX_KNOWN_SERVERS
                'available_servers': None,
                'global_rooms': [DISCOVERY_DEFAULT_ROOM],
                'retries_before_backoff': DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
                'retry_interval': DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL,
                'server': 'auto',
            },
        },
        'rpc': True,
        'console': False,
        'shutdown_timeout': DEFAULT_SHUTDOWN_TIMEOUT,
        'services': {
            'pathfinding_service_address': None,
            'pathfinding_max_paths': 3,
            'monitoring_enabled': False,
        },
    }

    def __init__(
            self,
            config: typing.Dict,
            chain: BlockChainService,
            query_start_block: typing.BlockNumber,
            default_registry: TokenNetworkRegistry,
            default_secret_registry: SecretRegistry,
            transport,
            raiden_event_handler,
            message_handler,
            discovery: Discovery = None,
    ):
        raiden = RaidenService(
            chain=chain,
            query_start_block=query_start_block,
            default_registry=default_registry,
            default_secret_registry=default_secret_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
            config=config,
            discovery=discovery,
        )

        # check that the settlement timeout fits the limits of the contract
        invalid_settle_timeout = (
            config['settle_timeout'] < default_registry.settlement_timeout_min() or
            config['settle_timeout'] > default_registry.settlement_timeout_max() or
            config['settle_timeout'] < config['reveal_timeout'] * 2
        )
        if invalid_settle_timeout:
            raise InvalidSettleTimeout(
                (
                    'Settlement timeout for Registry contract {} must '
                    'be in range [{}, {}], is {}'
                ).format(
                    to_checksum_address(default_registry.address),
                    default_registry.settlement_timeout_min(),
                    default_registry.settlement_timeout_max(),
                    config['settle_timeout'],
                ),
            )

        self.config = config
        self.discovery = discovery
        self.raiden = raiden
        self.start_console = self.config['console']

        # raiden.ui.console:Console assumes that a services
        # attribute is available for auto-registration
        self.services = dict()

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def start(self):
        """ Start the raiden app. """
        if self.raiden.stop_event.is_set():
            self.raiden.start()

    def stop(self):
        """ Stop the raiden app.

        Args:
            leave_channels: if True, also close and settle all channels before stopping
        """
        if not self.raiden.stop_event.is_set():
            self.raiden.stop()
