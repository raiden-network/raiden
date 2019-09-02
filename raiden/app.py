import structlog
from eth_utils import to_checksum_address

from raiden.constants import DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, RoutingMode
from raiden.exceptions import InvalidSettleTimeout
from raiden.message_handler import MessageHandler
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.transport.matrix.transport import MatrixTransport
from raiden.raiden_event_handler import EventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    DEFAULT_PATHFINDING_IOU_TIMEOUT,
    DEFAULT_PATHFINDING_MAX_FEE,
    DEFAULT_PATHFINDING_MAX_PATHS,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_SHUTDOWN_TIMEOUT,
    DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL,
    DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
    PRODUCTION_CONTRACT_VERSION,
)
from raiden.utils import typing
from raiden.utils.typing import Address
from raiden_contracts.contract_manager import contracts_precompiled_path

log = structlog.get_logger(__name__)


class App:  # pylint: disable=too-few-public-methods
    DEFAULT_CONFIG = {
        "reveal_timeout": DEFAULT_REVEAL_TIMEOUT,
        "settle_timeout": DEFAULT_SETTLE_TIMEOUT,
        "contracts_path": contracts_precompiled_path(PRODUCTION_CONTRACT_VERSION),
        "database_path": "",
        "transport_type": "matrix",
        "blockchain": {"confirmation_blocks": DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS},
        "transport": {
            "matrix": {
                # None causes fetching from url in raiden.settings.py::DEFAULT_MATRIX_KNOWN_SERVERS
                "available_servers": None,
                # TODO: Remove `PATH_FINDING_BROADCASTING_ROOM` when implementing #3735
                #       and fix the conditional in `raiden.ui.app:_setup_matrix`
                #       as well as the tests
                "global_rooms": [DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM],
                "retries_before_backoff": DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
                "retry_interval": DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL,
                "server": "auto",
            }
        },
        "rpc": True,
        "console": False,
        "shutdown_timeout": DEFAULT_SHUTDOWN_TIMEOUT,
        "services": {
            "pathfinding_service_address": None,
            "pathfinding_max_paths": DEFAULT_PATHFINDING_MAX_PATHS,
            "pathfinding_max_fee": DEFAULT_PATHFINDING_MAX_FEE,
            "pathfinding_iou_timeout": DEFAULT_PATHFINDING_IOU_TIMEOUT,
            "monitoring_enabled": False,
        },
    }

    def __init__(
        self,
        config: typing.Dict,
        chain: BlockChainService,
        query_start_block: typing.BlockNumber,
        default_registry: TokenNetworkRegistry,
        default_secret_registry: SecretRegistry,
        default_service_registry: typing.Optional[ServiceRegistry],
        default_one_to_n_address: typing.Optional[Address],
        default_msc_address: Address,
        transport: MatrixTransport,
        raiden_event_handler: EventHandler,
        message_handler: MessageHandler,
        routing_mode: RoutingMode,
        user_deposit: UserDeposit = None,
    ):
        raiden = RaidenService(
            chain=chain,
            query_start_block=query_start_block,
            default_registry=default_registry,
            default_one_to_n_address=default_one_to_n_address,
            default_secret_registry=default_secret_registry,
            default_service_registry=default_service_registry,
            default_msc_address=default_msc_address,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
            routing_mode=routing_mode,
            config=config,
            user_deposit=user_deposit,
        )

        # check that the settlement timeout fits the limits of the contract
        invalid_settle_timeout = (
            config["settle_timeout"] < default_registry.settlement_timeout_min()
            or config["settle_timeout"] > default_registry.settlement_timeout_max()
            or config["settle_timeout"] < config["reveal_timeout"] * 2
        )
        if invalid_settle_timeout:
            raise InvalidSettleTimeout(
                (
                    "Settlement timeout for Registry contract {} must "
                    "be in range [{}, {}], is {}"
                ).format(
                    to_checksum_address(default_registry.address),
                    default_registry.settlement_timeout_min(),
                    default_registry.settlement_timeout_max(),
                    config["settle_timeout"],
                )
            )

        self.config = config
        self.user_deposit = user_deposit
        self.raiden = raiden

    def __repr__(self) -> str:
        return "<{} {}>".format(self.__class__.__name__, to_checksum_address(self.raiden.address))

    def start(self) -> None:
        """ Start the raiden app. """
        if self.raiden.stop_event.is_set():
            self.raiden.start()
            log.info("Raiden started", node=self.raiden.address)

    def stop(self) -> None:
        """ Stop the raiden app. """
        if not self.raiden.stop_event.is_set():
            self.raiden.stop()
            log.info("Raiden stopped", node=self.raiden.address)
