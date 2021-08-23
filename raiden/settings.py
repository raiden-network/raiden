from dataclasses import dataclass, field
from pathlib import Path

from eth_typing import BlockNumber
from eth_utils import denoms, to_hex

import raiden_contracts.constants
from raiden.constants import MATRIX_AUTO_SELECT_SERVER, Environment
from raiden.network.pathfinding import PFSConfig
from raiden.utils.typing import (
    Address,
    BlockTimeout,
    ChainID,
    DatabasePath,
    Dict,
    FeeAmount,
    Host,
    List,
    NetworkTimeout,
    Optional,
    Port,
    ProportionalFeeAmount,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.contract_manager import ContractDevEnvironment, contracts_precompiled_path

CACHE_TTL = 60
GAS_LIMIT = 10 * 10 ** 6
GAS_LIMIT_HEX = to_hex(GAS_LIMIT)
GAS_PRICE = denoms.shannon * 20  # pylint: disable=no-member

DEFAULT_HTTP_SERVER_PORT = Port(5001)

DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF = 1
DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL_INITIAL = 5.0
DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL_MAX = 60.0
DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT = 60_000
# Maximum allowed time between syncs in addition to DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT.
# This is necessary because
# - The matrix server adds up to 10% to avoid thundering herds
# - Network latency
# - The Raiden node might not be able to process the messages immediately
DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY = 15_000
DEFAULT_MATRIX_KNOWN_SERVERS = {
    Environment.PRODUCTION: (
        "https://raw.githubusercontent.com/raiden-network/raiden-service-bundle"
        "/master/known_servers/known_servers-production-v1.2.0.json"
    ),
    Environment.DEVELOPMENT: (
        "https://raw.githubusercontent.com/raiden-network/raiden-service-bundle"
        "/master/known_servers/known_servers-development-v1.2.0.json"
    ),
}

DEFAULT_REVEAL_TIMEOUT = BlockTimeout(50)
DEFAULT_SETTLE_TIMEOUT = BlockTimeout(500)
DEFAULT_RETRY_TIMEOUT = NetworkTimeout(0.5)
DEFAULT_BLOCKCHAIN_QUERY_INTERVAL = 5.0
DEFAULT_JOINABLE_FUNDS_TARGET = 0.4
DEFAULT_INITIAL_CHANNEL_TARGET = 3
DEFAULT_WAIT_FOR_SETTLE = True
DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS = BlockTimeout(5)
DEFAULT_WAIT_BEFORE_LOCK_REMOVAL = BlockTimeout(2 * DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS)
DEFAULT_CHANNEL_SYNC_TIMEOUT = 5

DEFAULT_AVERAGE_BLOCK_TIME = 15.0
DEFAULT_TIMEOUT_BEFORE_BLOCK_PRUNED = 42

DEFAULT_SHUTDOWN_TIMEOUT = 2

DEFAULT_PATHFINDING_MAX_PATHS = 3
DEFAULT_PATHFINDING_MAX_FEE = TokenAmount(5 * 10 ** 16)  # about .01$
# PFS has 200 000 blocks (~40days) to cash in
DEFAULT_PATHFINDING_IOU_TIMEOUT = BlockTimeout(2 * 10 ** 5)

DEFAULT_MEDIATION_FLAT_FEE = FeeAmount(0)
DEFAULT_MEDIATION_PROPORTIONAL_FEE = ProportionalFeeAmount(4000)  # 0.4% in parts per million
DEFAULT_MEDIATION_PROPORTIONAL_IMBALANCE_FEE = ProportionalFeeAmount(
    3000  # 0.3% in parts per million
)
DEFAULT_MEDIATION_FEE_MARGIN: float = 0.03
PAYMENT_AMOUNT_BASED_FEE_MARGIN: float = 0.0005
INTERNAL_ROUTING_DEFAULT_FEE_PERC: float = 0.02
MAX_MEDIATION_FEE_PERC: float = 0.2

ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE = BlockTimeout(3)

RAIDEN_CONTRACT_VERSION = raiden_contracts.constants.CONTRACTS_VERSION

MIN_REI_THRESHOLD = TokenAmount(55 * 10 ** 17)  # about 1.1$

MONITORING_REWARD = TokenAmount(5 * 10 ** 18)  # about 1$

MIN_MONITORING_AMOUNT_DAI = TokenAmount(1 * 10 ** 18)  # naive approach about 1$
MIN_MONITORING_AMOUNT_WETH = TokenAmount(900 * 10 ** 12)  # naive approach about 1$

MIN_REVEAL_TIMEOUT = BlockTimeout(20)

DEFAULT_DAI_FLAT_FEE = 10 ** 12
DEFAULT_WETH_FLAT_FEE = 10 ** 10


@dataclass
class MediationFeeConfig:
    token_to_flat_fee: Dict[TokenAddress, FeeAmount] = field(default_factory=dict)
    token_to_proportional_fee: Dict[TokenAddress, ProportionalFeeAmount] = field(
        default_factory=dict
    )
    token_to_proportional_imbalance_fee: Dict[TokenAddress, ProportionalFeeAmount] = field(
        default_factory=dict
    )
    cap_meditation_fees: bool = True

    def get_flat_fee(self, token_address: TokenAddress) -> FeeAmount:
        return self.token_to_flat_fee.get(  # pylint: disable=no-member
            token_address, DEFAULT_MEDIATION_FLAT_FEE
        )

    def get_proportional_fee(self, token_address: TokenAddress) -> ProportionalFeeAmount:
        return self.token_to_proportional_fee.get(  # pylint: disable=no-member
            token_address, DEFAULT_MEDIATION_PROPORTIONAL_FEE
        )

    def get_proportional_imbalance_fee(self, token_address: TokenAddress) -> ProportionalFeeAmount:
        return self.token_to_proportional_imbalance_fee.get(  # pylint: disable=no-member
            token_address, DEFAULT_MEDIATION_PROPORTIONAL_IMBALANCE_FEE
        )


@dataclass
class CapabilitiesConfig:
    receive: bool = True
    mediate: bool = True
    delivery: bool = True
    web_rtc: bool = True
    to_device: bool = True
    immutable_metadata: bool = True


@dataclass
class MatrixTransportConfig:
    retries_before_backoff: int
    retry_interval_initial: float
    retry_interval_max: float
    server: str
    available_servers: List[str]
    sync_timeout: int = DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT
    sync_latency: int = DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY
    capabilities_config: CapabilitiesConfig = CapabilitiesConfig()


@dataclass
class ServiceConfig:
    pathfinding_service_address: Optional[Address] = None
    pathfinding_max_paths: int = DEFAULT_PATHFINDING_MAX_PATHS
    pathfinding_max_fee: TokenAmount = DEFAULT_PATHFINDING_MAX_FEE
    pathfinding_iou_timeout: BlockTimeout = DEFAULT_PATHFINDING_IOU_TIMEOUT
    monitoring_enabled: bool = False


@dataclass(frozen=True)
class BlockBatchSizeConfig:
    min: BlockNumber = BlockNumber(5)
    warn_threshold: BlockNumber = BlockNumber(50)
    initial: BlockNumber = BlockNumber(1_000)
    max: BlockNumber = BlockNumber(100_000)


@dataclass
class BlockchainConfig:
    confirmation_blocks: BlockTimeout = DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    query_interval: float = DEFAULT_BLOCKCHAIN_QUERY_INTERVAL
    timeout_before_block_pruned: float = DEFAULT_TIMEOUT_BEFORE_BLOCK_PRUNED
    block_batch_size_config: BlockBatchSizeConfig = BlockBatchSizeConfig()


@dataclass
class RestApiConfig:
    rest_api_enabled: bool = True
    web_ui_enabled: bool = False

    cors_domain_list: List[str] = field(default_factory=list)
    eth_rpc_endpoint: Optional[str] = None

    host: Optional[Host] = None
    port: Optional[Port] = None


@dataclass
class PythonApiConfig:
    minimum_reveal_timeout: BlockTimeout = BlockTimeout(1)


@dataclass
class RaidenConfig:
    chain_id: ChainID
    environment_type: Environment

    reveal_timeout: BlockTimeout = DEFAULT_REVEAL_TIMEOUT
    settle_timeout: BlockTimeout = DEFAULT_SETTLE_TIMEOUT

    contracts_path: Path = contracts_precompiled_path(RAIDEN_CONTRACT_VERSION)
    database_path: DatabasePath = ":memory:"

    blockchain: BlockchainConfig = BlockchainConfig()
    mediation_fees: MediationFeeConfig = MediationFeeConfig()
    services: ServiceConfig = ServiceConfig()
    development_environment: ContractDevEnvironment = ContractDevEnvironment.DEMO

    transport_type: str = "matrix"
    transport: MatrixTransportConfig = MatrixTransportConfig(
        # None causes fetching from url in raiden.settings.py::DEFAULT_MATRIX_KNOWN_SERVERS
        available_servers=[],
        retries_before_backoff=DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF,
        retry_interval_initial=DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL_INITIAL,
        retry_interval_max=DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL_MAX,
        server=MATRIX_AUTO_SELECT_SERVER,
        sync_timeout=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        capabilities_config=CapabilitiesConfig(),
    )

    rest_api: RestApiConfig = RestApiConfig()
    python_api: PythonApiConfig = PythonApiConfig()

    shutdown_timeout: int = DEFAULT_SHUTDOWN_TIMEOUT
    unrecoverable_error_should_crash: bool = False

    console: bool = False
    resolver_endpoint: Optional[str] = None

    pfs_config: Optional[PFSConfig] = None
