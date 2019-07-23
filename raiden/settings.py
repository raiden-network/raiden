from eth_utils import denoms, to_hex

import raiden_contracts.constants
from raiden.constants import Environment
from raiden.utils.typing import FeeAmount, NetworkTimeout, TokenAmount

CACHE_TTL = 60
GAS_LIMIT = 10 * 10 ** 6
GAS_LIMIT_HEX = to_hex(GAS_LIMIT)
GAS_PRICE = denoms.shannon * 20  # pylint: disable=no-member

DEFAULT_HTTP_SERVER_PORT = 5001

DEFAULT_TRANSPORT_RETRIES_BEFORE_BACKOFF = 5
DEFAULT_TRANSPORT_THROTTLE_CAPACITY = 10.0
DEFAULT_TRANSPORT_THROTTLE_FILL_RATE = 10.0
# matrix gets spammed with the default retry-interval of 1s, wait a little more
DEFAULT_TRANSPORT_MATRIX_RETRY_INTERVAL = 5.0
DEFAULT_MATRIX_KNOWN_SERVERS = {
    Environment.PRODUCTION: (
        "https://raw.githubusercontent.com/raiden-network/raiden-transport"
        "/master/known_servers.main.yaml"
    ),
    Environment.DEVELOPMENT: (
        "https://raw.githubusercontent.com/raiden-network/raiden-transport"
        "/master/known_servers.test.yaml"
    ),
}

DEFAULT_REVEAL_TIMEOUT = 50
DEFAULT_SETTLE_TIMEOUT = 500
DEFAULT_RETRY_TIMEOUT = NetworkTimeout(0.5)
DEFAULT_JOINABLE_FUNDS_TARGET = 0.4
DEFAULT_INITIAL_CHANNEL_TARGET = 3
DEFAULT_WAIT_FOR_SETTLE = True
DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS = 5
DEFAULT_WAIT_BEFORE_LOCK_REMOVAL = 2 * DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
DEFAULT_CHANNEL_SYNC_TIMEOUT = 5

DEFAULT_SHUTDOWN_TIMEOUT = 2

DEFAULT_PATHFINDING_MAX_PATHS = 3
DEFAULT_PATHFINDING_MAX_FEE = 1000
DEFAULT_PATHFINDING_IOU_TIMEOUT = 50000  # now the pfs has 200h to cash in

DEFAULT_MEDIATION_FLAT_FEE = FeeAmount(0)
DEFAULT_MEDIATION_PROPORTIONAL_FEE = 0
DEFAULT_MEDIATION_MAX_IMBALANCE_FEE = FeeAmount(0)

ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE = 3
ETHERSCAN_API = "https://{network}.etherscan.io/api?module=proxy&action={action}"

PRODUCTION_CONTRACT_VERSION = raiden_contracts.constants.CONTRACTS_VERSION
DEVELOPMENT_CONTRACT_VERSION = raiden_contracts.constants.CONTRACTS_VERSION

MIN_REI_THRESHOLD = 100

MONITORING_REWARD = TokenAmount(1)
MONITORING_MIN_CAPACITY = TokenAmount(100)

MEDIATION_FEE = FeeAmount(0)
