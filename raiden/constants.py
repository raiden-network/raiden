import math
from enum import Enum

from eth_utils import keccak, to_checksum_address, to_hex

LATEST = 'https://api.github.com/repos/raiden-network/raiden/releases/latest'
RELEASE_PAGE = 'https://github.com/raiden-network/raiden/releases'
SECURITY_EXPRESSION = r'\[CRITICAL UPDATE.*?\]'

RAIDEN_DB_VERSION = 20
SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)
PROTOCOL_VERSION = 1
MIN_REQUIRED_SOLC = 'v0.4.23'

INT64_MAX = 2 ** 63 - 1
UINT256_MAX = 2 ** 256 - 1
UINT64_MAX = 2 ** 64 - 1

RED_EYES_MAX_TOKEN_NETWORKS = 1
RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = int(0.075 * 10 ** 18)
RED_EYES_PER_TOKEN_NETWORK_LIMIT = int(250 * 10 ** 18)

GENESIS_BLOCK_NUMBER = 0
# Set at 64 since parity's default is 64 and Geth's default is 128
# TODO: Make this configurable. Since in parity this is also a configurable value
STATE_PRUNING_AFTER_BLOCKS = 64
STATE_PRUNING_SAFETY_MARGIN = 8
NO_STATE_QUERY_AFTER_BLOCKS = STATE_PRUNING_AFTER_BLOCKS - STATE_PRUNING_SAFETY_MARGIN

NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS = to_checksum_address(NULL_ADDRESS_BYTES)

EMPTY_HASH = bytes(32)
EMPTY_HASH_KECCAK = keccak(EMPTY_HASH)
EMPTY_SIGNATURE = bytes(65)
EMPTY_MERKLE_ROOT = bytes(32)

SECRET_HASH_HEXSTRING_LENGTH = len(to_hex(EMPTY_HASH))
SECRET_HEXSTRING_LENGTH = SECRET_HASH_HEXSTRING_LENGTH

RECEIPT_FAILURE_CODE = 0


class EthClient(Enum):
    GETH = 1
    PARITY = 2


ETH_RPC_DEFAULT_PORT = 8545
HTTP_PORT = 80
HTTPS_PORT = 443

START_QUERY_BLOCK_KEY = 'DefaultStartBlock'
SNAPSHOT_STATE_CHANGES_COUNT = 500

# An arbitrary limit for transaction size in Raiden, added in PR #1990
TRANSACTION_GAS_LIMIT_UPPER_BOUND = int(0.4 * 3_141_592)

# Used to add a 30% security margin to gas estimations in case the calculations are off
GAS_FACTOR = 1.3

# The more pending transfers there are, the more computationally complex
# it becomes to unlock them. Lest an unlocking operation fails because
# not enough gas is available, we define a gas limit for unlock calls
# and limit the number of pending transfers per channel so it is not
# exceeded. The limit is inclusive.
UNLOCK_TX_GAS_LIMIT = TRANSACTION_GAS_LIMIT_UPPER_BOUND
MAXIMUM_PENDING_TRANSFERS = 160


class Environment(Enum):
    """Environment configurations that can be chosen on the command line."""
    PRODUCTION = 'production'
    DEVELOPMENT = 'development'


class RoutingMode(Enum):
    """Routing mode configuration that can be chosen on the command line"""
    BASIC = 'basic'
    PFS = 'pfs'


GAS_REQUIRED_FOR_CREATE_ERC20_TOKEN_NETWORK = 3_234_716
GAS_REQUIRED_PER_SECRET_IN_BATCH = math.ceil(UNLOCK_TX_GAS_LIMIT / MAXIMUM_PENDING_TRANSFERS)
GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL = 100_000

CHECK_RDN_MIN_DEPOSIT_INTERVAL = 5 * 60
CHECK_GAS_RESERVE_INTERVAL = 5 * 60
CHECK_VERSION_INTERVAL = 3 * 60 * 60
CHECK_NETWORK_ID_INTERVAL = 5 * 60

DEFAULT_HTTP_REQUEST_TIMEOUT = 1.0  # seconds

DISCOVERY_DEFAULT_ROOM = 'discovery'
MONITORING_BROADCASTING_ROOM = 'monitoring'
PATH_FINDING_BROADCASTING_ROOM = 'path_finding'
