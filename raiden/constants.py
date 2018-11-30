import math
from enum import Enum

from eth_utils import keccak, to_checksum_address

SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)
PROTOCOL_VERSION = 1
MIN_REQUIRED_SOLC = 'v0.4.23'

INT64_MAX = 2 ** 63 - 1
UINT256_MAX = 2 ** 256 - 1
UINT64_MAX = 2 ** 64 - 1

GENESIS_BLOCK_NUMBER = 0

NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS = to_checksum_address(NULL_ADDRESS_BYTES)

EMPTY_HASH = bytes(32)
EMPTY_HASH_KECCAK = keccak(EMPTY_HASH)
EMPTY_SIGNATURE = bytes(65)


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


GAS_REQUIRED_FOR_CREATE_ERC20_TOKEN_NETWORK = 3_234_716
GAS_REQUIRED_PER_SECRET_IN_BATCH = math.ceil(UNLOCK_TX_GAS_LIMIT / MAXIMUM_PENDING_TRANSFERS)
GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL = 100_000
