from enum import Enum

from eth_utils import to_checksum_address

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
EMPTY_SIGNATURE = bytes(65)


class EthClient(Enum):
    GETH = 1
    PARITY = 2


ETH_RPC_DEFAULT_PORT = 8545
HTTP_PORT = 80
HTTPS_PORT = 443

START_QUERY_BLOCK_KEY = 'DefaultStartBlock'
SNAPSHOT_STATE_CHANGES_COUNT = 500

# The more pending transfers there are, the more computationally complex
# it becomes to unlock them. Lest an unlocking operation fails because
# not enough gas is available, we define a gas limit for unlock calls
# and limit the number of pending transfers per channel so it is not
# exceeded. The limit is inclusive.
TRANSACTION_GAS_LIMIT = int(0.4 * 3141592)
MAXIMUM_PENDING_TRANSFERS = 160


class Environment(Enum):
    """Environment configurations that can be chosen on the command line."""
    PRODUCTION = 'production'
    DEVELOPMENT = 'development'
