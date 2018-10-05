from enum import Enum

from eth_utils import to_checksum_address

SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)

UINT64_MAX = 2 ** 64 - 1
UINT64_MIN = 0

INT64_MAX = 2 ** 63 - 1
INT64_MIN = -(2 ** 63)

UINT256_MAX = 2 ** 256 - 1


class EthClient(Enum):
    GETH = 1
    PARITY = 2
    TESTER = 3


DISCOVERY_TX_GAS_LIMIT = 76000


# The more pending transfers there are, the more computationally complex
# it becomes to unlock them. Lest an unlocking operation fails because
# not enough gas is available, we define a gas limit for unlock calls
# and limit the number of pending transfers per channel so it is not
# exceeded. The limit is inclusive.
UNLOCK_TX_GAS_LIMIT = int(0.4 * 3141592)
MAXIMUM_PENDING_TRANSFERS = 160


ETH_RPC_DEFAULT_PORT = 8545
HTTP_PORT = 80
HTTPS_PORT = 443

EMPTY_HASH = bytes(32)
EMPTY_SIGNATURE = bytes(65)

START_QUERY_BLOCK_KEY = 'DefaultStartBlock'

MIN_REQUIRED_SOLC = 'v0.4.23'
NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS = to_checksum_address(NULL_ADDRESS_BYTES)

SNAPSHOT_STATE_CHANGES_COUNT = 500

# calculated as of raiden-contracts@d3c30e6d081ac3ed8fbf3f16381889baa3963ea7
# https://github.com/raiden-network/raiden-contracts/tree/d3c30e6d081ac3ed8fbf3f16381889baa3963ea7
GAS_REQUIRED_FOR_OPEN_CHANNEL = 109933
GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT = 42214
GAS_REQUIRED_FOR_REGISTER_SECRET = 46161
GAS_REQUIRED_FOR_CLOSE_CHANNEL = 112684
GAS_REQUIRED_FOR_BALANCE_PROOF = 96284
GAS_REQUIRED_FOR_SETTLE_CHANNEL = 125009
GAS_REQUIRED_FOR_UNLOCK_1_LOCKS = 33547
GAS_REQUIRED_FOR_UNLOCK_6_LOCKS = 73020
