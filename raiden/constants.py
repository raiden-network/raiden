import math
from enum import Enum
from hashlib import sha256

from eth_utils import keccak, to_checksum_address

from raiden.utils.typing import (
    AdditionalHash,
    BalanceHash,
    BlockHash,
    BlockNumber,
    Locksroot,
    RaidenDBVersion,
    RaidenProtocolVersion,
    Secret,
    SecretHash,
    Signature,
    TokenAmount,
    TransactionHash,
)

LATEST = "https://api.github.com/repos/raiden-network/raiden/releases/latest"
RELEASE_PAGE = "https://github.com/raiden-network/raiden/releases"
SECURITY_EXPRESSION = r"\[CRITICAL UPDATE.*?\]"

RAIDEN_DB_VERSION = RaidenDBVersion(23)
SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)
PROTOCOL_VERSION = RaidenProtocolVersion(1)

UINT256_MAX = 2 ** 256 - 1
UINT64_MAX = 2 ** 64 - 1

SECONDS_PER_DAY = 24 * 60 * 60

RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = int(0.075 * 10 ** 18)
RED_EYES_PER_TOKEN_NETWORK_LIMIT = int(250 * 10 ** 18)

GENESIS_BLOCK_NUMBER = BlockNumber(0)
# Set at 64 since parity's default is 64 and Geth's default is 128
# TODO: Make this configurable. Since in parity this is also a configurable value
STATE_PRUNING_AFTER_BLOCKS = 64
STATE_PRUNING_SAFETY_MARGIN = 8
NO_STATE_QUERY_AFTER_BLOCKS = STATE_PRUNING_AFTER_BLOCKS - STATE_PRUNING_SAFETY_MARGIN

NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS = to_checksum_address(NULL_ADDRESS_BYTES)

EMPTY_HASH = BlockHash(bytes(32))
EMPTY_TRANSACTION_HASH = TransactionHash(bytes(32))
EMPTY_BALANCE_HASH = BalanceHash(bytes(32))
EMPTY_MESSAGE_HASH = AdditionalHash(bytes(32))
EMPTY_SIGNATURE = Signature(bytes(65))
EMPTY_SECRETHASH = SecretHash(bytes(32))
EMPTY_SECRET = Secret(bytes(32))
EMPTY_SECRET_SHA256 = SecretHash(sha256(EMPTY_SECRET).digest())
LOCKSROOT_OF_NO_LOCKS = Locksroot(keccak(b""))
ZERO_TOKENS = TokenAmount(0)

ABSENT_SECRET = Secret(b"")

SECRET_LENGTH = 32
SECRETHASH_LENGTH = 32

RECEIPT_FAILURE_CODE = 0


class EthClient(Enum):
    GETH = "geth"
    PARITY = "parity"


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

    PRODUCTION = "production"
    DEVELOPMENT = "development"


class RoutingMode(Enum):
    """Routing mode configuration that can be chosen on the command line"""

    PFS = "pfs"
    LOCAL = "local"
    PRIVATE = "private"


GAS_REQUIRED_PER_SECRET_IN_BATCH = math.ceil(UNLOCK_TX_GAS_LIMIT / MAXIMUM_PENDING_TRANSFERS)
GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL = 100_000

CHECK_RDN_MIN_DEPOSIT_INTERVAL = 5 * 60
CHECK_GAS_RESERVE_INTERVAL = 5 * 60
CHECK_VERSION_INTERVAL = 3 * 60 * 60
CHECK_NETWORK_ID_INTERVAL = 5 * 60

DEFAULT_HTTP_REQUEST_TIMEOUT = 1.0  # seconds

DISCOVERY_DEFAULT_ROOM = "discovery"
MONITORING_BROADCASTING_ROOM = "monitoring"
PATH_FINDING_BROADCASTING_ROOM = "path_finding"

# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
EMPTY_ADDRESS = b"\0" * 20


# Keep in sync with .circleci/config.yaml
HIGHEST_SUPPORTED_GETH_VERSION = "1.8.27"
LOWEST_SUPPORTED_GETH_VERSION = "1.7.2"
# this is the last stable version as of this comment
HIGHEST_SUPPORTED_PARITY_VERSION = "2.5.5"
LOWEST_SUPPORTED_PARITY_VERSION = "1.7.6"
