from enum import Enum

from eth_utils import keccak, to_canonical_address

from raiden.utils.formatting import to_checksum_address, to_hex_address
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    Literal,
    Locksroot,
    Mapping,
    RaidenDBVersion,
    RaidenProtocolVersion,
    Secret,
    SecretHash,
    Signature,
    TokenAddress,
    TokenAmount,
)

LATEST = "https://api.github.com/repos/raiden-network/raiden/releases/latest"
RELEASE_PAGE = "https://github.com/raiden-network/raiden/releases"
DOC_URL = "https://raiden-network.readthedocs.io/en/latest/rest_api.html"
SECURITY_EXPRESSION = r"\[CRITICAL UPDATE.*?\]"

RAIDEN_DB_VERSION = RaidenDBVersion(27)
SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)
PROTOCOL_VERSION = RaidenProtocolVersion(1)

UINT256_MAX = 2 ** 256 - 1
UINT64_MAX = 2 ** 64 - 1

SECONDS_PER_DAY = 24 * 60 * 60

RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = TokenAmount(int(0.075 * 10 ** 18))
RED_EYES_PER_TOKEN_NETWORK_LIMIT = TokenAmount(int(250 * 10 ** 18))

GENESIS_BLOCK_NUMBER = BlockNumber(0)

# Relevant forks:
# BYZANTIUM https://eips.ethereum.org/EIPS/eip-609
# CONSTANTINOPLE https://eips.ethereum.org/EIPS/eip-1013


class EthereumForks(Enum):
    CONSTANTINOPLE = BlockNumber(7_280_000)


class RopstenForks(Enum):
    CONSTANTINOPLE = BlockNumber(4_230_000)


class KovanForks(Enum):
    CONSTANTINOPLE = BlockNumber(4_230_000)


class RinkebyForks(Enum):
    CONSTANTINOPLE = BlockNumber(3_660_663)


class GoerliForks(Enum):
    CONSTANTINOPLE = BlockNumber(0)


class Networks(Enum):
    MAINNET = ChainID(1)
    ROPSTEN = ChainID(3)
    RINKEBY = ChainID(4)
    GOERLI = ChainID(5)
    KOVAN = ChainID(42)
    SMOKETEST = ChainID(627)


class Capabilities(Enum):
    """Capabilities allow for protocol handshake between nodes."""

    RECEIVE = "Receive"  # handle receiving transfers
    MEDIATE = "Mediate"  # support for mediating transfers; mediating requires receiving
    DELIVERY = "Delivery"  # expects and sends Delivery messages
    WEBRTC = "webRTC"  # supports webRTC messaging
    TODEVICE = "toDevice"  # supports sending and receiving toDevice messages on Matrix
    IMMUTABLE_METADATA = "immutableMetadata"  # leave metadata unchanged, if 0 also prune route


class DeviceIDs(Enum):
    ALL_DEVICES = "*"
    RAIDEN = "RAIDEN"
    PFS = "PATH_FINDING"
    MS = "MONITORING"


class ServerListType(Enum):
    ACTIVE_SERVERS = "active_servers"
    ALL_SERVERS = "all_servers"


class NotificationIDs(Enum):
    LOW_RDN = "low_rdn"
    VERSION_OUTDATED = "version_outdated"
    MISSING_GAS_RESERVE = "missing_gas_reserve"
    VERSION_SECURITY_WARNING = "version_security_warning"


# Set at 64 since parity's default is 64 and Geth's default is 128
# TODO: Make this configurable. Since in parity this is also a configurable value
STATE_PRUNING_AFTER_BLOCKS = 64
STATE_PRUNING_SAFETY_MARGIN = 8
NO_STATE_QUERY_AFTER_BLOCKS = STATE_PRUNING_AFTER_BLOCKS - STATE_PRUNING_SAFETY_MARGIN

NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS_HEX = to_hex_address(Address(NULL_ADDRESS_BYTES))
NULL_ADDRESS_CHECKSUM = to_checksum_address(Address(NULL_ADDRESS_BYTES))

EMPTY_HASH = BlockHash(bytes(32))
EMPTY_BALANCE_HASH = BalanceHash(bytes(32))
EMPTY_MESSAGE_HASH = AdditionalHash(bytes(32))
EMPTY_SIGNATURE = Signature(bytes(65))
EMPTY_SECRET = Secret(bytes(32))
EMPTY_SECRETHASH = SecretHash(bytes(32))
EMPTY_SECRET_SHA256 = sha256_secrethash(EMPTY_SECRET)
LOCKSROOT_OF_NO_LOCKS = Locksroot(keccak(b""))
EMPTY_LOCKSROOT = Locksroot(bytes(32))
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
TRANSACTION_INTRINSIC_GAS = 21_000

# Used to add a 30% security margin to gas estimations in case the calculations are off
GAS_FACTOR = 1.3

# The more pending transfers there are, the more computationally complex
# it becomes to unlock them. Lest an unlocking operation fails because
# not enough gas is available, we define a gas limit for unlock calls
# and limit the number of pending transfers per channel so it is not
# exceeded. The limit is inclusive.
UNLOCK_TX_GAS_LIMIT = TRANSACTION_GAS_LIMIT_UPPER_BOUND
MAXIMUM_PENDING_TRANSFERS = 160

CHAIN_TO_MIN_REVEAL_TIMEOUT: Mapping[ChainID, BlockTimeout] = {
    Networks.MAINNET.value: BlockTimeout(20),
    Networks.ROPSTEN.value: BlockTimeout(20),
    Networks.GOERLI.value: BlockTimeout(20),
    Networks.RINKEBY.value: BlockTimeout(20),
    Networks.KOVAN.value: BlockTimeout(20),
    Networks.SMOKETEST.value: BlockTimeout(20),
}


class Environment(Enum):
    """Environment configurations that can be chosen on the command line."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"


class RoutingMode(Enum):
    """Routing mode configuration that can be chosen on the command line"""

    PFS = "pfs"
    PRIVATE = "private"


# See gas measurements in raiden contracts for these values, rounded up
GAS_REQUIRED_REGISTER_SECRET_BATCH_BASE = 23000
GAS_REQUIRED_PER_SECRET_IN_BATCH = 26000

GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL = 100_000

CHECK_RDN_MIN_DEPOSIT_INTERVAL = 5 * 60
CHECK_GAS_RESERVE_INTERVAL = 5 * 60
CHECK_VERSION_INTERVAL = 3 * 60 * 60
CHECK_CHAIN_ID_INTERVAL = 5 * 60

DEFAULT_HTTP_REQUEST_TIMEOUT = 10.0  # seconds

MATRIX_AUTO_SELECT_SERVER = "auto"

# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
EMPTY_ADDRESS = b"\0" * 20

BLOCK_ID_LATEST: Literal["latest"] = "latest"
BLOCK_ID_PENDING: Literal["pending"] = "pending"

# Thresholds for the ``eth.getLogs`` call. Used to automatically adjust the block batch size.
ETH_GET_LOGS_TIMEOUT = 10
ETH_GET_LOGS_THRESHOLD_FAST = ETH_GET_LOGS_TIMEOUT // 4
ETH_GET_LOGS_THRESHOLD_SLOW = ETH_GET_LOGS_TIMEOUT // 2

# Keep in sync with .circleci/config.yaml
HIGHEST_SUPPORTED_GETH_VERSION = "1.10.3"
LOWEST_SUPPORTED_GETH_VERSION = "1.9.7"
# this is the last stable version as of this comment
HIGHEST_SUPPORTED_PARITY_VERSION = "3.1.0"
LOWEST_SUPPORTED_PARITY_VERSION = "2.7.0"

WEB3_BLOCK_NOT_FOUND_RETRY_COUNT = 3

WETH_TOKEN_ADDRESS = TokenAddress(
    to_canonical_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
)
DAI_TOKEN_ADDRESS = TokenAddress(
    to_canonical_address("0x6B175474E89094C44Da98b954EedeAC495271d0F")
)

FLAT_MED_FEE_MIN = 0
PROPORTIONAL_MED_FEE_MIN = 0
# This needs to limit the total slope of the fee function < 1
# This is also the per-hop fee, so the actual value per-channel is X / (2 + X)
PROPORTIONAL_MED_FEE_MAX = 1_000_000
IMBALANCE_MED_FEE_MIN = 0
IMBALANCE_MED_FEE_MAX = 50_000


class CommunicationMedium(Enum):
    WEB_RTC = "webRTC"
    TO_DEVICE = "toDevice"


class MatrixMessageType(Enum):
    TEXT = "m.text"
    NOTICE = "m.notice"


PFS_PATHS_REQUEST_TIMEOUT = 90
