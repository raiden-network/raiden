from enum import Enum

from eth_utils import to_canonical_address

from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)


UINT64_MAX = 2 ** 64 - 1
UINT64_MIN = 0

INT64_MAX = 2 ** 63 - 1
INT64_MIN = -(2 ** 63)

UINT256_MAX = 2 ** 256 - 1


class EthClient(Enum):
    GETH = 1
    PARITY = 2
    TESTER = 3


# Deployed to Ropsten revival on 2018-08-09 from
# raiden-contracts@08b955499d5c8fb8f817eab55f0ab852275d334f
ROPSTEN_REGISTRY_ADDRESS = '0x445D79052522eC94078Dfccf96d9302775cA5b4E'
ROPSTEN_DISCOVERY_ADDRESS = '0x3F91c3Cd5c6E4fccB209fAFBD5FA9ba9eE6d220e'
ROPSTEN_SECRET_REGISTRY_ADDRESS = '0x3DE6B821E4fb4599653BF76FF60dC5FaF2e92De8'

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

MAINNET = 'mainnet'
ROPSTEN = 'ropsten'
RINKEBY = 'rinkeby'
KOVAN = 'kovan'
SMOKETEST = 'smoketest'

ID_TO_NETWORKNAME = {
    1: MAINNET,
    3: ROPSTEN,
    4: RINKEBY,
    42: KOVAN,
    627: SMOKETEST,
}

ID_TO_NETWORK_CONFIG = {
    3: {
        CONTRACT_ENDPOINT_REGISTRY: to_canonical_address(ROPSTEN_DISCOVERY_ADDRESS),
        CONTRACT_SECRET_REGISTRY: to_canonical_address(ROPSTEN_SECRET_REGISTRY_ADDRESS),
        CONTRACT_TOKEN_NETWORK_REGISTRY: to_canonical_address(ROPSTEN_REGISTRY_ADDRESS),
        START_QUERY_BLOCK_KEY: 3604000,  # 924 blocks before token network registry deployment
    },
}

NETWORKNAME_TO_ID = {
    name: id
    for id, name in ID_TO_NETWORKNAME.items()
}

MIN_REQUIRED_SOLC = 'v0.4.23'
NULL_ADDRESS = '0x' + '0' * 40
NULL_ADDRESS_BYTES = b'\x00' * 20

NULL_HASH_BYTES = b'\x00' * 32

TESTNET_GASPRICE_MULTIPLIER = 2.0

SNAPSHOT_BLOCK_COUNT = 5000

# calculated as of raiden-contracts@0dbe840c366841b414a11c78d8721046440b2a15
# https://github.com/raiden-network/raiden-contracts/tree/0dbe840c366841b414a11c78d8721046440b2a15
GAS_REQUIRED_FOR_OPEN_CHANNEL = 109921
GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT = 42605
GAS_REQUIRED_FOR_REGISTER_SECRET = 46152
GAS_REQUIRED_FOR_CLOSE_CHANNEL = 111483
GAS_REQUIRED_FOR_BALANCE_PROOF = 94379
GAS_REQUIRED_FOR_SETTLE_CHANNEL = 124991
GAS_REQUIRED_FOR_UNLOCK_1_LOCKS = 33550
GAS_REQUIRED_FOR_UNLOCK_6_LOCKS = 73123
