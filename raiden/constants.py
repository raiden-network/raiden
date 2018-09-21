from enum import Enum

from eth_utils import to_canonical_address, to_checksum_address

from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)

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


class NetworkType(Enum):
    MAIN = 1
    TEST = 2


# Deployed to Ropsten revival on 2018-09-03 from
# raiden-contracts@fc1c79329a165c738fc55c3505cf801cc79872e4
ROPSTEN_REGISTRY_ADDRESS = '0xf2a175A52Bd3c815eD7500c765bA19652AB89B30'
ROPSTEN_DISCOVERY_ADDRESS = '0xEEADDC1667B6EBc7784721B123a6F669B69Eb9bD'
ROPSTEN_SECRET_REGISTRY_ADDRESS = '0x16a25511A92C5ebfc6C30ad98F754e4c820c6822'
# Deployed to Ropsten revival on 2018-09-21 from
# raiden-contracts@bfb24fed3ebda2799e4d11ad1bb5a6de116bd12d
ROPSTEN_LIMITS_REGISTRY_ADDRESS = '0x6cC27CBF184B4177CD3c5D1a39a875aD07345eEb'
ROPSTEN_LIMITS_DISCOVERY_ADDRESS = '0xcF47EDF0D951c862ED9825F47075c15BEAf5Db1B'
ROPSTEN_LIMITS_SECRET_REGISTRY_ADDRESS = '0x8167a262Fa3Be92F05420675c3b409c64Be3d348'

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
        NetworkType.TEST: {
            'network_type': NetworkType.TEST,
            'contract_addresses': {
                CONTRACT_ENDPOINT_REGISTRY: to_canonical_address(ROPSTEN_DISCOVERY_ADDRESS),
                CONTRACT_SECRET_REGISTRY: to_canonical_address(ROPSTEN_SECRET_REGISTRY_ADDRESS),
                CONTRACT_TOKEN_NETWORK_REGISTRY: to_canonical_address(ROPSTEN_REGISTRY_ADDRESS),
            },
            # 924 blocks before token network registry deployment
            START_QUERY_BLOCK_KEY: 3604000,
        },
        NetworkType.MAIN: {
            'network_type': NetworkType.MAIN,
            'contract_addresses': {
                CONTRACT_ENDPOINT_REGISTRY: to_canonical_address(ROPSTEN_LIMITS_DISCOVERY_ADDRESS),
                CONTRACT_SECRET_REGISTRY: to_canonical_address(
                    ROPSTEN_LIMITS_SECRET_REGISTRY_ADDRESS,
                ),
                CONTRACT_TOKEN_NETWORK_REGISTRY: to_canonical_address(
                    ROPSTEN_LIMITS_REGISTRY_ADDRESS,
                ),
            },
            # 153 blocks before token network registry deployment
            START_QUERY_BLOCK_KEY: 4084000,
        },
    },
}

NETWORKNAME_TO_ID = {
    name: id
    for id, name in ID_TO_NETWORKNAME.items()
}

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
