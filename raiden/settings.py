from dataclasses import dataclass, field

from eth_utils import denoms, to_hex

import raiden_contracts.constants
from raiden.constants import Environment
from raiden.utils.typing import (
    Dict,
    FeeAmount,
    NetworkTimeout,
    ProportionalFeeAmount,
    TokenAmount,
    TokenNetworkAddress,
)

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
DEFAULT_PATHFINDING_MAX_FEE = TokenAmount(5 * 10 ** 16)  # about .01$
DEFAULT_PATHFINDING_IOU_TIMEOUT = 2 * 10 ** 5  # now the pfs has 200 000blocks (40days) to cash in

DEFAULT_MEDIATION_FLAT_FEE = FeeAmount(0)
DEFAULT_MEDIATION_PROPORTIONAL_FEE = ProportionalFeeAmount(0)
DEFAULT_MEDIATION_PROPORTIONAL_IMBALANCE_FEE = ProportionalFeeAmount(0)

ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE = 3
ETHERSCAN_API = "https://{network}.etherscan.io/api?module=proxy&action={action}"

PRODUCTION_CONTRACT_VERSION = raiden_contracts.constants.CONTRACTS_VERSION
DEVELOPMENT_CONTRACT_VERSION = raiden_contracts.constants.CONTRACTS_VERSION

MIN_REI_THRESHOLD = 100

MONITORING_REWARD = TokenAmount(5 * 10 ** 18)  # about 1$
MONITORING_MIN_CAPACITY = TokenAmount(100)

MEDIATION_FEE = FeeAmount(0)


@dataclass
class MediationFeeConfig:
    token_network_to_flat_fee: Dict[TokenNetworkAddress, FeeAmount] = field(default_factory=dict)
    proportional_fee: ProportionalFeeAmount = DEFAULT_MEDIATION_PROPORTIONAL_FEE
    proportional_imbalance_fee: ProportionalFeeAmount = (
        DEFAULT_MEDIATION_PROPORTIONAL_IMBALANCE_FEE
    )

    def get_flat_fee(self, token_network_address: TokenNetworkAddress) -> FeeAmount:
        return self.token_network_to_flat_fee.get(  # pylint: disable=no-member
            token_network_address, DEFAULT_MEDIATION_FLAT_FEE
        )
