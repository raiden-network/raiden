import enum

DEFAULT_TOKEN_BALANCE_MIN = 2_000
DEFAULT_TOKEN_BALANCE_FUND = 10_000
OWN_ACCOUNT_BALANCE_MIN = 5 * 10 ** 17    # := 0.5 Eth
NODE_ACCOUNT_BALANCE_MIN = 15 * 10 ** 16   # := 0.15 Eth
NODE_ACCOUNT_BALANCE_FUND = 3 * 10 ** 17  # := 0.3 Eth
TIMEOUT = 200
API_URL_ADDRESS = "{protocol}://{target_host}/api/v1/address"
API_URL_TOKENS = "{protocol}://{target_host}/api/v1/tokens"
API_URL_TOKEN_NETWORK_ADDRESS = "{protocol}://{target_host}/api/v1/tokens/{token_address}"
SUPPORTED_SCENARIO_VERSIONS = {1, 2}


class NodeMode(enum.Enum):
    EXTERNAL = 1
    MANAGED = 2
