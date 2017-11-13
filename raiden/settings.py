# -*- coding: utf-8 -*-
from ethereum.utils import denoms, int_to_big_endian

INITIAL_PORT = 40001

CACHE_TTL = 60
ESTIMATED_BLOCK_TIME = 7
GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')
GAS_PRICE = denoms.shannon * 20
GAS_PRICE_ROPSTEN = denoms.shannon * 200

DEFAULT_PROTOCOL_RETRIES_BEFORE_BACKOFF = 5
DEFAULT_PROTOCOL_THROTTLE_CAPACITY = 10.
DEFAULT_PROTOCOL_THROTTLE_FILL_RATE = 10.
DEFAULT_PROTOCOL_RETRY_INTERVAL = 1.

DEFAULT_REVEAL_TIMEOUT = 10
DEFAULT_SETTLE_TIMEOUT = DEFAULT_REVEAL_TIMEOUT * 9
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5
DEFAULT_POLL_TIMEOUT = 180
DEFAULT_JOINABLE_FUNDS_TARGET = 0.4
DEFAULT_INITIAL_CHANNEL_TARGET = 3
DEFAULT_WAIT_FOR_SETTLE = True

DEFAULT_NAT_KEEPALIVE_RETRIES = 2
DEFAULT_NAT_KEEPALIVE_TIMEOUT = 10
DEFAULT_NAT_INVITATION_TIMEOUT = 180

ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE = 3
ETHERSCAN_API = 'https://{network}.etherscan.io/api?module=proxy&action={action}'
