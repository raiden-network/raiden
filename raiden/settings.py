# -*- coding: utf-8 -*-
from binascii import hexlify
from eth_utils import denoms, int_to_big_endian

INITIAL_PORT = 38647

RPC_CACHE_TTL = 600
CACHE_TTL = 60
ESTIMATED_BLOCK_TIME = 7
GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + hexlify(int_to_big_endian(GAS_LIMIT)).decode('utf-8')
GAS_PRICE = denoms.shannon * 20

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
DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK = 5

DEFAULT_NAT_KEEPALIVE_RETRIES = 5
DEFAULT_NAT_KEEPALIVE_TIMEOUT = 5
DEFAULT_NAT_INVITATION_TIMEOUT = 15

DEFAULT_SHUTDOWN_TIMEOUT = 2

ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE = 3
ETHERSCAN_API = 'https://{network}.etherscan.io/api?module=proxy&action={action}'
