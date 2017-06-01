# -*- coding: utf-8 -*-
from ethereum.utils import denoms, int_to_big_endian

INITIAL_PORT = 40001

CACHE_TTL = 60
ESTIMATED_BLOCK_TIME = 7
GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')
GAS_PRICE = denoms.shannon * 20

DEFAULT_PROTOCOL_RETRIES_BEFORE_BACKOFF = 5
DEFAULT_PROTOCOL_THROTTLE_CAPACITY = 10.
DEFAULT_PROTOCOL_THROTTLE_FILL_RATE = 10.
DEFAULT_PROTOCOL_RETRY_INTERVAL = 1.

DEFAULT_REVEAL_TIMEOUT = 30
DEFAULT_SETTLE_TIMEOUT = DEFAULT_REVEAL_TIMEOUT * 20
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5
DEFAULT_POLL_TIMEOUT = 180
DEFAULT_JOINABLE_FUNDS_TARGET = 0.4
DEFAULT_INITIAL_CHANNEL_TARGET = 3
DEFAULT_WAIT_FOR_SETTLE = True

DEFAULT_NAT_KEEPALIVE_RETRIES = 5
DEFAULT_NAT_KEEPALIVE_TIMEOUT = 30
DEFAULT_NAT_INVITATION_TIMEOUT = 180

RAIDEN_DEFAULT_CONFIG = {
    'host': '',
    'port': INITIAL_PORT,
    'privatekey_hex': '',
    'reveal_timeout': DEFAULT_REVEAL_TIMEOUT,
    'settle_timeout': DEFAULT_SETTLE_TIMEOUT,
    'database_path': '',
    'msg_timeout': 100.0,
    'protocol': {
        'retry_interval': DEFAULT_PROTOCOL_RETRY_INTERVAL,
        'retries_before_backoff': DEFAULT_PROTOCOL_RETRIES_BEFORE_BACKOFF,
        'throttle_capacity': DEFAULT_PROTOCOL_THROTTLE_CAPACITY,
        'throttle_fill_rate': DEFAULT_PROTOCOL_THROTTLE_FILL_RATE,
        'nat_invitation_timeout': DEFAULT_NAT_INVITATION_TIMEOUT,
        'nat_keepalive_retries': DEFAULT_NAT_KEEPALIVE_RETRIES,
        'nat_keepalive_timeout': DEFAULT_NAT_KEEPALIVE_TIMEOUT,
    },
    'rpc': True,
    'console': False,
}
