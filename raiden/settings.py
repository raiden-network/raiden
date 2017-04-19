# -*- coding: utf-8 -*-
from ethereum.utils import denoms, int_to_big_endian

INITIAL_PORT = 40001

DEFAULT_TRANSACTION_LOG_FILENAME = "transaction.log"

DEFAULT_REVEAL_TIMEOUT = 30
DEFAULT_SETTLE_TIMEOUT = DEFAULT_REVEAL_TIMEOUT * 20
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5
DEFAULT_POLL_TIMEOUT = 180
DEFAULT_HEALTHCHECK_POLL_TIMEOUT = 1
ESTIMATED_BLOCK_TIME = 7

GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')
GAS_PRICE = denoms.shannon * 20
