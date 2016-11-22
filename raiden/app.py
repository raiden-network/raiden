# -*- coding: utf-8 -*-
from ethereum.utils import decode_hex

from raiden.raiden_service import RaidenService, DEFAULT_REVEAL_TIMEOUT, DEFAULT_SETTLE_TIMEOUT
from raiden.network.transport import UDPTransport, TokenBucket
from raiden.utils import pex

INITIAL_PORT = 40001
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5


class App(object):  # pylint: disable=too-few-public-methods
    default_config = dict(
        host='',
        port=INITIAL_PORT,
        privatekey_hex='',
        # number of blocks that a node requires to learn the secret before the lock expires
        reveal_timeout=DEFAULT_REVEAL_TIMEOUT,
        settle_timeout=DEFAULT_SETTLE_TIMEOUT,
        # how long to wait for a transfer until TimeoutTransfer is sent (time in milliseconds)
        msg_timeout=100.00,
        # throttle policy for token bucket
        throttle_capacity=10.,
        throttle_fill_rate=10.,
    )

    def __init__(self, config, chain, discovery, transport_class=UDPTransport):
        self.config = config
        self.discovery = discovery
        self.transport = transport_class(config['host'], config['port'])
        self.transport.throttle_policy = TokenBucket(
            config['throttle_capacity'],
            config['throttle_fill_rate']
        )
        self.raiden = RaidenService(
            chain,
            decode_hex(config['privatekey_hex']),
            self.transport,
            discovery,
            config,
        )
        self.services = {'raiden': self.raiden}
        self.start_console = True

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def stop(self):
        self.transport.stop()
        self.raiden.stop()
