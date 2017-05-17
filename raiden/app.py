# -*- coding: utf-8 -*-
from ethereum.utils import decode_hex

from raiden.raiden_service import RaidenService
from raiden.settings import (
    INITIAL_PORT,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
)
from raiden.network.transport import UDPTransport, TokenBucket
from raiden.utils import pex


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
        rpc=True,
        console=False,
    )

    def __init__(self, config, chain, discovery, transport_class=UDPTransport):
        self.config = config
        self.discovery = discovery
        if config.get('socket'):
            self.transport = transport_class(None, None, socket=config['socket'])
        else:
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

        self.start_console = self.config['console']

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def stop(self):
        self.raiden.stop()

        # The transport must be stopped after the protocol. The protocol can be
        # running multiple threads of execution and it expects the protocol to
        # be available.
        self.transport.stop()
