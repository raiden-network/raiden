# -*- coding: utf-8 -*-

import filelock
import sys
from binascii import hexlify, unhexlify

from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NAT_INVITATION_TIMEOUT,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NAT_KEEPALIVE_TIMEOUT,
    DEFAULT_PROTOCOL_RETRIES_BEFORE_BACKOFF,
    DEFAULT_PROTOCOL_THROTTLE_CAPACITY,
    DEFAULT_PROTOCOL_THROTTLE_FILL_RATE,
    DEFAULT_PROTOCOL_RETRY_INTERVAL,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_SHUTDOWN_TIMEOUT,
    INITIAL_PORT,
)
from raiden.network.transport import UDPTransport, TokenBucket
from raiden.utils import (
    pex,
    privatekey_to_address
)


class App:  # pylint: disable=too-few-public-methods
    DEFAULT_CONFIG = {
        'host': '',
        'port': INITIAL_PORT,
        'external_ip': '',
        'external_port': INITIAL_PORT,
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
        'shutdown_timeout': DEFAULT_SHUTDOWN_TIMEOUT,
    }

    def __init__(self, config, chain, default_registry, discovery, transport_class=UDPTransport):
        self.config = config
        self.discovery = discovery

        if config.get('socket'):
            transport = transport_class(
                None,
                None,
                socket=config['socket'],
            )
        else:
            transport = transport_class(
                config['host'],
                config['port'],
            )

        transport.throttle_policy = TokenBucket(
            config['protocol']['throttle_capacity'],
            config['protocol']['throttle_fill_rate']
        )
        try:
            self.raiden = RaidenService(
                chain,
                default_registry,
                unhexlify(config['privatekey_hex']),
                transport,
                discovery,
                config,
            )
        except filelock.Timeout:
            pubkey = privatekey_to_address(unhexlify(self.config['privatekey_hex']))
            print('FATAL: Another Raiden instance already running for account 0x%s' %
                  hexlify(str(pubkey)))
            sys.exit(1)
        self.start_console = self.config['console']

        # raiden.ui.console:Console assumes that a services
        # attribute is available for auto-registration
        self.services = dict()

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def stop(self, leave_channels=False):
        """
        Stop the raiden app.

        Args:
            leave_channels (bool): if True, also close and settle all channels before stopping
        """
        if leave_channels:
            self.raiden.close_and_settle()

        self.raiden.stop()
