# -*- coding: utf-8 -*-

import os
import filelock
import sys
import structlog
import traceback
from binascii import unhexlify

from raiden_libs.gevent_error_handler import register_error_handler
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
from raiden.utils import (
    pex,
    privatekey_to_address,
    address_encoder)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def greenlet_error_handler(context, exc_info):
    log.fatal("Unhandled greenlet exception. Raiden is terminating ...")
    etype = exc_info[0]
    evalue = exc_info[1]
    etb = exc_info[2]
    traceback.print_exception(
        etype=etype,
        value=evalue,
        tb=etb,
    )
    if 'TRAVIS' in os.environ:
        if evalue.__traceback__ is not etb:
            raise evalue.with_traceback(etb)
        raise evalue
    else:
        sys.exit(1)


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
        'transport_type': 'udp',
        'matrix': {
            'server': 'auto',
            'available_servers': [
                'https://transport01.raiden.network',
                'https://transport02.raiden.network',
                'https://transport03.raiden.network',
            ],
            'discovery_room': {
                'alias_fragment': 'discovery',
                'server': 'transport01.raiden.network',
            }
        }
    }

    def __init__(self, config, chain, default_registry, transport, discovery=None):
        register_error_handler(greenlet_error_handler)
        self.config = config
        self.discovery = discovery

        try:
            self.raiden = RaidenService(
                chain,
                default_registry,
                unhexlify(config['privatekey_hex']),
                transport,
                config,
                discovery,
            )
        except filelock.Timeout:
            pubkey = address_encoder(
                privatekey_to_address(unhexlify(self.config['privatekey_hex']))
            )
            print(
                f'FATAL: Another Raiden instance already running for account {pubkey} on '
                f'network id {chain.network_id}'
            )
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
