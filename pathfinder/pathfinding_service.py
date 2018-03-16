# -*- coding: utf-8 -*-
import logging
import sys
import traceback
from typing import Dict, Optional

import gevent
from eth_utils import is_checksum_address
from raiden_libs.blockchain import BlockchainListener

from pathfinder.gevent_error_handler import register_error_handler
from pathfinder.token_network import TokenNetwork
from pathfinder.transport import MatrixTransport
from pathfinder.utils.types import Address

log = logging.getLogger(__name__)


def error_handler(context, exc_info):
    log.fatal("Unhandled exception terminating the program")
    traceback.print_exception(
        etype=exc_info[0],
        value=exc_info[1],
        tb=exc_info[2]
    )
    sys.exit()


class PathfindingService(gevent.Greenlet):
    def __init__(
        self,
        transport: MatrixTransport,
        blockchain_listener: BlockchainListener
    ) -> None:
        super().__init__()
        self.transport = transport
        self.blockchain_listener = blockchain_listener
        self.is_running = gevent.event.Event()
        self.transport.add_message_callback(lambda message: self.on_message_event(message))
        self.token_networks: Dict[Address, TokenNetwork] = {}

        # subscribe to event notifications from blockchain listener
        self.blockchain_listener.add_confirmed_listener(
            'ChannelOpened',
            self.handle_channel_opened
        )
        self.blockchain_listener.add_confirmed_listener(
            'ChannelNewDeposit',
            self.handle_channel_net_deposit
        )
        self.blockchain_listener.add_confirmed_listener(
            'ChannelClosed',
            self.handle_channel_closed
        )

    def _run(self):
        register_error_handler(error_handler)
        self.transport.start()
        self.blockchain_listener.run()

        self.is_running.wait()

    def stop(self):
        self.is_running.set()

    def on_message_event(self, message: str):
        """This handles messages received over the Transport"""
        # TODO: process messages
        print(message)

    def _get_token_network(self, event) -> Optional[TokenNetwork]:
        token_network_address = event['address']
        assert is_checksum_address(token_network_address)

        try:
            token_network = self.token_networks[token_network_address]
        except KeyError as e:
            log.info('Ignoring event from unknown token network {}'.format(
                token_network_address
            ))
            return None

        return token_network

    def handle_channel_opened(self, event):
        token_network = self._get_token_network(event)

        if token_network:
            log.debug('Received ChannelOpened event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']

            token_network.handle_channel_opened(channel_identifier)

    def handle_channel_net_deposit(self, event):
        token_network = self._get_token_network(event)

        if token_network:
            log.debug('Received ChannelNetDeposit event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']
            participant_address = event['args']['participant']
            total_deposit = event['args']['total_deposit']

            token_network.handle_channel_new_deposit_event(
                channel_identifier,
                participant_address,
                total_deposit
            )

    def handle_channel_closed(self, event):
        token_network = self._get_token_network(event)

        if token_network:
            log.debug('Received ChannelClosed event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']

            token_network.handle_channel_closed_event(channel_identifier)
