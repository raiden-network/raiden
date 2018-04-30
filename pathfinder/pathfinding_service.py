# -*- coding: utf-8 -*-
import logging
import sys
import traceback
from typing import Dict, Optional, List

import gevent
from eth_utils import is_checksum_address, to_checksum_address
from raiden_libs.blockchain import BlockchainListener
from raiden_libs.messages import Message, FeeInfo, BalanceProof
from raiden_libs.gevent_error_handler import register_error_handler
from raiden_libs.transport import MatrixTransport
from raiden_libs.types import Address
from raiden_contracts.contract_manager import ContractManager
from matrix_client.errors import MatrixRequestError

from pathfinder.model import TokenNetwork

log = logging.getLogger(__name__)


def error_handler(context, exc_info):
    if exc_info[0] == MatrixRequestError:
        log.error(
            'Can not connect to the matrix system. Please check your settings. '
            'Detailed error message: %s', exc_info[1]
        )
        sys.exit()
    else:
        log.fatal(
            'Unhandled exception. Terminating the program...'
            'Please report this issue at '
            'https://github.com/raiden-network/raiden-pathfinding-service/issues'
        )
        traceback.print_exception(
            etype=exc_info[0],
            value=exc_info[1],
            tb=exc_info[2]
        )
        sys.exit()


class PathfindingService(gevent.Greenlet):
    def __init__(
        self,
        contract_manager: ContractManager,
        transport: MatrixTransport,
        token_network_listener: BlockchainListener,
        *,
        follow_networks: List[Address] = None,
        token_network_registry_listener: BlockchainListener = None,
    ) -> None:
        """ Creates a new pathfinding service

        Args:
            contract_manager: A contract manager
            transport: A transport object
            token_network_listener: A blockchain listener object
            follow_networks: A list of token network addresses to follow. This has precedence over
                the `token_network_registry_listener`
            token_network_registry_listener: A blockchain listener object for the network registry
        """
        super().__init__()
        self.contract_manager = contract_manager
        self.transport = transport
        self.token_network_listener = token_network_listener

        self.token_network_registry_listener = token_network_registry_listener
        self.follow_networks = follow_networks

        self.is_running = gevent.event.Event()
        self.transport.add_message_callback(lambda message: self.on_message_event(message))
        self.token_networks: Dict[Address, TokenNetwork] = {}

        assert (
            self.follow_networks is not None or self.token_network_registry_listener is not None
        )
        self._setup_token_networks()

        # subscribe to event notifications from blockchain listener
        self.token_network_listener.add_confirmed_listener(
            'ChannelOpened',
            self.handle_channel_opened
        )
        self.token_network_listener.add_confirmed_listener(
            'ChannelNewDeposit',
            self.handle_channel_new_deposit
        )
        self.token_network_listener.add_confirmed_listener(
            'ChannelClosed',
            self.handle_channel_closed
        )

    def _setup_token_networks(self):
        if self.follow_networks:
            for network_address in self.follow_networks:
                self.create_token_network_for_address(network_address)
        else:
            self.token_network_registry_listener.add_confirmed_listener(
                'TokenNetworkCreated',
                self.handle_token_network_created
            )

    def _run(self):
        register_error_handler(error_handler)
        self.transport.start()
        self.token_network_listener.start()
        if self.token_network_registry_listener:
            self.token_network_registry_listener.start()

        self.is_running.wait()

    def stop(self):
        self.is_running.set()

    def on_message_event(self, message: Message):
        """This handles messages received over the Transport"""
        assert isinstance(message, Message)
        if isinstance(message, FeeInfo):
            self.on_fee_info_message(message)
        elif isinstance(message, BalanceProof):
            self.on_balance_proof_message(message)
        else:
            log.error("Ignoring unknown message of type '%s'", (type(message)))

    def follows_token_network(self, token_network_address: Address) -> bool:
        """ Checks if a token network is followed by the pathfinding service. """
        assert is_checksum_address(token_network_address)

        return token_network_address in self.token_networks.keys()

    def _get_token_network(self, token_network_address: Address) -> Optional[TokenNetwork]:
        """ Returns the `TokenNetwork` for the given address or `None` for unknown networks. """

        assert is_checksum_address(token_network_address)

        if not self.follows_token_network(token_network_address):
            return None
        else:
            return self.token_networks[token_network_address]

    def handle_channel_opened(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network:
            log.debug('Received ChannelOpened event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']
            participant1 = event['args']['participant1']
            participant2 = event['args']['participant2']

            token_network.handle_channel_opened_event(
                channel_identifier,
                participant1,
                participant2
            )

    def handle_channel_new_deposit(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network:
            log.debug('Received ChannelNewDeposit event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']
            participant_address = event['args']['participant']
            total_deposit = event['args']['deposit']

            token_network.handle_channel_new_deposit_event(
                channel_identifier,
                participant_address,
                total_deposit
            )

    def handle_channel_closed(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network:
            log.debug('Received ChannelClosed event for token network {}'.format(
                token_network.address
            ))

            channel_identifier = event['args']['channel_identifier']

            token_network.handle_channel_closed_event(channel_identifier)

    def on_fee_info_message(self, fee_info: FeeInfo):
        token_network = self._get_token_network(fee_info.token_network_address)

        if token_network:
            log.debug('Received FeeInfo message for token network {}'.format(
                token_network.address
            ))
            # TODO: check chain id

            token_network.update_fee(
                fee_info.channel_identifier,
                Address(to_checksum_address(fee_info.signer)),
                fee_info.nonce,
                fee_info.percentage_fee
            )

    def on_balance_proof_message(self, balance_proof: BalanceProof):
        token_network = self._get_token_network(balance_proof.token_network_address)

        if token_network:
            log.debug('Received BalanceProof message for token network {}'.format(
                token_network.address
            ))
            # TODO: check chain id

            token_network.update_balance(
                balance_proof.channel_identifier,
                Address(to_checksum_address(balance_proof.signer)),
                balance_proof.nonce,
                balance_proof.transferred_amount,
                balance_proof.locked_amount,
            )

    def handle_token_network_created(self, event):
        token_network_address = event['args']['token_network_address']
        assert is_checksum_address(token_network_address)

        if not self.follows_token_network(token_network_address):
            log.info(f'Found new token network at {token_network_address}')
            self.create_token_network_for_address(token_network_address)

    def create_token_network_for_address(self, token_network_address: Address):
        log.info(f'Following token network at {token_network_address}')

        token_network = TokenNetwork(token_network_address)
        self.token_networks[token_network_address] = token_network
