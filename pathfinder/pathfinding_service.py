import logging
import sys
import traceback
from typing import Dict, List, Optional

import gevent
from eth_utils import is_checksum_address
from matrix_client.errors import MatrixRequestError
from web3 import Web3

from pathfinder.model import TokenNetwork
from pathfinder.utils.blockchain_listener import (
    BlockchainListener,
    create_channel_event_topics,
    create_registry_event_topics,
)
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    ChannelEvent,
)
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.gevent_error_handler import register_error_handler
from raiden_libs.types import Address

log = logging.getLogger(__name__)


def error_handler(context, exc_info):
    if exc_info[0] == MatrixRequestError:
        log.error(
            'Can not connect to the matrix system. Please check your settings. '
            'Detailed error message: %s', exc_info[1],
        )
        sys.exit()
    else:
        log.fatal(
            'Unhandled exception. Terminating the program...'
            'Please report this issue at '
            'https://github.com/raiden-network/raiden-pathfinding-service/issues',
        )
        traceback.print_exception(
            etype=exc_info[0],
            value=exc_info[1],
            tb=exc_info[2],
        )
        sys.exit()


class PathfindingService(gevent.Greenlet):
    def __init__(
        self,
        web3: Web3,
        contract_manager: ContractManager,
        registry_address: Address,
        sync_start_block: int = 0,
        required_confirmations: int = 8,
    ) -> None:
        """ Creates a new pathfinding service

        Args:
            contract_manager: A contract manager
            token_network_listener: A blockchain listener object
            token_network_registry_listener: A blockchain listener object for the network registry
            chain_id: The id of the chain the PFS runs on
        """
        super().__init__()
        self.web3 = web3
        self.contract_manager = contract_manager
        self.registry_address = registry_address
        self.sync_start_block = sync_start_block
        self.required_confirmations = required_confirmations
        self.chain_id = int(web3.net.version)

        self.is_running = gevent.event.Event()
        self.token_networks: Dict[Address, TokenNetwork] = {}
        self.token_network_listeners: List[BlockchainListener] = []

        self.is_running = gevent.event.Event()

        log.info('Starting TokenNetworkRegistry Listener (required confirmations: {})...'.format(
            self.required_confirmations,
        ))
        self.token_network_registry_listener = BlockchainListener(
            web3=web3,
            contract_manager=self.contract_manager,
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
            contract_address=self.registry_address,
            sync_start_block=self.sync_start_block,
            required_confirmations=self.required_confirmations,
        )
        log.info(
            f'Listening to token network registry @ {registry_address} '
            f'from block {sync_start_block}',
        )
        self._setup_token_networks()

    def _setup_token_networks(self):
        self.token_network_registry_listener.add_confirmed_listener(
            create_registry_event_topics(self.contract_manager),
            self.handle_token_network_created,
        )

    def _run(self):
        register_error_handler(error_handler)

        self.token_network_registry_listener.start()

        self.is_running.wait()

    def stop(self):
        self.is_running.set()

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

    def _check_chain_id(self, received_chain_id: int):
        if not received_chain_id == self.chain_id:
            raise ValueError('Chain id does not match')

    def handle_channel_event(self, event: Dict):
        event_name = event['event']

        if event_name == ChannelEvent.OPENED:
            self.handle_channel_opened(event)
        elif event_name == ChannelEvent.DEPOSIT:
            self.handle_channel_new_deposit(event)
        elif event_name == ChannelEvent.CLOSED:
            self.handle_channel_closed(event)
        else:
            log.info('Unhandled event: %s', event_name)

    def handle_channel_opened(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network is None:
            return

        log.debug('Received ChannelOpened event for token network {}'.format(
            token_network.address,
        ))

        channel_identifier = event['args']['channel_identifier']
        participant1 = event['args']['participant1']
        participant2 = event['args']['participant2']

        token_network.handle_channel_opened_event(
            channel_identifier,
            participant1,
            participant2,
        )

    def handle_channel_new_deposit(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network is None:
            return

        log.debug('Received ChannelNewDeposit event for token network {}'.format(
            token_network.address,
        ))

        channel_identifier = event['args']['channel_identifier']
        participant_address = event['args']['participant']
        total_deposit = event['args']['total_deposit']

        token_network.handle_channel_new_deposit_event(
            channel_identifier,
            participant_address,
            total_deposit,
        )

    def handle_channel_closed(self, event: Dict):
        token_network = self._get_token_network(event['address'])

        if token_network is None:
            return

        log.debug('Received ChannelClosed event for token network {}'.format(
            token_network.address,
        ))

        channel_identifier = event['args']['channel_identifier']

        token_network.handle_channel_closed_event(channel_identifier)

    def handle_token_network_created(self, event):
        token_network_address = event['args']['token_network_address']
        token_address = event['args']['token_address']
        event_block_number = event['blockNumber']

        assert is_checksum_address(token_network_address)
        assert is_checksum_address(token_address)

        if not self.follows_token_network(token_network_address):
            log.info(f'Found token network for token {token_address} @ {token_network_address}')
            self.create_token_network_for_address(
                token_network_address,
                token_address,
                event_block_number,
            )

    def create_token_network_for_address(
        self,
        token_network_address: Address,
        token_address: Address,
        block_number: int = 0,
    ):
        token_network = TokenNetwork(token_network_address, token_address)
        self.token_networks[token_network_address] = token_network

        log.info('Creating token network for %s', token_network_address)
        token_network_listener = BlockchainListener(
            web3=self.web3,
            contract_manager=self.contract_manager,
            contract_address=token_network_address,
            contract_name=CONTRACT_TOKEN_NETWORK,
            sync_start_block=block_number,
            required_confirmations=self.required_confirmations,
        )

        # subscribe to event notifications from blockchain listener
        token_network_listener.add_confirmed_listener(
            create_channel_event_topics(),
            self.handle_channel_event,
        )
        token_network_listener.start()
        self.token_network_listeners.append(token_network_listener)
