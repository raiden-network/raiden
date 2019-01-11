import logging
import sys
from typing import Callable, Dict, List, Tuple, Union

import gevent
import gevent.event
import requests
from eth_utils import decode_hex, encode_hex, to_checksum_address
from eth_utils.abi import event_abi_to_log_topic
from web3 import Web3
from web3.contract import get_event_data
from web3.utils.abi import filter_by_type

from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY, EVENT_TOKEN_NETWORK_CREATED
from raiden_contracts.contract_manager import ContractManager

log = logging.getLogger(__name__)


def create_channel_event_topics() -> List:
    return [
        None,  # event topic is any
    ]


def create_registry_event_topics(contract_manager: ContractManager) -> List:
    new_network_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK_REGISTRY,
        EVENT_TOKEN_NETWORK_CREATED,
    )
    return [encode_hex(event_abi_to_log_topic(new_network_abi))]


def decode_event(abi: Dict, log: Dict):
    """ Helper function to unpack event data using a provided ABI

    Args:
        abi: The ABI of the contract, not the ABI of the event
        log: The raw event data

    Returns:
        The decoded event
    """
    if isinstance(log['topics'][0], str):
        log['topics'][0] = decode_hex(log['topics'][0])
    elif isinstance(log['topics'][0], int):
        log['topics'][0] = decode_hex(hex(log['topics'][0]))
    event_id = log['topics'][0]
    events = filter_by_type('event', abi)
    topic_to_event_abi = {
        event_abi_to_log_topic(event_abi): event_abi
        for event_abi in events
    }
    event_abi = topic_to_event_abi[event_id]
    return get_event_data(event_abi, log)


def get_events(
        web3: Web3,
        contract_address: str,
        topics: List,
        from_block: Union[int, str] = 0,
        to_block: Union[int, str] = 'latest',
) -> List:
    """Returns events emmitted by a contract for a given event name, within a certain range.

    Args:
        web3: A Web3 instance
        contract_manager: A contract manager
        contract_name: The name of the contract
        contract_address: The address of the contract to be filtered, can be `None`
        topics: The topics to filter for
        from_block: The block to start search events
        to_block: The block to stop searching for events

    Returns:
        All matching events
    """
    filter_params = {
        'fromBlock': from_block,
        'toBlock': to_block,
        'address': to_checksum_address(contract_address),
        'topics': topics,
    }

    return web3.eth.getLogs(filter_params)


class BlockchainListener(gevent.Greenlet):
    """ A class listening for events on a given contract. """

    def __init__(
            self,
            web3: Web3,
            contract_manager: ContractManager,
            contract_name: str,
            contract_address: str,
            *,  # require all following arguments to be keyword arguments
            required_confirmations: int = 4,
            sync_chunk_size: int = 100_000,
            poll_interval: int = 15,
            sync_start_block: int = 0,
    ) -> None:
        """Creates a new BlockchainListener

        Args:
            web3: A Web3 instance
            contract_manager: A contract manager
            contract_name: The name of the contract
            required_confirmations: The number of confirmations required to call a block confirmed
            sync_chunk_size: The size of the chunks used during syncing
            poll_interval: The interval used between polls
            sync_start_block: The block number syncing is started at
        """
        super().__init__()

        self.contract_manager = contract_manager
        self.contract_name = contract_name
        self.contract_address = contract_address

        self.required_confirmations = required_confirmations
        self.web3 = web3

        self.confirmed_callbacks: Dict[int, Tuple[List, Callable]] = {}
        self.unconfirmed_callbacks: Dict[int, Tuple[List, Callable]] = {}

        self.wait_sync_event = gevent.event.Event()
        self.is_connected = gevent.event.Event()
        self.sync_chunk_size = sync_chunk_size
        self.running = False
        self.poll_interval = poll_interval

        self.unconfirmed_head_number = sync_start_block
        self.confirmed_head_number = sync_start_block
        self.unconfirmed_head_hash = None
        self.confirmed_head_hash = None

        self.counter = 0

    def add_confirmed_listener(self, topics: List, callback: Callable):
        """ Add a callback to listen for confirmed events. """
        self.confirmed_callbacks[self.counter] = (topics, callback)
        self.counter += 1

    def add_unconfirmed_listener(self, topics: List, callback: Callable):
        """ Add a callback to listen for unconfirmed events. """
        self.unconfirmed_callbacks[self.counter] = (topics, callback)
        self.counter += 1

    def _run(self):
        self.running = True
        log.info('Starting blockchain polling (interval %ss)', self.poll_interval)
        while self.running:
            try:
                self._update()
                self.is_connected.set()
                if self.wait_sync_event.is_set():
                    gevent.sleep(self.poll_interval)
            except requests.exceptions.ConnectionError:
                endpoint = self.web3.currentProvider.endpoint_uri
                log.warning(
                    'Ethereum node (%s) refused connection. Retrying in %d seconds.' %
                    (endpoint, self.poll_interval),
                )
                gevent.sleep(self.poll_interval)
                self.is_connected.clear()
        log.info('Stopped blockchain polling')

    def stop(self):
        """ Stops the BlockchainListener. """
        self.running = False

    def wait_sync(self):
        """Blocks until event polling is up-to-date with a most recent block of the blockchain. """
        self.wait_sync_event.wait()

    def _update(self):
        current_block = self.web3.eth.blockNumber

        # reset unconfirmed channels in case of reorg
        self.reset_unconfirmed_on_reorg(current_block)

        new_unconfirmed_head_number = self.unconfirmed_head_number + self.sync_chunk_size
        new_unconfirmed_head_number = min(new_unconfirmed_head_number, current_block)
        new_confirmed_head_number = max(
            new_unconfirmed_head_number - self.required_confirmations,
            self.confirmed_head_number,
        )

        # return if blocks have already been processed
        if (self.confirmed_head_number >= new_confirmed_head_number and
                self.unconfirmed_head_number >= new_unconfirmed_head_number):
            return

        run_confirmed_filters = (
            self.confirmed_head_number < new_confirmed_head_number and
            len(self.confirmed_callbacks) > 0
        )
        if run_confirmed_filters:
            # create filters depending on current head number
            filters_confirmed = self.get_filter_params(
                self.confirmed_head_number,
                new_confirmed_head_number,
            )
            log.debug(
                'Filtering for confirmed events: %s-%s @%d ...',
                filters_confirmed['from_block'],
                filters_confirmed['to_block'],
                current_block,
            )
            # filter the events and run callbacks
            self.filter_events(filters_confirmed, self.confirmed_callbacks)
            log.debug('Finished.')

        run_unconfirmed_filters = (
            self.unconfirmed_head_number < new_unconfirmed_head_number and
            len(self.unconfirmed_callbacks) > 0
        )
        if run_unconfirmed_filters:
            # create filters depending on current head number
            filters_unconfirmed = self.get_filter_params(
                self.unconfirmed_head_number,
                new_unconfirmed_head_number,
            )
            log.debug(
                'Filtering for unconfirmed events: %s-%s @%d ...',
                filters_unconfirmed['from_block'],
                filters_unconfirmed['to_block'],
                current_block,
            )
            # filter the events and run callbacks
            self.filter_events(filters_unconfirmed, self.unconfirmed_callbacks)
            log.debug('Finished.')

        # update head hash and number
        try:
            new_unconfirmed_head_hash = self.web3.eth.getBlock(new_unconfirmed_head_number).hash
            new_confirmed_head_hash = self.web3.eth.getBlock(new_confirmed_head_number).hash
        except AttributeError:
            log.critical("RPC endpoint didn't return proper info for an existing block "
                         "(%d,%d)" % (new_unconfirmed_head_number, new_confirmed_head_number))
            log.critical("It is possible that the blockchain isn't fully synced. "
                         "This often happens when Parity is run with --fast or --warp sync.")
            log.critical("Cannot continue - check status of the ethereum node.")
            sys.exit(1)

        self.unconfirmed_head_number = new_unconfirmed_head_number
        self.unconfirmed_head_hash = new_unconfirmed_head_hash
        self.confirmed_head_number = new_confirmed_head_number
        self.confirmed_head_hash = new_confirmed_head_hash

        if not self.wait_sync_event.is_set() and new_unconfirmed_head_number == current_block:
            self.wait_sync_event.set()

    def filter_events(self, filter_params: Dict, name_to_callback: Dict):
        """ Filter events for given event names

        Params:
            filter_params: arguments for the filter call
            name_to_callback: dict that maps event name to callbacks executed
                if the event is emmited
        """
        for _, (topics, callback) in name_to_callback.items():
            events = get_events(
                web3=self.web3,
                contract_address=self.contract_address,
                topics=topics,
                **filter_params,
            )

            for raw_event in events:
                decoded_event = decode_event(
                    self.contract_manager.get_contract_abi(self.contract_name),
                    raw_event,
                )
                log.debug('Received confirmed event: \n%s', decoded_event)
                callback(decoded_event)

    def _detected_chain_reorg(self, current_block: int):
        log.debug(
            'Chain reorganization detected. '
            'Resyncing unconfirmed events (unconfirmed_head=%d) [@%d] '
            'delta=%d block(s)',
            self.unconfirmed_head_number,
            current_block,
            current_block - self.unconfirmed_head_number,
        )
        # here we should probably have a callback or a user-overriden method
        self.unconfirmed_head_number = self.confirmed_head_number
        self.unconfirmed_head_hash = self.confirmed_head_hash

    def reset_unconfirmed_on_reorg(self, current_block: int):
        """Test if chain reorganization happened (head number used in previous pass is greater than
        current_block parameter) and in that case reset unconfirmed event list."""
        if self.wait_sync_event.is_set():  # but not on first sync

            # block number increased or stayed the same
            if current_block >= self.unconfirmed_head_number:
                # if the hash of our head changed, there was a chain reorg
                current_unconfirmed_hash = self.web3.eth.getBlock(
                    self.unconfirmed_head_number,
                ).hash
                if current_unconfirmed_hash != self.unconfirmed_head_hash:
                    self._detected_chain_reorg(current_block)
            # block number decreased, there was a chain reorg
            elif current_block < self.unconfirmed_head_number:
                self._detected_chain_reorg(current_block)

            # now we have to check that the confirmed_head_hash stayed the same
            # otherwise the program aborts
            try:
                current_head_hash = self.web3.eth.getBlock(self.confirmed_head_number).hash
                if current_head_hash != self.confirmed_head_hash:
                    log.critical(
                        'Events considered confirmed have been reorganized. '
                        'Expected block hash %s for block number %d, but got block hash %s. '
                        "The BlockchainListener's number of required confirmations is %d.",
                        self.confirmed_head_hash,
                        self.confirmed_head_number,
                        current_head_hash,
                        self.required_confirmations,
                    )
                    sys.exit(1)  # unreachable as long as confirmation level is set high enough
            except AttributeError:
                log.critical(
                    'Events considered confirmed have been reorganized. '
                    'The block %d with hash %s does not exist any more.',
                    self.confirmed_head_number,
                    self.confirmed_head_hash,
                )
                sys.exit(1)  # unreachable as long as confirmation level is set high enough

    # filter for events after block_number
    # to_block is incremented because eth-tester doesn't include events from the end block
    # see https://github.com/raiden-network/raiden/pull/1321
    def get_filter_params(self, from_block: int, to_block: int) -> Dict[str, int]:
        assert from_block <= to_block
        return {
            'from_block': from_block + 1,
            'to_block': to_block + 1,
        }
