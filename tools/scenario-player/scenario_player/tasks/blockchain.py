from typing import Any, List, Dict

import structlog
from eth_utils import to_checksum_address, decode_hex, event_abi_to_log_topic
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK
from raiden_contracts.contract_manager import ContractManager

from scenario_player.runner import ScenarioRunner
from scenario_player.exceptions import ScenarioError, ScenarioAssertionError
from web3 import Web3
from web3.utils.abi import filter_by_type
from web3.utils.events import get_event_data

from raiden.utils.typing import BlockNumber, Address, ABI
from .base import Task

log = structlog.get_logger(__name__)


def decode_event(abi: ABI, log_: Dict) -> Dict:
    """ Helper function to unpack event data using a provided ABI

    Args:
        abi: The ABI of the contract, not the ABI of the event
        log_: The raw event data

    Returns:
        The decoded event
    """
    if isinstance(log_['topics'][0], str):
        log_['topics'][0] = decode_hex(log_['topics'][0])
    elif isinstance(log_['topics'][0], int):
        log_['topics'][0] = decode_hex(hex(log_['topics'][0]))
    event_id = log_['topics'][0]
    events = filter_by_type('event', abi)
    topic_to_event_abi = {
        event_abi_to_log_topic(event_abi): event_abi
        for event_abi in events
    }
    event_abi = topic_to_event_abi[event_id]
    return get_event_data(event_abi, log_)


def query_blockchain_events(
    web3: Web3,
    contract_manager: ContractManager,
    contract_address: Address,
    contract_name: str,
    topics: List,
    from_block: BlockNumber,
    to_block: BlockNumber,
) -> List[Dict]:
    """Returns events emmitted by a contract for a given event name, within a certain range.

    Args:
        web3: A Web3 instance
        contract_manager: A contract manager
        contract_address: The address of the contract to be filtered, can be `None`
        contract_name: The name of the contract
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

    events = web3.eth.getLogs(filter_params)

    return [
        decode_event(
            contract_manager.get_contract_abi(contract_name),
            raw_event,
        )
        for raw_event in events
    ]


class BlockchainEventFilter(Task):
    _name = 'assert_events'

    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail: bool = True,
    ) -> None:
        super().__init__(runner, config, parent, abort_on_fail)

        required_keys = ['contract_name', 'event_name', 'num_events']
        all_required_options_provided = all(
            key in config.keys() for key in required_keys
        )
        if not all_required_options_provided:
            raise ScenarioError(
                'Not all required keys provided. Required: ' + ', '.join(required_keys),
            )

        self.contract_name = config.get('contract_name', None)
        self.event_name = config.get('event_name', None)
        self.num_events = config.get('num_events', 0)

        self.web3 = self._runner.client.web3

    def _run(self, *args, **kwargs):
        events = query_blockchain_events(
            web3=self.web3,
            contract_manager=self._runner.contract_manager,
            contract_address=self._runner.token_network_address,
            contract_name=CONTRACT_TOKEN_NETWORK,
            topics=[],
            from_block=BlockNumber(self._runner.token_deployment_block),
            to_block=BlockNumber(self.web3.eth.blockNumber),
        )

        # Filter matching events
        events = [e for e in events if e['event'] == self.event_name]

        # Raise exception when events do not match
        if not self.num_events == len(events):
            raise ScenarioAssertionError(
                f'Expected number of events ({self.num_events}) did not match the number '
                f'of events found ({len(events)})',
            )
