from eth_utils import (
    decode_hex,
    event_abi_to_log_topic,
)
from web3 import Web3
from web3.utils.abi import filter_by_type
from web3.utils.events import get_event_data
from eth_utils import to_checksum_address
from web3.utils.filters import construct_event_filter_params, LogFilter
from pkg_resources import DistributionNotFound

from raiden_contracts.contract_manager import CONTRACT_MANAGER
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, EVENT_CHANNEL_OPENED

from raiden.utils.typing import Address, ChannelID, BlockSpecification, List, Dict

try:
    from eth_tester.exceptions import BlockNotFound
except (ModuleNotFoundError, DistributionNotFound):
    class BlockNotFound(Exception):
        pass


def get_filter_args_for_specific_event_from_channel(
        token_network_address: Address,
        channel_identifier: ChannelID,
        event_name: str,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
):
    """ Return the filter params for a specific event of a given channel. """
    if not event_name:
        raise ValueError('Event name must be given')

    event_abi = CONTRACT_MANAGER.get_event_abi(CONTRACT_TOKEN_NETWORK, event_name)

    # Here the topics for a specific event are created
    # The first entry of the topics list is the event name, then the first parameter is encoded,
    # in the case of a token network, the first parameter is always the channel identifier
    _, event_filter_params = construct_event_filter_params(
        event_abi=event_abi,
        contract_address=to_checksum_address(token_network_address),
        argument_filters={
            'channel_identifier': channel_identifier,
        },
        fromBlock=from_block,
        toBlock=to_block,
    )

    return event_filter_params


def get_filter_args_for_all_events_from_channel(
        token_network_address: Address,
        channel_identifier: ChannelID,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> Dict:
    """ Return the filter params for all events of a given channel. """

    event_filter_params = get_filter_args_for_specific_event_from_channel(
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        event_name=EVENT_CHANNEL_OPENED,
        from_block=from_block,
        to_block=to_block,
    )

    # As we want to get all events for a certain channel we remove the event specific code here
    # and filter just for the channel identifier
    # We also have to remove the trailing topics to get all filters
    event_filter_params['topics'] = [None, event_filter_params['topics'][1]]

    return event_filter_params


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


class StatelessFilter(LogFilter):
    _last_block: int = -1

    def __init__(self, web3: Web3, filter_params: dict):
        super().__init__(web3, filter_id=None)
        self.filter_params = filter_params

    def get_new_entries(self):
        try:
            logs = self.web3.eth.getLogs(dict(
                self.filter_params,
                fromBlock=max(
                    self.filter_params.get('fromBlock', 0),
                    self._last_block + 1,
                ),
            ))
            self._update_last_block(logs)
            return logs
        except BlockNotFound:
            return []

    def get_all_entries(self):
        try:
            logs = self.web3.eth.getLogs(self.filter_params)
            self._update_last_block(logs)
            return logs
        except BlockNotFound:
            return []

    def _update_last_block(self, logs: List[Dict]=None):
        if not logs or self.filter_params.get('toBlock') in ('latest', 'pending'):
            block_number = self.web3.eth.blockNumber
        else:
            block_number = max(event.get('blockNumber', 0) for event in logs)
        if block_number and block_number > self._last_block:
            self._last_block = block_number
