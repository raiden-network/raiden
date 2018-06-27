from typing import Dict

from eth_utils import to_checksum_address
from web3.utils.filters import construct_event_filter_params
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, EVENT_CHANNEL_OPENED

from raiden.utils.typing import Address, ChannelID, BlockSpecification


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
