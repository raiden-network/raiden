# -*- coding: utf-8 -*-

from ethereum import _solidity
from ethereum.abi import event_id, normalize_name
from raiden.utils import get_contract_path

__all__ = (
    'REGISTRY_ABI',
    'ASSETADDED_EVENT',
    'ASSETADDED_EVENTID',

    'CHANNEL_MANAGER_ABI',
    'CHANNELNEW_EVENT',
    'CHANNELNEW_EVENTID',

    'NETTING_CHANNEL_ABI',
    'CHANNELNEWBALANCE_EVENT',
    'CHANNELNEWBALANCE_EVENTID',
    'CHANNELCLOSED_EVENT',
    'CHANNELCLOSED_EVENTID',
    'CHANNELSECRETREVEALED_EVENT',
    'CHANNELSECRETREVEALED_EVENTID',
    'CHANNELSETTLED_EVENT',
    'CHANNELSETTLED_EVENTID',

    'HUMAN_TOKEN_ABI',
)


def get_event(full_abi, event_name):
    for description in full_abi:
        name = description.get('name')

        # skip constructors
        if name is None:
            continue

        normalized_name = normalize_name(name)

        if normalized_name == event_name:
            return description


def get_eventname_types(event_description):
    if 'name' not in event_description:
        raise ValueError('Not an event description, missing the name.')

    name = normalize_name(event_description['name'])
    encode_types = [
        element['type']
        for element in event_description['inputs']
    ]
    return name, encode_types


# pylint: disable=invalid-name
human_token_compiled = _solidity.compile_contract(
    get_contract_path('HumanStandardToken.sol'),
    'HumanStandardToken',
    combined='abi',
)

channel_manager_compiled = _solidity.compile_contract(
    get_contract_path('ChannelManagerContract.sol'),
    'ChannelManagerContract',
    combined='abi',
)

endpoint_registry_compiled = _solidity.compile_contract(
    get_contract_path('EndpointRegistry.sol'),
    'EndpointRegistry',
    combined='abi',
)

netting_channel_compiled = _solidity.compile_contract(
    get_contract_path('NettingChannelContract.sol'),
    'NettingChannelContract',
    combined='abi',
)

registry_compiled = _solidity.compile_contract(
    get_contract_path('Registry.sol'),
    'Registry',
    combined='abi',
)

# pylint: enable=invalid-name

HUMAN_TOKEN_ABI = human_token_compiled['abi']
CHANNEL_MANAGER_ABI = channel_manager_compiled['abi']
NETTING_CHANNEL_ABI = netting_channel_compiled['abi']
REGISTRY_ABI = registry_compiled['abi']
ENDPOINT_REGISTRY_ABI = endpoint_registry_compiled['abi']

ASSETADDED_EVENT = get_event(REGISTRY_ABI, 'AssetAdded')
ASSETADDED_EVENTID = event_id(*get_eventname_types(ASSETADDED_EVENT))

CHANNELNEW_EVENT = get_event(CHANNEL_MANAGER_ABI, 'ChannelNew')
CHANNELNEW_EVENTID = event_id(*get_eventname_types(CHANNELNEW_EVENT))

CHANNELNEWBALANCE_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelNewBalance')
CHANNELNEWBALANCE_EVENTID = event_id(*get_eventname_types(CHANNELNEWBALANCE_EVENT))

CHANNELCLOSED_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelClosed')
CHANNELCLOSED_EVENTID = event_id(*get_eventname_types(CHANNELCLOSED_EVENT))

CHANNELSECRETREVEALED_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelSecretRevealed')
CHANNELSECRETREVEALED_EVENTID = event_id(*get_eventname_types(CHANNELSECRETREVEALED_EVENT))

CHANNELSETTLED_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelSettled')
CHANNELSETTLED_EVENTID = event_id(*get_eventname_types(CHANNELSETTLED_EVENT))
