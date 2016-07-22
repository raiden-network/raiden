# -*- coding: utf8 -*-
import os

from ethereum import _solidity
from ethereum.abi import event_id, normalize_name

import raiden

__all__ = (
    'get_contract_path',

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

    'HUMAN_TOKEN_ABI',
    'REGISTRY_ABI',
)


def get_contract_path(contract_name):
    project_directory = os.path.dirname(raiden.__file__)
    contract_path = os.path.join(project_directory, 'smart_contracts', contract_name)
    return os.path.realpath(contract_path)


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

CHANNELNEW_EVENT = get_event(CHANNEL_MANAGER_ABI, 'ChannelNew')
CHANNELNEW_EVENTID = event_id(*get_eventname_types(CHANNELNEW_EVENT))

CHANNELNEWBALANCE_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelNewBalance')
CHANNELNEWBALANCE_EVENTID = event_id(*get_eventname_types(CHANNELNEWBALANCE_EVENT))

CHANNELCLOSED_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelClosed')
CHANNELCLOSED_EVENTID = event_id(*get_eventname_types(CHANNELCLOSED_EVENT))

CHANNELSECRETREVEALED_EVENT = get_event(NETTING_CHANNEL_ABI, 'ChannelSecretRevealed')
CHANNELSECRETREVEALED_EVENTID = event_id(*get_eventname_types(CHANNELSECRETREVEALED_EVENT))
