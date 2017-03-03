# -*- coding: utf-8 -*-
import os
import json
import hashlib

from ethereum import _solidity
from ethereum.abi import event_id, normalize_name, ContractTranslator

from raiden.utils import get_contract_path

__all__ = (
    'REGISTRY_ABI',
    'TOKENADDED_EVENT',
    'TOKENADDED_EVENTID',

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

    'REGISTRY_TRANSLATOR',
    'CHANNEL_MANAGER_TRANSLATOR',
    'NETTING_CHANNEL_TRANSLATOR',
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


def get_static_or_compile(
        contract_path,
        contract_name,
        **compiler_flags):
    """Search the path of `contract_path` for a file with the same name and the
    extension `.static-abi.json`. If the file exists, and the recorded checksum
    matches, this will return the precompiled contract, otherwise it will
    compile it.

    Writing compiled contracts to the desired file and path happens only when
    the environment variable `STORE_PRECOMPILED` is set (to whatever value).
    Users are not expected to ever set this value, the functionality is exposed
    through the `setup.py compile_contracts` command.

    Args:
        contract_path (str): the path of the contract file
        contract_name (str): the contract name
        **compiler_flags (dict): flags that will be passed to the compiler
    """
    # this will be set by `setup.py compile_contracts`
    store_updated = os.environ.get('STORE_PRECOMPILED', False)
    precompiled = None
    precompiled_path = '{}.static-abi.json'.format(contract_path)
    try:
        with open(precompiled_path) as f:
            precompiled = json.load(f)
    except IOError:
        pass

    if precompiled or store_updated:
        checksum = contract_checksum(contract_path)
    if precompiled and precompiled['checksum'] == checksum:
        return precompiled
    if _solidity.get_solidity() is None:
        raise RuntimeError("The solidity compiler, `solc`, is not available.")
    compiled = _solidity.compile_contract(
        contract_path,
        contract_name,
        combined='abi'
    )
    if store_updated:
        compiled['checksum'] = checksum
        with open(precompiled_path, 'w') as f:
            json.dump(compiled, f)
        print("'{}' written".format(precompiled_path))
    return compiled


def contract_checksum(contract_path):
    with open(contract_path) as f:
        checksum = hashlib.sha1(f.read()).hexdigest()
        return checksum


# pylint: disable=invalid-name
human_token_compiled = get_static_or_compile(
    get_contract_path('HumanStandardToken.sol'),
    'HumanStandardToken',
    combined='abi',
)

channel_manager_compiled = get_static_or_compile(
    get_contract_path('ChannelManagerContract.sol'),
    'ChannelManagerContract',
    combined='abi',
)

endpoint_registry_compiled = get_static_or_compile(
    get_contract_path('EndpointRegistry.sol'),
    'EndpointRegistry',
    combined='abi',
)

netting_channel_compiled = get_static_or_compile(
    get_contract_path('NettingChannelContract.sol'),
    'NettingChannelContract',
    combined='abi',
)

registry_compiled = get_static_or_compile(
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

TOKENADDED_EVENT = get_event(REGISTRY_ABI, 'TokenAdded')
TOKENADDED_EVENTID = event_id(*get_eventname_types(TOKENADDED_EVENT))

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

REGISTRY_TRANSLATOR = ContractTranslator(REGISTRY_ABI)
CHANNEL_MANAGER_TRANSLATOR = ContractTranslator(CHANNEL_MANAGER_ABI)
NETTING_CHANNEL_TRANSLATOR = ContractTranslator(NETTING_CHANNEL_ABI)
