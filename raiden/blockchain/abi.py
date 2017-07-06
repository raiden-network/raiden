# -*- coding: utf-8 -*-
import os
import json
import hashlib

from ethereum import _solidity
from ethereum.abi import event_id, normalize_name, ContractTranslator

from raiden.utils import get_contract_path

__all__ = ('CONTRACT_MANAGER',)


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


class ContractManager():

    def __init__(self):
        self.is_instantiated = False

    def instantiate(self):
        self.human_standard_token_compiled = get_static_or_compile(
            get_contract_path('HumanStandardToken.sol'),
            'HumanStandardToken',
            combined='abi',
        )

        self.channel_manager_compiled = get_static_or_compile(
            get_contract_path('ChannelManagerContract.sol'),
            'ChannelManagerContract',
            combined='abi',
        )

        self.endpoint_registry_compiled = get_static_or_compile(
            get_contract_path('EndpointRegistry.sol'),
            'EndpointRegistry',
            combined='abi',
        )

        self.netting_channel_compiled = get_static_or_compile(
            get_contract_path('NettingChannelContract.sol'),
            'NettingChannelContract',
            combined='abi',
        )

        self.registry_compiled = get_static_or_compile(
            get_contract_path('Registry.sol'),
            'Registry',
            combined='abi',
        )

        self.is_instantiated = True

    def get_abi(self, contract_name):
        if not self.is_instantiated:
            self.instantiate()

        compiled = getattr(self, '{}_compiled'.format(contract_name))
        return compiled['abi']

    def get_event_id(self, event_name):
        """ Not really generic, as it maps event names to events of specific contracts,
        but it is good enough for what we want to accomplish.
        """
        if event_name == 'TokenAdded':
            event = get_event(self.get_abi('registry'), event_name)
        elif event_name == 'ChannelNew':
            event = get_event(self.get_abi('channel_manager'), event_name)
        elif event_name == 'ChannelNewBalance':
            event = get_event(self.get_abi('netting_channel'), event_name)
        elif event_name == 'ChannelClosed':
            event = get_event(self.get_abi('netting_channel'), event_name)
        elif event_name == 'ChannelSecretRevealed':
            event = get_event(self.get_abi('netting_channel'), event_name)
        elif event_name == 'ChannelSettled':
            event = get_event(self.get_abi('netting_channel'), event_name)
        else:
            raise ValueError('Unknown event: {}'.format(event_name))

        return event_id(*get_eventname_types(event))

    def get_translator(self, contract_name):
        return ContractTranslator(self.get_abi(contract_name))


CONTRACT_MANAGER = ContractManager()
