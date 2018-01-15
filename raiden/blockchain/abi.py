# -*- coding: utf-8 -*-


import hashlib
import json
import os
import subprocess

from threading import Lock

from ethereum.tools import _solidity
from ethereum.abi import event_id, normalize_name, ContractTranslator

from raiden.utils import get_contract_path

__all__ = (
    'CONTRACT_MANAGER',

    'CONTRACT_CHANNEL_MANAGER',
    'CONTRACT_ENDPOINT_REGISTRY',
    'CONTRACT_HUMAN_STANDARD_TOKEN',
    'CONTRACT_NETTING_CHANNEL',
    'CONTRACT_REGISTRY',

    'EVENT_CHANNEL_NEW',
    'EVENT_CHANNEL_NEW_BALANCE',
    'EVENT_CHANNEL_CLOSED',
    'EVENT_CHANNEL_SECRET_REVEALED',
    'EVENT_CHANNEL_SETTLED',
    'EVENT_TOKEN_ADDED',
)

CONTRACT_CHANNEL_MANAGER = 'channel_manager'
CONTRACT_ENDPOINT_REGISTRY = 'endpoint_registry'
CONTRACT_HUMAN_STANDARD_TOKEN = 'human_standard_token'
CONTRACT_NETTING_CHANNEL = 'netting_channel'
CONTRACT_REGISTRY = 'registry'

EVENT_CHANNEL_NEW = 'ChannelNew'
EVENT_CHANNEL_NEW_BALANCE = 'ChannelNewBalance'
EVENT_CHANNEL_CLOSED = 'ChannelClosed'
EVENT_CHANNEL_SECRET_REVEALED = 'ChannelSecretRevealed'
EVENT_CHANNEL_SETTLED = 'ChannelSettled'
EVENT_TOKEN_ADDED = 'TokenAdded'


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
        contract_path: str,
        contract_name: str,
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
        contract_path: the path of the contract file
        contract_name: the contract name
        **compiler_flags: flags that will be passed to the compiler
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

    validate_solc()

    compiled = _solidity.compile_contract(
        contract_path,
        contract_name,
        **compiler_flags
    )

    if store_updated:
        compiled['checksum'] = checksum
        with open(precompiled_path, 'w') as f:
            json.dump(compiled, f)
        print("'{}' written".format(precompiled_path))
    return compiled


def contract_checksum(contract_path):
    with open(contract_path) as f:
        checksum = hashlib.sha1(f.read().encode()).hexdigest()
        return checksum


def validate_solc():
    if _solidity.get_solidity() is None:
        raise RuntimeError(
            "Couldn't find the solc in the current $PATH.\n"
            "Make sure the solidity compiler is installed and available on your $PATH."
        )

    try:
        _solidity.compile_contract(
            get_contract_path('HumanStandardToken.sol'),
            'HumanStandardToken',
            combined='abi',
            optimize=False,
        )
    except subprocess.CalledProcessError as e:
        msg = (
            'The solidity compiler failed to execute. Please make sure that you\n'
            'are using the binary version of the compiler (solc-js is not compatible)\n'
        )

        if e.output:
            msg += (
                '\n'
                'Output: ' + e.output
            )

        raise RuntimeError(msg)

    except OSError as e:
        msg = (
            'The solidity compiler failed to execute. Please make sure the\n'
            'binary is compatible with your architecture and you can execute it.'
        )

        child_traceback = getattr(e, 'child_traceback', None)
        if child_traceback:
            msg += (
                '\n'
                'Traceback: ' + child_traceback
            )

        raise RuntimeError(msg)


class ContractManager:
    def __init__(self):
        self.is_instantiated = False
        self.lock = Lock()
        self.event_to_contract = {
            'ChannelNew': CONTRACT_CHANNEL_MANAGER,
            'ChannelNewBalance': CONTRACT_NETTING_CHANNEL,
            'ChannelClosed': CONTRACT_NETTING_CHANNEL,
            'ChannelSecretRevealed': CONTRACT_NETTING_CHANNEL,
            'ChannelSettled': CONTRACT_NETTING_CHANNEL,
            'TokenAdded': CONTRACT_REGISTRY,
        }

        self.human_standard_token_compiled = None
        self.channel_manager_compiled = None
        self.endpoint_registry_compiled = None
        self.netting_channel_compiled = None
        self.registry_compiled = None

    def instantiate(self):
        with self.lock:
            if self.is_instantiated:
                return

            self.human_standard_token_compiled = get_static_or_compile(
                get_contract_path('HumanStandardToken.sol'),
                'HumanStandardToken',
                combined='abi',
                optimize=False,
            )

            self.channel_manager_compiled = get_static_or_compile(
                get_contract_path('ChannelManagerContract.sol'),
                'ChannelManagerContract',
                combined='abi',
                optimize=False,
            )

            self.endpoint_registry_compiled = get_static_or_compile(
                get_contract_path('EndpointRegistry.sol'),
                'EndpointRegistry',
                combined='abi',
                optimize=False,
            )

            self.netting_channel_compiled = get_static_or_compile(
                get_contract_path('NettingChannelContract.sol'),
                'NettingChannelContract',
                combined='abi',
                optimize=False,
            )

            self.registry_compiled = get_static_or_compile(
                get_contract_path('Registry.sol'),
                'Registry',
                combined='abi',
                optimize=False,
            )

            self.is_instantiated = True

    def get_abi(self, contract_name):
        self.instantiate()
        compiled = getattr(self, '{}_compiled'.format(contract_name))
        return compiled['abi']

    def get_event_id(self, event_name):
        """ Not really generic, as it maps event names to events of specific contracts,
        but it is good enough for what we want to accomplish.
        """
        event = get_event(self.get_abi(self.event_to_contract[event_name]), event_name)
        return event_id(*get_eventname_types(event))

    def get_translator(self, contract_name):
        return ContractTranslator(self.get_abi(contract_name))


CONTRACT_MANAGER = ContractManager()
