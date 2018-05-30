# -*- coding: utf-8 -*-


import hashlib
import json
import os
import subprocess
import re

from threading import Lock

from solc import compile_files, get_solc_version
from eth_utils import event_abi_to_log_topic, encode_hex
from web3.utils.contracts import find_matching_event_abi


from raiden.utils import get_contract_path, compare_versions
from raiden.constants import MIN_REQUIRED_SOLC
from raiden.exceptions import ContractVersionMismatch


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

CONTRACT_VERSION_RE = r'^\s*string constant public contract_version = "([0-9]+\.[0-9]+\.[0-9\_])";\s*$' # noqa


def parse_contract_version(contract_file, version_re):
    contract_file = get_contract_path(contract_file)
    with open(contract_file, 'r') as original:
        for line in original.readlines():
            match = version_re.match(line)
            if match:
                return match.group(1)


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

    compiled = compile_files(
        [contract_path],
        contract_name,
        **compiler_flags
    )

    if store_updated:
        compiled['checksum'] = checksum
        with open(precompiled_path, 'w') as f:
            json.dump(compiled, f)
        print("'{}' written".format(precompiled_path))
    compiled_abi = [
        v for k, v in compiled.items()
        if k.split(':')[1] == contract_name
    ]
    assert len(compiled_abi) == 1
    return compiled_abi[0]


def contract_checksum(contract_path):
    with open(contract_path) as f:
        checksum = hashlib.sha1(f.read().encode()).hexdigest()
        return checksum


def validate_solc():
    if get_solc_version() is None:
        raise RuntimeError(
            "Couldn't find the solc in the current $PATH.\n"
            "Make sure the solidity compiler is installed and available on your $PATH."
        )

    try:
        compile_files(
            [get_contract_path('HumanStandardToken.sol')],
            'HumanStandardToken',
            optimize=False,
        )
    except subprocess.CalledProcessError as e:
        msg = (
            'The solidity compiler failed to execute. Please make sure that you\n'
            'are using the binary version of the compiler (solc-js is not compatible)\n'
            'and that the version is >= {}'.format(MIN_REQUIRED_SOLC)
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
        self.contract_to_version = dict()

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
                optimize=False,
            )

            self.channel_manager_compiled = get_static_or_compile(
                get_contract_path('ChannelManagerContract.sol'),
                'ChannelManagerContract',
                optimize=False,
            )

            self.endpoint_registry_compiled = get_static_or_compile(
                get_contract_path('EndpointRegistry.sol'),
                'EndpointRegistry',
                optimize=False,
            )

            self.netting_channel_compiled = get_static_or_compile(
                get_contract_path('NettingChannelContract.sol'),
                'NettingChannelContract',
                optimize=False,
            )

            self.registry_compiled = get_static_or_compile(
                get_contract_path('Registry.sol'),
                'Registry',
                optimize=False,
            )

            self.is_instantiated = True
            self.init_contract_versions()

    def init_contract_versions(self):
        contracts = [
            ('HumanStandardToken.sol', CONTRACT_HUMAN_STANDARD_TOKEN),
            ('ChannelManagerContract.sol', CONTRACT_CHANNEL_MANAGER),
            ('EndpointRegistry.sol', CONTRACT_ENDPOINT_REGISTRY),
            ('NettingChannelContract.sol', CONTRACT_NETTING_CHANNEL),
            ('Registry.sol', CONTRACT_REGISTRY)
        ]
        version_re = re.compile(CONTRACT_VERSION_RE)
        for contract_file, contract_name in contracts:
            self.contract_to_version[contract_name] = parse_contract_version(
                contract_file,
                version_re
            )

    def get_version(self, contract_name):
        """Return version of the contract."""
        return self.contract_to_version[contract_name]

    def get_abi(self, contract_name):
        self.instantiate()
        compiled = getattr(self, '{}_compiled'.format(contract_name))
        return compiled['abi']

    def get_event_id(self, event_name: str) -> int:
        """ Not really generic, as it maps event names to events of specific contracts,
        but it is good enough for what we want to accomplish.
        """
        contract_abi = self.get_abi(self.event_to_contract[event_name])
        event_abi = find_matching_event_abi(contract_abi, event_name)
        log_id = event_abi_to_log_topic(event_abi)
        return int(encode_hex(log_id), 16)

    def check_contract_version(self, deployed_version, contract_name):
        """Check if the deployed contract version matches used contract version."""
        our_version = CONTRACT_MANAGER.get_version(contract_name)
        if compare_versions(deployed_version, our_version) is False:
            raise ContractVersionMismatch('Incompatible ABI for %s' % contract_name)


CONTRACT_MANAGER = ContractManager()
