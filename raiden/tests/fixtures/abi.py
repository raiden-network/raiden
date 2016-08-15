# -*- coding: utf8 -*-
import pytest
from ethereum._solidity import compile_file

from raiden.blockchain.abi import get_contract_path


@pytest.fixture(scope='session')
def token_abi():
    human_token_path = get_contract_path('HumanStandardToken.sol')
    human_token_compiled = compile_file(human_token_path, combined='abi')
    human_token_abi = human_token_compiled['HumanStandardToken']['abi']
    return human_token_abi


@pytest.fixture(scope='session')
def channel_manager_abi():
    channel_manager_path = get_contract_path('ChannelManagerContract.sol')
    channel_manager_compiled = compile_file(channel_manager_path, combined='abi')
    channel_manager_abi = channel_manager_compiled['ChannelManagerContract']['abi']
    return channel_manager_abi


@pytest.fixture(scope='session')
def netting_channel_abi():
    netting_channel_path = get_contract_path('NettingChannelContract.sol')
    netting_channel_compiled = compile_file(netting_channel_path, combined='abi')
    netting_channel_abi = netting_channel_compiled['NettingChannelContract']['abi']
    return netting_channel_abi


@pytest.fixture(scope='session')
def registry_abi():
    registry_path = get_contract_path('Registry.sol')
    registry_compiled = compile_file(registry_path, combined='abi')
    registry_abi = registry_compiled['Registry']['abi']
    return registry_abi
