# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum._solidity import compile_file
from ethereum.tester import ABIContract, ContractTranslator

from raiden.blockchain.abi import get_contract_path

# pylint: disable=redefined-outer-name,no-member


@pytest.fixture
def asset_amount():
    return 10000


@pytest.fixture
def settle_timeout():
    return 30


@pytest.fixture
def events():
    events = []
    return events


@pytest.fixture
def token_abi():
    human_token_path = get_contract_path('HumanStandardToken.sol')
    human_compiled = compile_file(human_token_path, combined='abi')
    return human_compiled['HumanStandardToken']['abi']


@pytest.fixture
def state():
    state = tester.state()
    state.block.number = 1158001
    return state


@pytest.fixture
def token_address(asset_amount, state):
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    standard_token_address = state.contract(
        None,
        path=standard_token_path,
        language='solidity',
    )

    human_libraries = {
        'StandardToken': standard_token_address.encode('hex'),
    }
    human_token_proxy = state.abi_contract(
        None,
        path=human_token_path,
        language='solidity',
        libraries=human_libraries,
        constructor_parameters=[asset_amount, 'raiden', 0, 'rd'],
    )

    state.mine()

    return human_token_proxy.address


@pytest.fixture
def token(state, token_address, token_abi):
    translator = ContractTranslator(token_abi)

    return ABIContract(
        state,
        translator,
        token_address,
    )


@pytest.fixture
def netting_channel_library(state):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    library_address = state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
    )
    return library_address


@pytest.fixture
def netting_channel_abi():
    netting_library_path = get_contract_path('ChannelManagerLibrary.sol')
    netting_channel_compiled = compile_file(netting_library_path)['NettingChannelContract']
    netting_channel_abi = netting_channel_compiled['abi']
    return netting_channel_abi


@pytest.fixture
def channel_manager_library(state, netting_channel_library, settle_timeout, token_address):
    manager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    library_address = state.contract(
        None,
        path=manager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': netting_channel_library.encode('hex'),
        }
    )
    return library_address


@pytest.fixture
def channel(state, token, netting_channel_library, settle_timeout, events):
    netting_contract_path = get_contract_path('ChannelManagerLibrary.sol')
    abi = state.abi_contract(
        None,
        path=netting_contract_path,
        language='solidity',
        constructor_parameters=[token.address, tester.a0, tester.a1, settle_timeout],
        contract_name='NettingChannelContract',
        log_listener=events.append,
        libraries={
            'NettingChannelLibrary': netting_channel_library.encode('hex'),
        }
    )
    return abi


@pytest.fixture
def manager(state, token, channel_manager_library, events):
    registry_path = get_contract_path('Registry.sol')

    return state.abi_contract(
        None,
        path=registry_path,
        language='solidity',
        constructor_parameters=[token.address],
        contract_name='ChannelManagerContract',
        log_listener=events.append,
        libraries={
            'ChannelManagerLibrary': channel_manager_library.encode('hex'),
        }
    )


@pytest.fixture
def registry(state, token, channel_manager_library, events):
    registry_path = get_contract_path('Registry.sol')

    return state.abi_contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        log_listener=events.append,
        libraries={
            'ChannelManagerLibrary': channel_manager_library.encode('hex')
        }
    )
