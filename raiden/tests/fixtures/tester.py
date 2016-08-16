# -*- coding: utf8 -*-
import pytest
from ethereum import tester
from ethereum.tester import ABIContract, ContractTranslator

from raiden.blockchain.abi import get_contract_path


@pytest.fixture
def tester_state():
    state = tester.state()
    state.block.number = 1150001  # HOMESTEAD_FORK_BLKNUM=1150000
    return state


@pytest.fixture
def tester_events():
    return list()


@pytest.fixture
def tester_token_address(asset_amount, tester_state):
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    standard_token_address = tester_state.contract(
        None,
        path=standard_token_path,
        language='solidity',
    )

    human_token_libraries = {
        'StandardToken': standard_token_address.encode('hex'),
    }
    # using abi_contract because of the constructor_parameters
    human_token_proxy = tester_state.abi_contract(
        None,
        path=human_token_path,
        language='solidity',
        libraries=human_token_libraries,
        constructor_parameters=[asset_amount, 'raiden', 0, 'rd'],
    )
    tester_state.mine()

    human_token_address = human_token_proxy.address
    return human_token_address


@pytest.fixture
def tester_nettingchannel_library_address(tester_state):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    library_address = tester_state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
    )
    tester_state.mine()
    return library_address


@pytest.fixture
def tester_channelmanager_library_address(tester_state, tester_nettingchannel_library_address):
    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    manager_address = tester_state.contract(
        None,
        path=channelmanager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': tester_nettingchannel_library_address.encode('hex'),
        }
    )
    tester_state.mine()
    return manager_address


@pytest.fixture
def tester_registry_address(tester_state, tester_channelmanager_library_address):
    registry_path = get_contract_path('Registry.sol')
    registry_address = tester_state.contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        libraries={
            'ChannelManagerLibrary': tester_channelmanager_library_address.encode('hex')
        }
    )
    tester_state.mine()
    return registry_address


@pytest.fixture
def tester_token(tester_state, tester_token_address, token_abi, tester_events):
    translator = ContractTranslator(token_abi)

    return ABIContract(
        tester_state,
        translator,
        tester_token_address,
        log_listener=tester_events.append,
    )


@pytest.fixture
def tester_registry(tester_state, registry_abi, tester_registry_address, tester_events):
    translator = ContractTranslator(registry_abi)

    return ABIContract(
        tester_state,
        translator,
        tester_registry_address,
        log_listener=tester_events.append,
    )


@pytest.fixture
def tester_default_channel_manager(tester_state, tester_token, tester_registry,
                                   tester_events, channel_manager_abi):
    contract_address = tester_registry.addAsset(tester_token.address)
    translator = ContractTranslator(channel_manager_abi)
    channel_manager_abi = ABIContract(
        tester_state,
        translator,
        contract_address,
        log_listener=tester_events.append,
    )
    return channel_manager_abi
