# -*- coding: utf8 -*-
import pytest
import ethereum.db
import ethereum.blocks
import ethereum.config
from ethereum import tester
from ethereum.utils import int_to_addr, zpad
from ethereum.keys import privtoaddr
from pyethapp.jsonrpc import address_decoder, data_decoder, quantity_decoder

from raiden.network.rpc.client import GAS_LIMIT
from raiden.blockchain.abi import get_contract_path
from raiden.tests.utils.blockchain import DEFAULT_BALANCE
from raiden.tests.utils.tester import create_channelmanager_proxy, create_registryproxy, create_tokenproxy


@pytest.fixture
def tester_blockgas_limit():
    """ The tester's block gas limit. Increase this value to avoid `mine`ing to
    if the blockgas is not of interest for the test.
    """
    return GAS_LIMIT


@pytest.fixture
def tester_state(private_keys, tester_blockgas_limit):
    tester_state = tester.state()

    # special addresses 1 to 5
    alloc = {
        int_to_addr(i): {'wei': 1}
        for i in range(1, 5)
    }

    for privkey in private_keys:
        address = privtoaddr(privkey)
        alloc[address] = {
            'balance': DEFAULT_BALANCE,
        }

    for account in tester.accounts:
        alloc[account] = {
            'balance': DEFAULT_BALANCE,
        }

    db = ethereum.db.EphemDB()
    env = ethereum.config.Env(
        db,
        ethereum.config.default_config,
    )
    genesis_overwrite = {
        'nonce': zpad(data_decoder('0x00006d6f7264656e'), 8),
        'difficulty': quantity_decoder('0x20000'),
        'mixhash': zpad(b'\x00', 32),
        'coinbase': address_decoder('0x0000000000000000000000000000000000000000'),
        'timestamp': 0,
        'extra_data': b'',
        'gas_limit': tester_blockgas_limit,
        'start_alloc': alloc,
    }
    genesis_block = ethereum.blocks.genesis(
        env,
        **genesis_overwrite
    )

    # enable DELEGATECALL opcode
    genesis_block.number = genesis_block.config['HOMESTEAD_FORK_BLKNUM'] + 1

    tester_state.db = db
    tester_state.env = env
    tester_state.block = genesis_block
    tester_state.blocks = [genesis_block]

    return tester_state


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
    tester_state.mine(number_of_blocks=1)

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
    tester_state.mine(number_of_blocks=1)

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
    tester_state.mine(number_of_blocks=1)
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
    tester_state.mine(number_of_blocks=1)
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
    tester_state.mine(number_of_blocks=1)
    return registry_address


@pytest.fixture
def tester_token(tester_state, tester_token_address, tester_events):
    return create_tokenproxy(
        tester_state,
        tester_token_address,
        tester_events,
    )


@pytest.fixture
def tester_registry(tester_state, tester_registry_address, tester_events):
    return create_registryproxy(
        tester_state,
        tester_registry_address,
        tester_events,
    )
