# -*- coding: utf-8 -*-
import pytest
import ethereum.db
import ethereum.blocks
import ethereum.config
from ethereum import tester
from ethereum.utils import int_to_addr, zpad
from pyethapp.jsonrpc import address_decoder, data_decoder, quantity_decoder


from raiden.utils import privatekey_to_address, get_contract_path
from raiden.tests.utils.blockchain import DEFAULT_BALANCE
from raiden.tests.utils.tester import (
    approve_and_deposit,
    channel_from_nettingcontract,
    create_registryproxy,
    create_tokenproxy,
    new_channelmanager,
    new_nettingcontract,
)
from raiden.tests.utils.tester_client import ChannelExternalStateTester


@pytest.fixture
def tester_blockgas_limit():
    """ The tester's block gas limit.

    Set this value to `GAS_LIMIT`ing if the test needs to consider the gas usage.

    Note:
        `GAS_LIMIT` is defined in `raiden.network.rpc.client.GAS_LIMIT`
    """
    return 10 ** 10


@pytest.fixture
def tester_events():
    return list()


@pytest.fixture
def tester_state(deploy_key, private_keys, tester_blockgas_limit):
    tester_state = tester.state()

    # special addresses 1 to 5
    alloc = {
        int_to_addr(i): {'wei': 1}
        for i in range(1, 5)
    }

    for privkey in [deploy_key] + private_keys:
        address = privatekey_to_address(privkey)
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
def tester_token_address(private_keys, token_amount, tester_state):
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
        constructor_parameters=[token_amount, 'raiden', 0, 'rd'],
        sender=private_keys[0],
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
def tester_token_raw(tester_state, tester_token_address, tester_events):
    return create_tokenproxy(
        tester_state,
        tester_token_address,
        tester_events.append,
    )


@pytest.fixture
def tester_token(token_amount, private_keys, tester_state, tester_token_address, tester_events):
    token = create_tokenproxy(
        tester_state,
        tester_token_address,
        tester_events.append,
    )

    privatekey0 = private_keys[0]
    for transfer_to in private_keys[1:]:
        token.transfer(
            privatekey_to_address(transfer_to),
            token_amount // len(private_keys),
            sender=privatekey0,
        )

    return token


@pytest.fixture
def tester_registry(tester_state, tester_registry_address, tester_events):
    return create_registryproxy(
        tester_state,
        tester_registry_address,
        tester_events.append,
    )


@pytest.fixture
def tester_channelmanager(
        private_keys,
        tester_state,
        tester_events,
        tester_registry,
        tester_token):
    privatekey0 = private_keys[0]
    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )
    return channel_manager


@pytest.fixture
def tester_nettingcontracts(
        deposit,
        both_participants_deposit,
        private_keys,
        settle_timeout,
        tester_state,
        tester_events,
        tester_channelmanager,
        tester_token):
    raiden_chain = zip(private_keys[:-1], private_keys[1:])

    result = list()
    for pos, (first_key, second_key) in enumerate(raiden_chain, start=1):

        # tester.py log_listener is enabled for the whole tester, meaning that
        # a log_listener will receive all events that it can decode, even if
        # the event is from a different contract, because of that we _must_
        # only install the log_listener for the first ABI, otherwise the logs
        # will be repeated for each ABI
        if pos == 1:
            log_listener = tester_events.append
        else:
            log_listener = None

        nettingcontract = new_nettingcontract(
            first_key,
            second_key,
            tester_state,
            log_listener,
            tester_channelmanager,
            settle_timeout,
        )
        result.append(
            (first_key, second_key, nettingcontract),
        )

        approve_and_deposit(
            tester_token,
            nettingcontract,
            deposit,
            first_key,
        )

        if both_participants_deposit:
            approve_and_deposit(
                tester_token,
                nettingcontract,
                deposit,
                second_key,
            )

    return result


@pytest.fixture
def tester_channels(tester_state, tester_nettingcontracts, reveal_timeout):
    result = list()
    for first_key, second_key, nettingcontract in tester_nettingcontracts:
        first_externalstate = ChannelExternalStateTester(
            tester_state,
            first_key,
            nettingcontract.address,
        )
        first_channel = channel_from_nettingcontract(
            first_key,
            nettingcontract,
            first_externalstate,
            reveal_timeout,
            tester_state.block.number,
        )

        second_externalstate = ChannelExternalStateTester(
            tester_state,
            second_key,
            nettingcontract.address,
        )
        second_channel = channel_from_nettingcontract(
            second_key,
            nettingcontract,
            second_externalstate,
            reveal_timeout,
            tester_state.block.number,
        )

        result.append(
            (first_key, second_key, nettingcontract, first_channel, second_channel)
        )

    return result
