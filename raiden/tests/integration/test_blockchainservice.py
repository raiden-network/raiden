# -*- coding: utf-8 -*-
from binascii import unhexlify
import os
import itertools

import pytest
from ethereum.tools import _solidity
from ethereum.tools._solidity import compile_file
from ethereum.utils import denoms, normalize_address

from raiden.blockchain.abi import CONTRACT_MANAGER, CONTRACT_CHANNEL_MANAGER
from raiden.exceptions import AddressWithoutCode, SamePeerAddress
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.settings import GAS_PRICE
from raiden.tests.utils.blockchain import wait_until_block
from raiden.utils import privatekey_to_address, get_contract_path, topic_decoder


solidity = _solidity.get_solidity()   # pylint: disable=invalid-name


@pytest.mark.parametrize('privatekey_seed', ['blockchain:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [0])
def test_new_netting_contract(raiden_network, token_amount, settle_timeout):
    # pylint: disable=line-too-long,too-many-statements,too-many-locals

    app0, app1, app2 = raiden_network
    peer0_address = app0.raiden.address
    peer1_address = app1.raiden.address
    peer2_address = app2.raiden.address

    blockchain_service0 = app0.raiden.chain
    registry = app0.raiden.default_registry

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    token_address = blockchain_service0.deploy_and_register_token(
        registry,
        contract_name='HumanStandardToken',
        contract_path=humantoken_path,
        constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
    )

    token0 = blockchain_service0.token(token_address)
    for transfer_to in raiden_network[1:]:
        token0.transfer(
            privatekey_to_address(transfer_to.raiden.privkey),
            token_amount // len(raiden_network),
        )

    manager0 = registry.manager_by_token(token_address)

    # sanity
    assert manager0.channels_addresses() == []
    assert manager0.channels_by_participant(peer0_address) == []
    assert manager0.channels_by_participant(peer1_address) == []
    assert manager0.channels_by_participant(peer2_address) == []

    # create one channel
    netting_address_01 = manager0.new_netting_channel(
        peer1_address,
        settle_timeout,
    )

    # check contract state
    netting_channel_01 = blockchain_service0.netting_channel(netting_address_01)
    assert netting_channel_01.can_transfer() is False

    # check channels
    channel_list = manager0.channels_addresses()
    assert sorted(channel_list[0]) == sorted([peer0_address, peer1_address])

    assert manager0.channels_by_participant(peer0_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer1_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer2_address) == []
    # create a duplicated channel with same participants while previous channel
    #  is still open should throw an exception
    with pytest.raises(Exception):
        manager0.new_netting_channel(
            peer1_address,
            settle_timeout,
        )
    # create other channel
    netting_address_02 = manager0.new_netting_channel(
        peer2_address,
        settle_timeout,
    )

    netting_channel_02 = blockchain_service0.netting_channel(netting_address_02)

    assert netting_channel_02.can_transfer() is False

    channel_list = manager0.channels_addresses()
    expected_channels = [
        sorted([peer0_address, peer1_address]),
        sorted([peer0_address, peer2_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    result0 = sorted(manager0.channels_by_participant(peer0_address))
    result1 = sorted([netting_address_01, netting_address_02])
    assert result0 == result1
    assert manager0.channels_by_participant(peer1_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer2_address) == [netting_address_02]

    # deposit without approve should fail
    netting_channel_01.deposit(100)
    assert netting_channel_01.can_transfer() is False
    assert netting_channel_02.can_transfer() is False
    assert netting_channel_01.detail()['our_balance'] == 0
    assert netting_channel_02.detail()['our_balance'] == 0

    # single-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_01, 100)
    netting_channel_01.deposit(100)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is False

    assert netting_channel_01.detail()['our_balance'] == 100
    assert netting_channel_02.detail()['our_balance'] == 0

    # double-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_02, 70)
    netting_channel_02.deposit(70)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 0

    app2.raiden.chain.token(token_address).approve(netting_address_02, 130)
    app2.raiden.chain.netting_channel(netting_address_02).deposit(130)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 130

    # open channel with same peer again after settling
    netting_channel_01.close(
        nonce=0,
        transferred_amount=0,
        locksroot='',
        extra_hash='',
        signature='',
    )

    wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + settle_timeout + 1)
    netting_channel_01.settle()

    with pytest.raises(AddressWithoutCode):
        netting_channel_01.closed()

    with pytest.raises(AddressWithoutCode):
        netting_channel_01.opened()

    # open channel with same peer again
    netting_address_01_reopened = manager0.new_netting_channel(
        peer1_address,
        settle_timeout,
    )
    netting_channel_01_reopened = blockchain_service0.netting_channel(netting_address_01_reopened)

    assert netting_channel_01_reopened.opened() != 0
    assert netting_address_01_reopened in manager0.channels_by_participant(peer0_address)
    assert netting_address_01 not in manager0.channels_by_participant(peer0_address)

    app0.raiden.chain.token(token_address).approve(netting_address_01_reopened, 100)
    netting_channel_01_reopened.deposit(100)
    assert netting_channel_01_reopened.opened() != 0


@pytest.mark.parametrize('number_of_nodes', [10])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channelmanager_graph_building(
        raiden_network,
        token_addresses,
        settle_timeout):

    token_address = token_addresses[0]

    total_pairs = 0
    pairs = itertools.combinations(raiden_network, 2)
    for app0, app1 in pairs:
        manager = app0.raiden.default_registry.manager_by_token(token_address)
        manager.new_netting_channel(
            app1.raiden.address,
            settle_timeout,
        )
        total_pairs += 1
        assert total_pairs == len(manager.channels_addresses())


@pytest.mark.skipif(
    'TRAVIS' in os.environ,
    reason='Flaky test due to mark.timeout not being scheduled. Issue #319'
)
@pytest.mark.parametrize('privatekey_seed', ['blockchain:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_blockchain(
        blockchain_backend,  # required to start the geth backend pylint: disable=unused-argument
        blockchain_rpc_ports,
        private_keys,
        poll_timeout):
    # pylint: disable=too-many-locals

    addresses = [
        privatekey_to_address(priv)
        for priv in private_keys
    ]

    privatekey = private_keys[0]
    address = privatekey_to_address(privatekey)
    total_token = 100

    host = '127.0.0.1'
    jsonrpc_client = JSONRPCClient(
        host,
        blockchain_rpc_ports[0],
        privatekey,
    )

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        list(),
        (total_token, 'raiden', 2, 'Rd'),
        contract_path=humantoken_path,
        gasprice=GAS_PRICE,
        timeout=poll_timeout,
    )

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_file(registry_path)
    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'Registry',
        registry_contracts,
        list(),
        tuple(),
        contract_path=registry_path,
        gasprice=GAS_PRICE,
        timeout=poll_timeout,
    )

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert not log_list

    assert token_proxy.call('balanceOf', address) == total_token
    transaction_hash = registry_proxy.transact(
        'addToken',
        token_proxy.contract_address,
        gasprice=denoms.wei,
    )
    jsonrpc_client.poll(unhexlify(transaction_hash), timeout=poll_timeout)

    assert len(registry_proxy.call('tokenAddresses')) == 1

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 1

    channel_manager_address_encoded = registry_proxy.call(
        'channelManagerByToken',
        token_proxy.contract_address,
    )
    channel_manager_address = normalize_address(channel_manager_address_encoded)

    log = log_list[0]
    log_topics = [
        topic_decoder(topic)
        for topic in log['topics']  # pylint: disable=invalid-sequence-index
    ]
    log_data = log['data']  # pylint: disable=invalid-sequence-index
    event = registry_proxy.translator.decode_event(
        log_topics,
        unhexlify(log_data[2:]),
    )

    assert channel_manager_address == normalize_address(event['channel_manager_address'])
    assert token_proxy.contract_address == normalize_address(event['token_address'])

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
    )

    transaction_hash = channel_manager_proxy.transact(
        'newChannel',
        addresses[1],
        10,
        gasprice=denoms.wei,
    )
    jsonrpc_client.poll(unhexlify(transaction_hash), timeout=poll_timeout)

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 2


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_with_self(raiden_network, settle_timeout):
    app0, = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    token_address = app0.raiden.default_registry.token_addresses()[0]

    assert not app0.raiden.token_to_channelgraph[token_address].address_to_channel

    graph0 = app0.raiden.default_registry.manager_by_token(token_address)

    with pytest.raises(SamePeerAddress) as excinfo:
        graph0.new_netting_channel(
            app0.raiden.address,
            settle_timeout,
        )

    assert 'The other peer must not have the same address as the client.' in str(excinfo.value)

    transaction_hash = graph0.proxy.transact(
        'newChannel',
        app0.raiden.address,
        settle_timeout,
    )

    # wait to make sure we get the receipt
    wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + 5)
    assert check_transaction_threw(app0.raiden.chain.client, transaction_hash)
