# -*- coding: utf-8 -*-
from __future__ import division

import os
import itertools

import pytest
from ethereum import _solidity
from ethereum._solidity import compile_file
from ethereum.tester import TransactionFailed
from ethereum.utils import denoms
from pyethapp.jsonrpc import default_gasprice
from pyethapp.rpc_client import JSONRPCClient

from raiden.tests.utils.blockchain import wait_until_block
from raiden.network.rpc.client import (
    decode_topic,
    patch_send_transaction,
    patch_send_message,
    check_transaction_threw,
)
from raiden.exceptions import AddressWithoutCode
from raiden.utils import privatekey_to_address, get_contract_path
from raiden.blockchain.abi import CONTRACT_MANAGER, CONTRACT_CHANNEL_MANAGER
from raiden.exceptions import SamePeerAddress


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
        peer0_address,
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
            peer0_address,
            peer1_address,
            settle_timeout,
        )
    # create other channel
    netting_address_02 = manager0.new_netting_channel(
        peer0_address,
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
        peer0_address,
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
            app0.raiden.address,
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
        blockchain_type,
        blockchain_backend,  # required to start the geth backend
        blockchain_rpc_ports,
        private_keys,
        poll_timeout):
    # pylint: disable=too-many-locals

    # this test is for interaction with a blockchain using json-rpc, so it
    # doesnt make sense to execute it against tester
    if blockchain_type not in ('geth',):
        return

    addresses = [
        privatekey_to_address(priv)
        for priv in private_keys
    ]

    privatekey = private_keys[0]
    address = privatekey_to_address(privatekey)
    total_token = 100

    jsonrpc_client = JSONRPCClient(
        port=blockchain_rpc_ports[0],
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(jsonrpc_client)
    patch_send_message(jsonrpc_client)

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        dict(),
        (total_token, 'raiden', 2, 'Rd'),
        contract_path=humantoken_path,
        gasprice=default_gasprice,
        timeout=poll_timeout,
    )

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_file(registry_path)
    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'Registry',
        registry_contracts,
        dict(),
        tuple(),
        contract_path=registry_path,
        gasprice=default_gasprice,
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
    assert len(log_list) == 0

    # pylint: disable=no-member

    assert token_proxy.balanceOf(address) == total_token
    transaction_hash = registry_proxy.addToken.transact(
        token_proxy.address,
        gasprice=denoms.wei,
    )
    jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=poll_timeout)

    assert len(registry_proxy.tokenAddresses.call()) == 1

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 1

    channel_manager_address_encoded = registry_proxy.channelManagerByToken.call(
        token_proxy.address,
    )
    channel_manager_address = channel_manager_address_encoded.decode('hex')

    log = log_list[0]
    log_topics = [
        decode_topic(topic)
        for topic in log['topics']  # pylint: disable=invalid-sequence-index
    ]
    log_data = log['data']
    event = registry_proxy.translator.decode_event(
        log_topics,
        log_data[2:].decode('hex'),
    )

    assert channel_manager_address == event['channel_manager_address'].decode('hex')
    assert token_proxy.address == event['token_address'].decode('hex')

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
    )

    transaction_hash = channel_manager_proxy.newChannel.transact(
        addresses[1],
        10,
        gasprice=denoms.wei,
    )
    jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=poll_timeout)

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
def test_channel_with_self(raiden_network, settle_timeout, blockchain_type):
    app0, = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    token_address = app0.raiden.default_registry.token_addresses()[0]

    assert len(app0.raiden.token_to_channelgraph[token_address].address_to_channel) == 0

    graph0 = app0.raiden.default_registry.manager_by_token(token_address)

    with pytest.raises(SamePeerAddress) as excinfo:
        graph0.new_netting_channel(
            app0.raiden.address,
            app0.raiden.address,
            settle_timeout,
        )
        assert 'Peer1 and peer2 must not be equal' in str(excinfo.value)

    if blockchain_type == 'tester':
        with pytest.raises(TransactionFailed):
            graph0.proxy.newChannel(app0.raiden.address, settle_timeout)
    else:
        tx = graph0.proxy.newChannel(app0.raiden.address, settle_timeout)
        # wait to make sure we get the receipt
        wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + 5)
        assert check_transaction_threw(app0.raiden.chain.client, tx)
