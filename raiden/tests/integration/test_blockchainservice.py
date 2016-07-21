# -*- coding: utf8 -*-
import random
import string

import pytest
from ethereum import slogging
from ethereum import _solidity
from ethereum.keys import privtoaddr
from ethereum._solidity import compile_file
from ethereum.utils import denoms
from pyethapp.accounts import mk_privkey
from pyethapp.rpc_client import JSONRPCClient

from raiden.blockchain.abi import get_contract_path
from raiden.network.rpc.client import decode_topic, patch_send_transaction

slogging.configure(
    ':DEBUG'
    ',eth.chain.tx:DEBUG'
    ',jsonrpc:DEBUG'
    ',eth.vm:TRACE,eth.pb.tx:TRACE,eth.pb.msg:TRACE,eth.pb.msg.state:TRACE'
)
solidity = _solidity.get_solidity()   # pylint: disable=invalid-name

LETTERS = string.printable


def addr(seed):
    return privtoaddr(privkey(seed))


def privkey(seed):
    return mk_privkey('42:account:{seed}'.format(seed=seed))


def make_address():
    return ''.join(random.choice(LETTERS) for _ in range(20))


ADDR = addr('0')
xADDR = '0x' + ADDR.encode('hex')  # pylint: disable=invalid-name
PRIVKEY = privkey('0')


def test_new_netting_contract(blockchain_service, settle_timeout):
    # pylint: disable=line-too-long,too-many-statements,too-many-locals
    asset_address = make_address()
    peer1_address = make_address()
    peer2_address = make_address()
    peer3_address = make_address()

    blockchain_service.default_registry.add_asset(asset_address)
    manager = blockchain_service.manager_by_asset(asset_address)

    # sanity
    assert manager.channels_addresses() == []
    assert manager.channels_by_participant(peer1_address) == []
    assert manager.channels_by_participant(peer2_address) == []
    assert manager.channels_by_participant(peer3_address) == []

    # create one channel
    netting1_address = manager.new_netting_channel(
        peer1_address,
        peer2_address,
        settle_timeout,
    )

    # check contract state
    netting_channel1 = blockchain_service.netting_channel(netting1_address)
    assert netting_channel1.isopen() is False
    assert netting_channel1.partner(peer1_address) == peer2_address
    assert netting_channel1.partner(peer2_address) == peer1_address

    # check channels
    channel_list = manager.channels_addresses()
    assert sorted(channel_list[0]) == sorted([peer1_address, peer2_address])

    assert manager.channels_by_participant(peer1_address) == [netting1_address]
    assert manager.channels_by_participant(peer2_address) == [netting1_address]
    assert manager.channels_by_participant(peer3_address) == []

    # cant recreate the existing channel
    with pytest.raises(Exception):
        netting1_address = manager.new_netting_channel(
            peer1_address,
            peer2_address,
            settle_timeout,
        )

    # create other chanel
    netting2_address = manager.new_netting_channel(
        peer1_address,
        peer3_address,
        settle_timeout,
    )

    netting_channel2 = blockchain_service.netting_channel(netting2_address)

    assert netting_channel2.isopen() is False
    assert netting_channel2.partner(peer1_address) == peer3_address
    assert netting_channel2.partner(peer3_address) == peer1_address

    channel_list = manager.channels_addresses()
    expected_channels = [
        sorted([peer1_address, peer2_address]),
        sorted([peer1_address, peer3_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    assert manager.channels_by_participant(peer1_address) == [netting1_address, netting2_address]
    assert manager.channels_by_participant(peer2_address) == [netting1_address]
    assert manager.channels_by_participant(peer3_address) == [netting2_address]

    # single-funded channel
    netting_channel1.deposit(peer1_address, 100)
    assert netting_channel1.isopen() is True
    assert netting_channel2.isopen() is False

    # with pytest.raises(Exception):
    #    blockchain_service.deposit(asset_address, netting1_address, peer1_address, 100)

    netting_channel2.deposit(peer1_address, 70)
    assert netting_channel1.isopen() is True
    assert netting_channel2.isopen() is True

    netting_channel1.deposit(peer2_address, 130)
    assert netting_channel1.isopen() is True
    assert netting_channel2.isopen() is True

    # we need to allow the settlement of the channel even if no transfers were
    # made
    peer1_last_sent_transfer = None
    peer2_last_sent_transfer = None

    netting_channel1.close(
        peer1_address,
        peer1_last_sent_transfer,
        peer2_last_sent_transfer,
    )

    # with pytest.raises(Exception):
    #     blockchain_service.close(asset_address, netting2_address, peer1_address, peer1_last_sent_transfers)

    assert netting_channel1.isopen() is False
    assert netting_channel2.isopen() is True

    netting_channel2.deposit(peer3_address, 21)

    assert netting_channel1.isopen() is False
    assert netting_channel2.isopen() is True

    netting_channel1.update_transfer(peer2_address, peer2_last_sent_transfer)

    assert netting_channel1.isopen() is False
    assert netting_channel2.isopen() is True


@pytest.mark.parametrize('privatekey_seed', ['blockchain:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_blockchain(private_keys, number_of_nodes, cluster, poll_timeout):
    # pylint: disable=too-many-locals
    addresses = [
        privtoaddr(priv)
        for priv in private_keys
    ]

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)
    total_asset = 100

    jsonrpc_client = JSONRPCClient(
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(jsonrpc_client)

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        dict(),
        (total_asset, 'raiden', 2, 'Rd'),
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

    assert token_proxy.balanceOf(address) == total_asset
    transaction_hash = registry_proxy.addAsset.transact(
        token_proxy.address,
        gasprice=denoms.wei,
    )
    jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=poll_timeout)

    assert len(registry_proxy.assetAddresses.call()) == 1

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 1

    channel_manager_address_encoded = registry_proxy.channelManagerByAsset.call(token_proxy.address)
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

    assert channel_manager_address == event['assetAddress'].decode('hex')

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        registry_contracts['ChannelManagerContract']['abi'],
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
