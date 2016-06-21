# -*- coding: utf8 -*-
import random
import string

import pytest
from ethereum import slogging
from ethereum import _solidity
from ethereum.keys import privtoaddr
from ethereum._solidity import compile_file
from pyethapp.accounts import mk_privkey
from pyethapp.rpc_client import JSONRPCClient

from raiden.network.rpc.client import get_contract_path
from raiden.utils import isaddress

slogging.configure(':DEBUG')
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
    # pylint: disable=line-too-long,too-many-statements
    asset_address = make_address()
    peer1_address = make_address()
    peer2_address = make_address()
    peer3_address = make_address()

    contract_address = blockchain_service.new_channel_manager_contract(asset_address)
    assert isaddress(contract_address)

    # sanity
    assert blockchain_service.addresses_by_asset(asset_address) == []
    assert blockchain_service.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address,
    ) == []
    assert blockchain_service.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == []
    assert blockchain_service.nettingaddresses_by_asset_participant(
        asset_address,
        peer3_address
    ) == []

    # create one channel
    netting1_address = blockchain_service.new_netting_contract(
        asset_address,
        peer1_address,
        peer2_address,
        settle_timeout,
    )

    # check contract state
    assert isaddress(netting1_address)
    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.partner(asset_address, netting1_address, peer1_address) == peer2_address
    assert blockchain_service.partner(asset_address, netting1_address, peer2_address) == peer1_address

    # check channels
    assert sorted(blockchain_service.addresses_by_asset(asset_address)[0]) == sorted([peer1_address, peer2_address])

    assert blockchain_service.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address
    ) == [netting1_address]
    assert blockchain_service.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == [netting1_address]
    assert blockchain_service.nettingaddresses_by_asset_participant(asset_address, peer3_address) == []

    # cant recreate the existing channel
    with pytest.raises(Exception):
        blockchain_service.new_netting_contract(
            asset_address,
            peer1_address,
            peer2_address,
            settle_timeout,
        )

    # create other chanel
    netting2_address = blockchain_service.new_netting_contract(
        asset_address,
        peer1_address,
        peer3_address,
        settle_timeout,
    )

    assert isaddress(netting2_address)
    assert blockchain_service.isopen(asset_address, netting2_address) is False
    assert blockchain_service.partner(asset_address, netting2_address, peer1_address) == peer3_address
    assert blockchain_service.partner(asset_address, netting2_address, peer3_address) == peer1_address

    channel_list = blockchain_service.addresses_by_asset(asset_address)
    expected_channels = [
        sorted([peer1_address, peer2_address]),
        sorted([peer1_address, peer3_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    assert sorted(blockchain_service.nettingaddresses_by_asset_participant(asset_address, peer1_address)) == sorted([
        netting1_address,
        netting2_address,
    ])
    assert blockchain_service.nettingaddresses_by_asset_participant(asset_address, peer2_address) == [netting1_address]
    assert blockchain_service.nettingaddresses_by_asset_participant(asset_address, peer3_address) == [netting2_address]

    blockchain_service.deposit(asset_address, netting1_address, peer1_address, 100)
    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.isopen(asset_address, netting2_address) is False

    # with pytest.raises(Exception):
    #    blockchain_service.deposit(asset_address, netting1_address, peer1_address, 100)

    blockchain_service.deposit(asset_address, netting2_address, peer1_address, 70)
    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.isopen(asset_address, netting2_address) is False

    blockchain_service.deposit(asset_address, netting1_address, peer2_address, 130)
    assert blockchain_service.isopen(asset_address, netting1_address) is True
    assert blockchain_service.isopen(asset_address, netting2_address) is False

    # we need to allow the settlement of the channel even if no transfers were
    # made
    peer1_last_sent_transfer = None
    peer2_last_sent_transfer = None

    blockchain_service.close(
        asset_address,
        netting1_address,
        peer1_address,
        peer1_last_sent_transfer,
        peer2_last_sent_transfer,
    )

    # with pytest.raises(Exception):
    #     blockchain_service.close(asset_address, netting2_address, peer1_address, peer1_last_sent_transfers)

    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.isopen(asset_address, netting2_address) is False

    blockchain_service.deposit(asset_address, netting2_address, peer3_address, 21)

    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.isopen(asset_address, netting2_address) is True

    blockchain_service.update_transfer(asset_address, netting1_address, peer2_address, peer2_last_sent_transfer)

    assert blockchain_service.isopen(asset_address, netting1_address) is False
    assert blockchain_service.isopen(asset_address, netting2_address) is True


@pytest.mark.xfail(reason='flaky test')  # this test has timeout issues that need to be fixed
@pytest.mark.parametrize('privatekey_seed', ['blockchain:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('timeout', [3])
def test_blockchain(private_keys, hydrachain_network, timeout):
    # pylint: disable=too-many-locals
    addresses = [
        privtoaddr(priv)
        for priv in private_keys
    ]

    privatekey_hex = hydrachain_network[0].config['node']['privkey_hex']
    privatekey = privatekey_hex.decode('hex')
    address = privtoaddr(privatekey)

    jsonrpc_client = JSONRPCClient(
        privkey=privatekey,
        print_communication=False,
    )

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        dict(),
        (9999, 'raiden', 2, 'Rd'),
        timeout=timeout,
    )

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_file(registry_path, libraries=dict())
    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'Registry',
        registry_contracts,
        dict(),
        tuple(),
        timeout=timeout,
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

    assert token_proxy.balanceOf(address) == 9999
    transaction_hash = registry_proxy.addAsset(token_proxy.address)
    jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=timeout)

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

    # pylint: disable=invalid-name
    log_channel_manager_address_encoded = log_list[0]['data']
    # remove 0x at the start
    log_channel_manager_address_encoded = log_channel_manager_address_encoded[2:]
    # remove the padding
    log_channel_manager_address_encoded = log_channel_manager_address_encoded.lstrip('0')
    # pad it back to the correct size
    log_channel_manager_address_encoded = log_channel_manager_address_encoded.rjust(40, '0')
    log_channel_manager_address = log_channel_manager_address_encoded.decode('hex')
    # pylint: enable=invalid-name

    assert channel_manager_address == log_channel_manager_address

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        registry_contracts['ChannelManagerContract']['abi'],
        channel_manager_address,
    )

    transaction_hash = channel_manager_proxy.newChannel(addresses[1], 10)
    jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=timeout)

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 2

    channel_manager_proxy.get.call(
        address.encode('hex'),
        addresses[1].encode('hex'),
    )
