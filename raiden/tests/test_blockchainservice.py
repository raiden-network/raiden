# -*- coding: utf8 -*-
import random
import string
import tempfile

import pytest
import gevent
import gevent.monkey
from ethereum import slogging
from ethereum import _solidity
from ethereum.keys import privtoaddr
from ethereum._solidity import compile_file
from pyethapp.accounts import mk_privkey
from pyethapp.rpc_client import JSONRPCClient

from raiden.network.rpc.client import BlockChainServiceMock, get_contract_path
from raiden.utils import isaddress
from raiden.tests.utils.network import hydrachain_network

# Monkey patch subprocess.Popen used by solidity wrapper
gevent.monkey.patch_socket()  # patch_subprocess()

slogging.configure(':debug')
solidity = _solidity.get_solidity()   # pylint: disable=invalid-name

LETTERS = string.printable


def teardown_module(module):  # pylint: disable=unused-argument
    from raiden.tests.utils.tests import cleanup_tasks
    cleanup_tasks()


def addr(seed):
    return privtoaddr(privkey(seed))


def privkey(seed):
    return mk_privkey('42:account:{seed}'.format(seed=seed))


def make_address():
    return ''.join(random.choice(LETTERS) for _ in range(20))


ADDR = addr('0')
xADDR = '0x' + ADDR.encode('hex')  # pylint: disable=invalid-name
PRIVKEY = privkey('0')


def test_new_netting_contract():
    # pylint: disable=line-too-long,too-many-statements
    client = BlockChainServiceMock()

    asset_address = make_address()
    peer1_address = make_address()
    peer2_address = make_address()
    peer3_address = make_address()

    contract_address = client.new_channel_manager_contract(asset_address)
    assert isaddress(contract_address)

    # sanity
    assert client.addresses_by_asset(asset_address) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address,
    ) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer3_address
    ) == []

    # create one channel
    netting1_address = client.new_netting_contract(asset_address, peer1_address, peer2_address)

    # check contract state
    assert isaddress(netting1_address)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.partner(asset_address, netting1_address, peer1_address) == peer2_address
    assert client.partner(asset_address, netting1_address, peer2_address) == peer1_address

    # check channels
    assert sorted(client.addresses_by_asset(asset_address)[0]) == sorted([peer1_address, peer2_address])

    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address
    ) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(asset_address, peer3_address) == []

    # cant recreate the existing channel
    with pytest.raises(Exception):
        client.new_netting_contract(asset_address, peer1_address, peer2_address)

    # create other chanel
    netting2_address = client.new_netting_contract(asset_address, peer1_address, peer3_address)

    assert isaddress(netting2_address)
    assert client.isopen(asset_address, netting2_address) is False
    assert client.partner(asset_address, netting2_address, peer1_address) == peer3_address
    assert client.partner(asset_address, netting2_address, peer3_address) == peer1_address

    channel_list = client.addresses_by_asset(asset_address)
    expected_channels = [
        sorted([peer1_address, peer2_address]),
        sorted([peer1_address, peer3_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    assert sorted(client.nettingaddresses_by_asset_participant(asset_address, peer1_address)) == sorted([
        netting1_address,
        netting2_address,
    ])
    assert client.nettingaddresses_by_asset_participant(asset_address, peer2_address) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(asset_address, peer3_address) == [netting2_address]

    client.deposit(asset_address, netting1_address, peer1_address, 100)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    # with pytest.raises(Exception):
    #    client.deposit(asset_address, netting1_address, peer1_address, 100)

    client.deposit(asset_address, netting2_address, peer1_address, 70)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    client.deposit(asset_address, netting1_address, peer2_address, 130)
    assert client.isopen(asset_address, netting1_address) is True
    assert client.isopen(asset_address, netting2_address) is False

    # we need to allow the settlement of the channel even if no transfers were
    # made
    peer1_last_sent_transfer = None
    peer2_last_sent_transfer = None

    client.close(
        asset_address,
        netting1_address,
        peer1_address,
        peer1_last_sent_transfer,
        peer2_last_sent_transfer,
    )

    # with pytest.raises(Exception):
    #     client.close(asset_address, netting2_address, peer1_address, peer1_last_sent_transfers)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    client.deposit(asset_address, netting2_address, peer3_address, 21)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is True

    client.update_transfer(asset_address, netting1_address, peer2_address, peer2_last_sent_transfer)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is True


@pytest.mark.xfail(reason='flaky test')  # this test has timeout issues that need to be fixed
def test_blockchain(request):
    # pylint: disable=too-many-locals
    from hydrachain import app
    app.slogging.configure(':ERROR')

    quantity = 3
    base_port = 29870
    timeout = 3  # seconds
    tmp_datadir = tempfile.mktemp()

    private_keys = [
        mk_privkey('raidentest:{}'.format(position))
        for position in range(quantity)
    ]

    addresses = [
        privtoaddr(priv)
        for priv in private_keys
    ]

    hydrachain_apps = hydrachain_network(private_keys, base_port, tmp_datadir)

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)

    jsonrpc_client = JSONRPCClient(privkey=private_keys[0], print_communication=False)

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_abi = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        dict(),
        (9999, 'raiden', 2, 'Rd'),
        timeout=timeout,
    )

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_file(registry_path, libraries=dict())
    registry_abi = jsonrpc_client.deploy_solidity_contract(
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

    assert token_abi.balanceOf(address) == 9999
    transaction_hash = registry_abi.addAsset(token_abi.address)
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

    channel_manager_address_encoded = registry_abi.channelManagerByAsset.call(token_abi.address)
    channel_manager_address = channel_manager_address_encoded.decode('hex')

    log_channel_manager_address_encoded = log_list[0]['data']
    log_channel_manager_address = log_channel_manager_address_encoded[2:].lstrip('0').rjust(40, '0').decode('hex')

    assert channel_manager_address == log_channel_manager_address

    channel_manager_abi = jsonrpc_client.new_contract_proxy(
        registry_contracts['ChannelManagerContract']['abi'],
        channel_manager_address,
    )

    transaction_hash = channel_manager_abi.newChannel(addresses[1], 10)
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

    channel_manager_abi.get.call(
        address.encode('hex'),
        addresses[1].encode('hex'),
    )
