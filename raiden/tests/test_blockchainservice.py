# -*- coding: utf8 -*-
import os
import random
import string
import tempfile

import pytest
import gevent
import gevent.monkey
from devp2p.crypto import privtopub
from devp2p.utils import host_port_pubkey_to_uri
from ethereum import slogging
from ethereum import _solidity
from ethereum.keys import privtoaddr, PBKDF2_CONSTANTS
from ethereum.utils import denoms
from pyethapp.accounts import mk_privkey, Account
from pyethapp.rpc_client import JSONRPCClient

from raiden.network.rpc.client import BlockChainServiceMock, get_contract_path, get_code_signature
from raiden.utils import isaddress

gevent.monkey.patch_all()
slogging.configure(':debug')
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


def hydrachain_network(quantity, base_port, base_datadir):
    # pylint: disable=too-many-locals
    from hydrachain.app import services, start_app, HPCApp
    import pyethapp.config as konfig

    def privkey_to_uri(private_key):
        host = b'0.0.0.0'
        pubkey = privtopub(private_key)
        return host_port_pubkey_to_uri(host, base_port, pubkey)

    private_keys = [
        mk_privkey('raidentest:{}'.format(position))
        for position in range(quantity)
    ]

    bootstrap_nodes = [
        privkey_to_uri(private_keys[0]),
    ]

    validator_keys = [
        mk_privkey('raidenvalidator:{}'.format(position))
        for position in range(quantity)
    ]

    validator_addresses = [
        privtoaddr(validator_keys[position])
        for position in range(quantity)
    ]

    all_apps = []
    for number in range(quantity):
        port = base_port + number

        config = konfig.get_default_config(services + [HPCApp])

        datadir = os.path.join(base_datadir, str(number))
        konfig.setup_data_dir(datadir)

        account = Account.new(
            password='',
            key=validator_keys[number],
        )

        config['data_dir'] = datadir
        config['node']['privkey_hex'] = private_keys[number].encode('hex')
        config['hdc']['validators'] = validator_addresses
        config['jsonrpc']['listen_port'] += number
        config['client_version_string'] = 'NODE{}'.format(number)

        config['discovery']['bootstrap_nodes'] = bootstrap_nodes
        config['discovery']['listen_port'] = port

        config['p2p']['listen_port'] = port
        config['p2p']['min_peers'] = min(10, quantity - 1)
        config['p2p']['max_peers'] = quantity * 2

        hydrachain_app = start_app(config, accounts=[account])
        all_apps.append(hydrachain_app)

    return private_keys, all_apps


def deploy_contract(jsonrpc_client, sender, bytecode):
    transaction_hash = jsonrpc_client.send_transaction(
        sender,
        to='',
        data=bytecode,
        gasprice=denoms.wei,
    )

    gevent.sleep(1)  # let hydrachain work

    jsonrpc_client.poll(transaction_hash.decode('hex'))
    receipt = jsonrpc_client.call('eth_getTransactionReceipt', '0x' + transaction_hash)
    return receipt


def test_blockchain():
    # pylint: disable=too-many-locals
    from hydrachain import app
    app.slogging.configure(':ERRROR,jsonrpc:DEBUG')
    PBKDF2_CONSTANTS['c'] = 100
    gevent.get_hub().SYSTEM_ERROR = BaseException

    quantity = 3
    base_port = 29870
    tmp_datadir = tempfile.mktemp()

    private_keys, hydrachain_apps = hydrachain_network(quantity, base_port, tmp_datadir)

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)

    jsonrpc_client = JSONRPCClient(privkey=private_keys[0])

    token_path = get_contract_path('Token.sol')
    token_code, _ = get_code_signature(token_path)
    token_receipt = deploy_contract(jsonrpc_client, address, token_code)

    standardtoken_libraries = {
        'Token': token_receipt['address'],
    }
    standardtoken_path = get_contract_path('StandardToken.sol')
    standardtoken_code, _ = get_code_signature(
        standardtoken_path,
        libraries=standardtoken_libraries,
    )
    standardtoken_receipt = deploy_contract(jsonrpc_client, address, standardtoken_code)

    humantoken_libraries = {
        'StandardToken': standardtoken_receipt['address'],
        'Token': token_receipt['address'],
    }
    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_code, humantoken_signature = get_code_signature(
        humantoken_path,
        libraries=humantoken_libraries,
    )
    humantoken_receipt = deploy_contract(jsonrpc_client, address, humantoken_code)

    token_abi = jsonrpc_client.new_abi_contract(
        humantoken_signature,
        humantoken_receipt['contractAddress'],
    )
    assert token_abi.balanceOf(address) > 0  # pylint: disable=no-member

    for hydrachain in hydrachain_apps:
        hydrachain.stop()
