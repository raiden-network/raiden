import itertools
import gevent

import pytest
from eth_utils import to_canonical_address, is_address, is_same_address


from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.blockchain.abi import (
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_MANAGER,
    CONTRACT_REGISTRY,
)
from raiden.exceptions import AddressWithoutCode, SamePeerAddress
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.network.proxies import Token, Registry, ChannelManager
from raiden.tests.utils.geth import wait_until_block
from raiden.transfer import views
from raiden.utils import privatekey_to_address, get_contract_path
from raiden.utils.filters import decode_event
from raiden.utils.solc import compile_files_cwd


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
    registry_address = app0.raiden.default_registry.address

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
    exception = RuntimeError("Timeout while waiting for a new channel")
    with gevent.Timeout(seconds=10, exception=exception):
        waiting.wait_for_newchannel(
            app1.raiden,
            registry_address,
            token_address,
            app0.raiden.address,
            app1.raiden.alarm.wait_time,
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
    netting_channel_01.set_total_deposit(100)
    assert netting_channel_01.can_transfer() is False
    assert netting_channel_02.can_transfer() is False
    assert netting_channel_01.detail()['our_balance'] == 0
    assert netting_channel_02.detail()['our_balance'] == 0

    # single-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_01, 100)
    netting_channel_01.set_total_deposit(100)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is False

    assert netting_channel_01.detail()['our_balance'] == 100
    assert netting_channel_02.detail()['our_balance'] == 0

    # double-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_02, 70)
    netting_channel_02.set_total_deposit(70)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 0

    app2.raiden.chain.token(token_address).approve(netting_address_02, 130)
    app2.raiden.chain.netting_channel(netting_address_02).set_total_deposit(130)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 130

    wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + 2)
    RaidenAPI(app1.raiden).channel_close(registry_address, token_address, app0.raiden.address)

    waiting.wait_for_settle(
        app1.raiden,
        registry_address,
        token_address,
        [netting_address_01],
        app1.raiden.alarm.wait_time,
    )

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
    netting_channel_01_reopened.set_total_deposit(100)
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


@pytest.mark.parametrize('number_of_nodes', [3])
def test_blockchain(
        web3,
        blockchain_rpc_ports,
        private_keys,
):
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
        web3=web3,
    )

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_files_cwd([humantoken_path])
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        'HumanStandardToken',
        humantoken_contracts,
        list(),
        (total_token, 'raiden', 2, 'Rd'),
        contract_path=humantoken_path,
    )
    token_proxy = Token(jsonrpc_client, to_canonical_address(token_proxy.contract.address))

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_files_cwd([registry_path])
    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        'Registry',
        registry_contracts,
        list(),
        tuple(),
        contract_path=registry_path,
    )
    registry_proxy = Registry(
        jsonrpc_client,
        to_canonical_address(registry_proxy.contract.address),
    )

    log_list = jsonrpc_client.web3.eth.getLogs(
        {
            'fromBlock': 0,
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert not log_list

    assert token_proxy.balance_of(address) == total_token
    manager_address = registry_proxy.add_token(
        to_canonical_address(token_proxy.proxy.contract.address),
    )
    assert is_address(manager_address)
    assert len(registry_proxy.token_addresses()) == 1

    log_list = jsonrpc_client.web3.eth.getLogs(
        {
            'fromBlock': 0,
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 1

    channel_manager_address_encoded = registry_proxy.manager_address_by_token(
        token_proxy.proxy.contract.address,
    )
    channel_manager_address = to_canonical_address(channel_manager_address_encoded)

    log = log_list[0]
    event = decode_event(CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY), log)
    event_args = event['args']

    assert channel_manager_address == to_canonical_address(event_args['channel_manager_address'])
    assert is_same_address(token_proxy.proxy.contract.address, event_args['token_address'])

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
    )
    channel_manager_proxy = ChannelManager(
        jsonrpc_client,
        to_canonical_address(channel_manager_proxy.contract.address),
    )

    channel_address = channel_manager_proxy.new_netting_channel(
        addresses[1],
        10,
    )
    assert is_address(channel_address)

    log_list = jsonrpc_client.web3.eth.getLogs(
        {
            'fromBlock': 0,
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 2


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_with_self(raiden_network, settle_timeout, token_addresses):
    app0, = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    current_chanels = views.list_channelstate_for_tokennetwork(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    assert not current_chanels

    graph0 = app0.raiden.default_registry.manager_by_token(token_address)

    with pytest.raises(SamePeerAddress) as excinfo:
        graph0.new_netting_channel(
            app0.raiden.address,
            settle_timeout,
        )

    assert 'The other peer must not have the same address as the client.' in str(excinfo.value)

    transaction_hash = graph0.proxy.transact('newChannel', app0.raiden.address, settle_timeout)

    # wait to make sure we get the receipt
    wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + 5)
    assert check_transaction_threw(app0.raiden.chain.client, transaction_hash)
