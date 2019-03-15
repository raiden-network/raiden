from copy import copy
from unittest.mock import Mock, patch

import pytest
import requests
from eth_utils import to_checksum_address

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import get_pfs_info, get_pfs_iou, update_iou
from raiden.routing import get_best_routes
from raiden.tests.utils import factories
from raiden.transfer import token_network
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NettingChannelState,
    TokenNetworkState,
)
from raiden.transfer.state_change import ContractReceiveChannelNew, ContractReceiveRouteNew
from raiden.utils import typing


def create_square_network_topology(
        token_network_state,
        our_address,
) -> typing.Tuple[
    TokenNetworkState,
    typing.List[typing.Address],
    typing.List[NettingChannelState],
]:
    open_block_number = 10
    open_block_hash = factories.make_block_hash()
    address1 = factories.make_address()
    address2 = factories.make_address()
    address3 = factories.make_address()

    # Create a network with the following topology
    #
    # our  ----- 50 ---->  (1)
    #  |                    ^
    #  |                    |
    # 100                  100
    #  |                    |
    #  v                    |
    # (2)  ----- 100 --->  (3)

    channel_state1 = factories.make_channel(
        our_balance=50,
        our_address=our_address,
        partner_balance=0,
        partner_address=address1,
    )
    channel_state2 = factories.make_channel(
        our_balance=100,
        our_address=our_address,
        partner_balance=0,
        partner_address=address2,
    )

    # create new channels as participant
    channel_new_state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state1,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )
    channel_new_state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state2,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration1 = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change1,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration2 = token_network.state_transition(
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change2,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    graph_state = channel_new_iteration2.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 2
    assert len(graph_state.network.edges()) == 2

    # create new channels without being participant
    channel_new_state_change3 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address,
            channel_identifier=3,
        ),
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration3 = token_network.state_transition(
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_new_state_change3,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
    )

    graph_state = channel_new_iteration3.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 3
    assert len(graph_state.network.edges()) == 3

    channel_new_state_change4 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address,
            channel_identifier=4,
        ),
        participant1=address3,
        participant2=address1,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )
    channel_new_iteration4 = token_network.state_transition(
        token_network_state=channel_new_iteration3.new_state,
        state_change=channel_new_state_change4,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
    )

    graph_state = channel_new_iteration4.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 4
    assert len(graph_state.network.edges()) == 4

    return (
        channel_new_iteration4.new_state,
        [address1, address2, address3],
        (channel_state1, channel_state2),
    )


CONFIG = {
    'services': {
        'pathfinding_service_address': 'my-pfs',
        'pathfinding_eth_address': to_checksum_address(factories.make_address()),
        'pathfinding_max_paths': 3,
        'pathfinding_iou_timeout': 10,
        'pathfinding_max_fee': 50,
    },
}

PRIVKEY = b'privkeyprivkeyprivkeyprivkeypriv'


def get_best_routes_with_iou_request_mocked(
        chain_state,
        token_network_state,
        from_address,
        to_address,
        amount,
        iou_json_data=None,
):
    iou_response = Mock()
    iou_response.configure_mock(status_code=200)
    iou_response.json = Mock(return_value=iou_json_data or {})

    with patch.object(requests, 'get', return_value=iou_response):
        return get_best_routes(
            chain_state=chain_state,
            token_network_id=token_network_state.address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=None,
            config=CONFIG,
            privkey=PRIVKEY,
        )


def test_get_pfs_info_success():
    json_data = {
        'price_info': 0,
        'network_info': {
            'chain_id': 1,
            'registry_address': '0xB9633dd9a9a71F22C933bF121d7a22008f66B908',
        },
        'message': 'This is your favorite pathfinding service',
        'operator': 'John Doe',
        'version': '0.0.1',
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)

    with patch.object(requests, 'get', return_value=response):
        pathfinding_service_info = get_pfs_info('url')

        req_registry_address = '0xB9633dd9a9a71F22C933bF121d7a22008f66B908'
        assert pathfinding_service_info['price_info'] == 0
        assert pathfinding_service_info['network_info']['chain_id'] == 1
        assert pathfinding_service_info['network_info']['registry_address'] == req_registry_address
        assert pathfinding_service_info['message'] == 'This is your favorite pathfinding service'
        assert pathfinding_service_info['operator'] == 'John Doe'
        assert pathfinding_service_info['version'] == '0.0.1'


def test_get_pfs_info_request_error():
    response = Mock()
    response.configure_mock(status_code=400)

    with patch.object(requests, 'get', side_effect=requests.RequestException()):
        pathfinding_service_info = get_pfs_info('url')

    assert pathfinding_service_info is None


@pytest.fixture
def happy_path_fixture(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses

    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    # channel 1 and 2 are flipped here, to see when the PFS gets called
    json_data = {
        'result': [
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address2)],
                'fees': 0,
            },
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address1)],
                'fees': 0,
            },
        ],
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)

    return addresses, chain_state, channel_states, response, token_network_state


def test_routing_mocked_pfs_happy_path(
        happy_path_fixture,
        our_address,
):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    address1, address2, _ = addresses
    channel_state1, channel_state2 = channel_states

    with patch.object(requests, 'post', return_value=response) as patched:
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )

    assert routes[0].node_address == address2
    assert routes[0].channel_identifier == channel_state2.identifier
    assert routes[1].node_address == address1
    assert routes[1].channel_identifier == channel_state1.identifier

    # Check for iou arguments in request payload
    payload = patched.call_args[1]['data']
    config = CONFIG['services']
    assert all(
        k in payload
        for k in ('amount', 'expiration_block', 'signature', 'sender', 'receiver')
    )
    assert payload['amount'] <= config['pathfinding_max_fee']
    latest_expected_expiration = config['pathfinding_iou_timeout'] + chain_state.block_number
    assert payload['expiration_block'] <= latest_expected_expiration


def test_routing_mocked_pfs_happy_path_with_updated_iou(
        happy_path_fixture,
        our_address,
):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    address1, address2, _ = addresses
    channel_state1, channel_state2 = channel_states

    iou = dict(
        amount=13,
        expiration_block=110,
        sender=to_checksum_address(our_address),
        receiver=to_checksum_address(factories.UNIT_TRANSFER_TARGET),
    )
    last_iou = copy(iou)

    with patch.object(requests, 'post', return_value=response) as patched:
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
            iou_json_data=dict(last_iou=iou),
        )

    assert routes[0].node_address == address2
    assert routes[0].channel_identifier == channel_state2.identifier
    assert routes[1].node_address == address1
    assert routes[1].channel_identifier == channel_state1.identifier

    # Check for iou arguments in request payload
    payload = patched.call_args[1]['data']
    config = CONFIG['services']
    old_amount = last_iou['amount']
    assert old_amount < payload['amount'] <= config['pathfinding_max_fee'] + old_amount
    assert all(
        payload[k] == last_iou[k]
        for k in ('expiration_block', 'sender', 'receiver')
    )
    assert 'signature' in payload


def test_routing_mocked_pfs_request_error(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses
    channel_state1, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    with patch.object(requests, 'post', side_effect=requests.RequestException()):
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )
        assert routes[0].node_address == address1
        assert routes[0].channel_identifier == channel_state1.identifier
        assert routes[1].node_address == address2
        assert routes[1].channel_identifier == channel_state2.identifier


def test_routing_mocked_pfs_bad_http_code(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses
    channel_state1, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    # channel 1 and 2 are flipped here, to see when the PFS gets called
    json_data = {
        'result': [
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address2)],
                'fees': 0,
            },
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address1)],
                'fees': 0,
            },
        ],
    }

    response = Mock()
    response.configure_mock(status_code=400)
    response.json = Mock(return_value=json_data)

    with patch.object(requests, 'post', return_value=response):
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )
        assert routes[0].node_address == address1
        assert routes[0].channel_identifier == channel_state1.identifier
        assert routes[1].node_address == address2
        assert routes[1].channel_identifier == channel_state2.identifier


def test_routing_mocked_pfs_invalid_json(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses
    channel_state1, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(side_effect=ValueError())

    with patch.object(requests, 'post', return_value=response):
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )
        assert routes[0].node_address == address1
        assert routes[0].channel_identifier == channel_state1.identifier
        assert routes[1].node_address == address2
        assert routes[1].channel_identifier == channel_state2.identifier


def test_routing_mocked_pfs_invalid_json_structure(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses
    channel_state1, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    response = Mock()
    response.configure_mock(status_code=400)
    response.json = Mock(return_value={})

    with patch.object(requests, 'post', return_value=response):
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )
        assert routes[0].node_address == address1
        assert routes[0].channel_identifier == channel_state1.identifier
        assert routes[1].node_address == address2
        assert routes[1].channel_identifier == channel_state2.identifier


def test_routing_mocked_pfs_unavailable_peer(
        chain_state,
        token_network_state,
        our_address,
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state,
        our_address=our_address,
    )
    address1, address2, address3 = addresses
    _, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    # channel 1 and 2 are flipped here, to see when the PFS gets called
    json_data = {
        'result': [
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address2)],
                'fees': 0,
            },
            {
                'path': [to_checksum_address(our_address), to_checksum_address(address1)],
                'fees': 0,
            },
        ],
    }

    # test routing with node 2 unavailable
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_UNREACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)
    with patch.object(requests, 'post', return_value=response):
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )

    assert routes[0].node_address == address2
    assert routes[0].channel_identifier == channel_state2.identifier


def test_get_and_update_iou():

    # RequestExceptions should be reraised as ServiceRequestFailed
    with pytest.raises(ServiceRequestFailed):
        with patch.object(requests, 'get', side_effect=requests.RequestException):
            get_pfs_iou('url', factories.UNIT_TOKEN_NETWORK_ADDRESS)

    # invalid JSON should raise a ServiceRequestFailed
    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(side_effect=ValueError)
    with pytest.raises(ServiceRequestFailed):
        with patch.object(requests, 'get', return_value=response):
            get_pfs_iou('url', factories.UNIT_TOKEN_NETWORK_ADDRESS)

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value={'other_key': 'other_value'})
    with patch.object(requests, 'get', return_value=response):
        iou = get_pfs_iou('url', factories.UNIT_TOKEN_NETWORK_ADDRESS)
    assert iou is None, 'get_pfs_iou should return None if pfs returns no iou.'

    response = Mock()
    response.configure_mock(status_code=200)
    last_iou = dict(
        amount=7,
        sender=to_checksum_address(factories.UNIT_TRANSFER_INITIATOR),
        receiver=to_checksum_address(factories.UNIT_TRANSFER_TARGET),
        expiration_block=42,
    )
    response.json = Mock(return_value=dict(last_iou=last_iou))
    with patch.object(requests, 'get', return_value=response):
        iou = get_pfs_iou('url', factories.UNIT_TOKEN_NETWORK_ADDRESS)
    assert iou == last_iou

    new_iou_1 = update_iou(iou, PRIVKEY, added_amount=10)
    assert new_iou_1['amount'] == 17
    assert all(new_iou_1[k] == iou[k] for k in ('expiration_block', 'sender', 'receiver'))
    assert 'signature' in new_iou_1

    new_iou_2 = update_iou(iou, PRIVKEY, expiration_block=45)
    assert new_iou_2['expiration_block'] == 45
    assert all(new_iou_2[k] == iou[k] for k in ('amount', 'sender', 'receiver'))
    assert 'signature' in new_iou_2
