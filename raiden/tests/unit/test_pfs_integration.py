from copy import copy
from unittest.mock import Mock, patch

import pytest
import requests
from eth_utils import encode_hex, is_checksum_address, is_hex, is_hex_address, to_checksum_address

from raiden.exceptions import ServiceRequestFailed, ServiceRequestIOURejected
from raiden.network.pathfinding import (
    MAX_PATHS_QUERY_ATTEMPTS,
    PFSError,
    get_last_iou,
    get_pfs_info,
    make_iou,
    query_paths,
    update_iou,
)
from raiden.routing import get_best_routes
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import patched_get_for_succesful_pfs_info
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NettingChannelState,
    TokenNetworkState,
)
from raiden.utils import privatekey_to_address, typing
from raiden.utils.typing import Address, TokenNetworkAddress
from raiden_contracts.utils.proofs import sign_one_to_n_iou


def assert_checksum_address_in_url(url):
    message = "URL does not contain properly encoded address."
    assert any(is_checksum_address(token) for token in url.split("/")), message


def create_square_network_topology(
    token_network_state, our_address
) -> typing.Tuple[
    TokenNetworkState, typing.List[typing.Address], typing.List[NettingChannelState]
]:
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

    routes = [
        factories.RouteProperties(address1=our_address, address2=address1, capacity1to2=50),
        factories.RouteProperties(address1=our_address, address2=address2, capacity1to2=100),
        factories.RouteProperties(address1=address2, address2=address3, capacity1to2=100),
        factories.RouteProperties(address1=address3, address2=address1, capacity1to2=100),
    ]

    new_state, channels = factories.create_network(
        token_network_state=token_network_state,
        our_address=our_address,
        routes=routes,
        block_number=10,
    )

    return (new_state, [address1, address2, address3], channels)


CONFIG = {
    "services": {
        "pathfinding_service_address": "my-pfs",
        "pathfinding_eth_address": factories.make_checksum_address(),
        "pathfinding_max_paths": 3,
        "pathfinding_iou_timeout": 10,
        "pathfinding_max_fee": 50,
    }
}

PRIVKEY = b"privkeyprivkeyprivkeyprivkeypriv"


def get_best_routes_with_iou_request_mocked(
    chain_state, token_network_state, from_address, to_address, amount, iou_json_data=None
):
    def iou_side_effect(*_, **kwargs):
        assert "params" in kwargs
        body = kwargs["params"]

        assert is_hex_address(body["sender"])
        assert is_hex_address(body["receiver"])
        assert "timestamp" in body
        assert is_hex(body["signature"])
        assert len(body["signature"]) == 65 * 2 + 2  # 65 hex encoded bytes with 0x prefix

        return Mock(json=Mock(return_value=iou_json_data or {}), status_code=200)

    with patch.object(requests, "get", side_effect=iou_side_effect) as patched:
        best_routes = get_best_routes(
            chain_state=chain_state,
            token_network_id=token_network_state.address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=None,
            config=CONFIG,
            privkey=PRIVKEY,
        )
        assert_checksum_address_in_url(patched.call_args[0][0])
        return best_routes


def test_get_pfs_info_success():
    json_data = {
        "price_info": 0,
        "network_info": {
            "chain_id": 1,
            "registry_address": "0xB9633dd9a9a71F22C933bF121d7a22008f66B908",
        },
        "message": "This is your favorite pathfinding service",
        "operator": "John Doe",
        "version": "0.0.1",
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)

    with patched_get_for_succesful_pfs_info():
        pathfinding_service_info = get_pfs_info("url")

        req_registry_address = "0xB9633dd9a9a71F22C933bF121d7a22008f66B908"
        assert pathfinding_service_info["price_info"] == 0
        assert pathfinding_service_info["network_info"]["chain_id"] == 1
        assert pathfinding_service_info["network_info"]["registry_address"] == req_registry_address
        assert pathfinding_service_info["message"] == "This is your favorite pathfinding service"
        assert pathfinding_service_info["operator"] == "John Doe"
        assert pathfinding_service_info["version"] == "0.0.1"


def test_get_pfs_info_request_error():
    response = Mock()
    response.configure_mock(status_code=400)

    with patch.object(requests, "get", side_effect=requests.RequestException()):
        pathfinding_service_info = get_pfs_info("url")

    assert pathfinding_service_info is None


@pytest.fixture
def happy_path_fixture(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3 = addresses

    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    # channel 1 and 2 are flipped here, to see when the PFS gets called
    json_data = {
        "result": [
            {"path": [to_checksum_address(our_address), to_checksum_address(address2)], "fees": 0},
            {"path": [to_checksum_address(our_address), to_checksum_address(address1)], "fees": 0},
        ]
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)

    return addresses, chain_state, channel_states, response, token_network_state


def test_routing_mocked_pfs_happy_path(happy_path_fixture, our_address):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    address1, address2, _ = addresses
    channel_state1, channel_state2 = channel_states

    with patch.object(requests, "post", return_value=response) as patched:
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].node_address == address2
    assert routes[0].channel_identifier == channel_state2.identifier
    assert routes[1].node_address == address1
    assert routes[1].channel_identifier == channel_state1.identifier

    # Check for iou arguments in request payload
    iou = patched.call_args[1]["json"]["iou"]
    config = CONFIG["services"]
    for key in ("amount", "expiration_block", "signature", "sender", "receiver"):
        assert key in iou
    assert iou["amount"] <= config["pathfinding_max_fee"]
    latest_expected_expiration = config["pathfinding_iou_timeout"] + chain_state.block_number
    assert iou["expiration_block"] <= latest_expected_expiration


def test_routing_mocked_pfs_happy_path_with_updated_iou(happy_path_fixture, our_address):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    address1, address2, _ = addresses
    channel_state1, channel_state2 = channel_states

    iou = make_iou(
        config=dict(
            pathfinding_eth_address=to_checksum_address(factories.UNIT_TRANSFER_TARGET),
            pathfinding_iou_timeout=100,
            pathfinding_max_fee=13,
        ),
        our_address=factories.UNIT_TRANSFER_SENDER,
        privkey=PRIVKEY,
        block_number=10,
    )
    last_iou = copy(iou)

    with patch.object(requests, "post", return_value=response) as patched:
        routes = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            from_address=our_address,
            to_address=address1,
            amount=50,
            iou_json_data=dict(last_iou=iou),
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].node_address == address2
    assert routes[0].channel_identifier == channel_state2.identifier
    assert routes[1].node_address == address1
    assert routes[1].channel_identifier == channel_state1.identifier

    # Check for iou arguments in request payload
    payload = patched.call_args[1]["json"]
    config = CONFIG["services"]
    old_amount = last_iou["amount"]
    assert old_amount < payload["iou"]["amount"] <= config["pathfinding_max_fee"] + old_amount
    for key in ("expiration_block", "sender", "receiver"):
        assert payload["iou"][key] == last_iou[key]
    assert "signature" in payload["iou"]


def test_routing_mocked_pfs_request_error(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3 = addresses
    channel_state1, channel_state2 = channel_states

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    with patch.object(requests, "post", side_effect=requests.RequestException()):
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


def test_routing_mocked_pfs_bad_http_code(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
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
        "result": [
            {"path": [to_checksum_address(our_address), to_checksum_address(address2)], "fees": 0},
            {"path": [to_checksum_address(our_address), to_checksum_address(address1)], "fees": 0},
        ]
    }

    response = Mock()
    response.configure_mock(status_code=400)
    response.json = Mock(return_value=json_data)

    with patch.object(requests, "post", return_value=response):
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


def test_routing_mocked_pfs_invalid_json(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
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

    with patch.object(requests, "post", return_value=response):
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


def test_routing_mocked_pfs_invalid_json_structure(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
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

    with patch.object(requests, "post", return_value=response):
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


def test_routing_mocked_pfs_unavailable_peer(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
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
        "result": [
            {"path": [to_checksum_address(our_address), to_checksum_address(address2)], "fees": 0},
            {"path": [to_checksum_address(our_address), to_checksum_address(address1)], "fees": 0},
        ]
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
    with patch.object(requests, "post", return_value=response):
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

    request_args = dict(
        url="url",
        token_network_address=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        sender=factories.make_address(),
        receiver=factories.make_address(),
        privkey=PRIVKEY,
    )
    # RequestExceptions should be reraised as ServiceRequestFailed
    with pytest.raises(ServiceRequestFailed):
        with patch.object(requests, "get", side_effect=requests.RequestException):
            get_last_iou(**request_args)

    # invalid JSON should raise a ServiceRequestFailed
    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(side_effect=ValueError)
    with pytest.raises(ServiceRequestFailed):
        with patch.object(requests, "get", return_value=response):
            get_last_iou(**request_args)

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value={"other_key": "other_value"})
    with patch.object(requests, "get", return_value=response):
        iou = get_last_iou(**request_args)
    assert iou is None, "get_pfs_iou should return None if pfs returns no iou."

    response = Mock()
    response.configure_mock(status_code=200)
    last_iou = make_iou(
        config=dict(
            pathfinding_eth_address=to_checksum_address(factories.UNIT_TRANSFER_TARGET),
            pathfinding_iou_timeout=500,
            pathfinding_max_fee=100,
        ),
        our_address=factories.UNIT_TRANSFER_INITIATOR,
        privkey=PRIVKEY,
        block_number=10,
    )
    response.json = Mock(return_value=dict(last_iou=last_iou))
    with patch.object(requests, "get", return_value=response):
        iou = get_last_iou(**request_args)
    assert iou == last_iou

    new_iou_1 = update_iou(iou.copy(), PRIVKEY, added_amount=10)
    assert new_iou_1["amount"] == last_iou["amount"] + 10
    for key in ("expiration_block", "sender", "receiver"):
        assert new_iou_1[key] == iou[key]
    assert is_hex(new_iou_1["signature"])

    new_iou_2 = update_iou(iou, PRIVKEY, expiration_block=45)
    assert new_iou_2["expiration_block"] == 45
    for key in ("amount", "sender", "receiver"):
        assert new_iou_2[key] == iou[key]
    assert all(new_iou_2[k] == iou[k] for k in ("amount", "sender", "receiver"))
    assert is_hex(new_iou_2["signature"])


def test_get_pfs_iou():
    token_network_address = TokenNetworkAddress(bytes([1] * 20))
    privkey = bytes([2] * 32)
    sender = privatekey_to_address(privkey)
    receiver = factories.make_address()
    with patch("raiden.network.pathfinding.requests.get") as get_mock:
        # No previous IOU
        get_mock.return_value.json.return_value = {"last_iou": None}
        assert (
            get_last_iou("http://example.com", token_network_address, sender, receiver, PRIVKEY)
            is None
        )

        # Previous IOU
        iou = dict(sender=sender, receiver=receiver, amount=10, expiration_block=1000)
        iou["signature"] = sign_one_to_n_iou(
            privatekey=encode_hex(privkey),
            sender=to_checksum_address(sender),
            receiver=to_checksum_address(receiver),
            amount=iou["amount"],
            expiration=iou["expiration_block"],
        )
        get_mock.return_value.json.return_value = {"last_iou": iou}
        assert (
            get_last_iou("http://example.com", token_network_address, sender, receiver, PRIVKEY)
            == iou
        )


def test_make_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))
    config = {
        "pathfinding_eth_address": encode_hex(receiver),
        "pathfinding_iou_timeout": 10000,
        "pathfinding_max_fee": 100,
    }

    iou = make_iou(config, our_address=sender, privkey=privkey, block_number=10)

    assert iou["sender"] == to_checksum_address(sender)
    assert iou["receiver"] == encode_hex(receiver)
    assert 0 < iou["amount"] <= config["pathfinding_max_fee"]


def test_update_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))

    # prepare iou
    iou = {
        "sender": encode_hex(sender),
        "receiver": encode_hex(receiver),
        "amount": 10,
        "expiration_block": 1000,
    }
    iou["signature"] = encode_hex(
        sign_one_to_n_iou(
            privatekey=encode_hex(privkey),
            sender=iou["sender"],
            receiver=iou["receiver"],
            amount=iou["amount"],
            expiration=iou["expiration_block"],
        )
    )

    # update and compare
    added_amount = 10
    new_iou = update_iou(iou=iou.copy(), privkey=privkey, added_amount=added_amount)
    assert new_iou["amount"] == iou["amount"] + added_amount
    assert new_iou["sender"] == iou["sender"]
    assert new_iou["receiver"] == iou["receiver"]
    assert new_iou["signature"] != iou["signature"]

    # Previous IOU with increased amount by evil PFS
    tampered_iou = new_iou.copy()
    tampered_iou["amount"] += 10
    with pytest.raises(ServiceRequestFailed):
        update_iou(iou=tampered_iou, privkey=privkey, added_amount=added_amount)


def request_mock(response=None, status_code=200):
    mock = Mock()
    mock.configure_mock(status_code=status_code)
    mock.json = Mock(return_value=response or {})
    return mock


def assert_failed_pfs_request(
    paths_args: typing.Dict[str, typing.Any],
    responses: typing.List[typing.Dict],
    status_codes: typing.List[int] = (400, 400),
    expected_requests: int = MAX_PATHS_QUERY_ATTEMPTS,
    expected_get_iou_requests: int = None,
    expected_success: bool = False,
    exception_type: typing.Type = None,
):
    while len(responses) < MAX_PATHS_QUERY_ATTEMPTS:
        responses.append(responses[0])
    for response in responses:
        if "error_code" in response:
            response["errors"] = "broken iou"

    path_mocks = [request_mock(*data) for data in zip(responses, status_codes)]

    with patch.object(requests, "get", return_value=request_mock()) as get_iou:
        with patch.object(requests, "post", side_effect=path_mocks) as post_paths:
            if expected_success:
                query_paths(**paths_args)
            else:
                with pytest.raises(exception_type or ServiceRequestFailed) as raised_exception:
                    query_paths(**paths_args)
                    assert "broken iou" in str(raised_exception)
            assert get_iou.call_count == expected_get_iou_requests or expected_requests
            assert post_paths.call_count == expected_requests


@pytest.fixture
def pfs_max_fee():
    return 1000


@pytest.fixture
def query_paths_args(token_network_state, our_address, pfs_max_fee):
    service_config = dict(
        pathfinding_service_address="mock.pathservice",
        pathfinding_eth_address="0x2222222222222222222222222222222222222222",
        pathfinding_max_fee=pfs_max_fee,
        pathfinding_max_paths=3,
        pathfinding_iou_timeout=500,
    )
    return dict(
        service_config=service_config,
        our_address=our_address,
        privkey=PRIVKEY,
        current_block_number=10,
        token_network_address=token_network_state.address,
        route_from=our_address,
        route_to=factories.make_address(),
        value=50,
    )


@pytest.fixture
def valid_response_json():
    return dict(result="some result")


def test_query_paths_with_second_try(query_paths_args, valid_response_json):
    " IOU rejection errors that are expected to result in an unaltered second attempt "
    for try_again in (PFSError.BAD_IOU, PFSError.MISSING_IOU, PFSError.USE_THIS_IOU):
        response = [dict(error_code=try_again.value)] * 2
        assert_failed_pfs_request(
            query_paths_args,
            response,
            expected_requests=2,
            exception_type=ServiceRequestIOURejected,
        )

        response[1] = valid_response_json
        assert_failed_pfs_request(query_paths_args, response, [400, 200], expected_success=True)


def test_query_paths_with_scrapped_iou(query_paths_args, valid_response_json):
    " Errors that will result in reattempting with a new iou "
    for scrap_iou in (PFSError.IOU_ALREADY_CLAIMED, PFSError.IOU_EXPIRED_TOO_EARLY):
        response = [dict(error_code=scrap_iou.value)] * 2
        assert_failed_pfs_request(
            query_paths_args,
            response,
            expected_requests=2,
            expected_get_iou_requests=1,
            exception_type=ServiceRequestIOURejected,
        )

        response[1] = valid_response_json
        assert_failed_pfs_request(query_paths_args, response, [400, 200], expected_success=True)


def test_query_paths_with_unrecoverable_pfs_error(query_paths_args):
    " No retries after unrecoverable errors. "
    for unrecoverable in (
        PFSError.INVALID_REQUEST,
        PFSError.INVALID_SIGNATURE,
        PFSError.REQUEST_OUTDATED,
    ):
        response = [dict(error_code=unrecoverable.value)] * 2
        assert_failed_pfs_request(query_paths_args, response, expected_requests=1)

    for unrecoverable in (PFSError.WRONG_IOU_RECIPIENT, PFSError.DEPOSIT_TOO_LOW):
        response = [dict(error_code=unrecoverable.value)] * 2
        assert_failed_pfs_request(
            query_paths_args,
            response,
            expected_requests=1,
            exception_type=ServiceRequestIOURejected,
        )


def test_query_paths_with_insufficient_payment(query_paths_args, valid_response_json, pfs_max_fee):
    " After an insufficient payment response, we retry only if we are below our maximum fee. "
    insufficient_payment = [dict(error_code=PFSError.INSUFFICIENT_SERVICE_PAYMENT.value)] * 2
    assert_failed_pfs_request(
        query_paths_args,
        insufficient_payment,
        expected_requests=1,
        exception_type=ServiceRequestIOURejected,
    )

    query_paths_args["service_config"]["pathfinding_fee"] = pfs_max_fee
    assert_failed_pfs_request(
        query_paths_args,
        insufficient_payment,
        expected_requests=1,
        exception_type=ServiceRequestIOURejected,
    )

    query_paths_args["service_config"]["pathfinding_fee"] = int(pfs_max_fee / 2)
    assert_failed_pfs_request(
        query_paths_args,
        insufficient_payment,
        expected_requests=2,
        exception_type=ServiceRequestIOURejected,
    )

    # second attempt not rejected
    insufficient_payment[1] = valid_response_json
    assert_failed_pfs_request(
        query_paths_args, insufficient_payment, [400, 200], expected_success=True
    )


def test_query_paths_with_multiple_errors(query_paths_args):
    " Max. number of attempts is not exceeded also if there is a new recoverable issue. "
    different_recoverable_errors = [
        dict(error_code=PFSError.BAD_IOU.value),
        dict(error_code=PFSError.IOU_ALREADY_CLAIMED.value),
    ]
    assert_failed_pfs_request(
        query_paths_args, different_recoverable_errors, exception_type=ServiceRequestIOURejected
    )
