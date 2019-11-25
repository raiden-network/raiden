from copy import copy
from dataclasses import replace
from unittest.mock import Mock, call, patch
from uuid import UUID, uuid4

import pytest
import requests
from eth_utils import is_checksum_address, is_hex, is_hex_address, to_checksum_address

from raiden.constants import RoutingMode
from raiden.exceptions import ServiceRequestFailed, ServiceRequestIOURejected
from raiden.network import pathfinding
from raiden.network.pathfinding import (
    IOU,
    MAX_PATHS_QUERY_ATTEMPTS,
    PFSConfig,
    PFSError,
    PFSInfo,
    get_last_iou,
    make_iou,
    post_pfs_feedback,
    query_paths,
    update_iou,
)
from raiden.routing import get_best_routes
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import mocked_failed_response, mocked_json_response
from raiden.transfer.state import NettingChannelState, NetworkState, TokenNetworkState
from raiden.utils import privatekey_to_address, typing
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    ChainID,
    Dict,
    PaymentAmount,
    TokenAmount,
    TokenNetworkAddress,
)

DEFAULT_FEEDBACK_TOKEN = UUID("381e4a005a4d4687ac200fa1acd15c6f")


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
    address4 = factories.make_address()

    # Create a network with the following topology
    #
    # our  ----- 50 ---->  (1) <------50------
    #  |                                    |
    #  |                                    |
    # 100                                  (4)
    #  |                                    ^
    #  v                                    |
    # (2)  ----- 100 --->  (3) <-------100---

    routes = [
        factories.RouteProperties(
            address1=our_address, address2=address1, capacity1to2=TokenAmount(50)
        ),
        factories.RouteProperties(
            address1=our_address, address2=address2, capacity1to2=TokenAmount(100)
        ),
        factories.RouteProperties(
            address1=address4, address2=address1, capacity1to2=TokenAmount(50)
        ),
        factories.RouteProperties(
            address1=address2, address2=address3, capacity1to2=TokenAmount(100)
        ),
        factories.RouteProperties(
            address1=address3,
            address2=address4,
            capacity1to2=TokenAmount(100),
            capacity2to1=TokenAmount(100),
        ),
    ]

    new_state, channels = factories.create_network(
        token_network_state=token_network_state,
        our_address=our_address,
        routes=routes,
        block_number=factories.make_block_number(),
    )

    return new_state, [address1, address2, address3, address4], channels


PFS_CONFIG = PFSConfig(
    info=PFSInfo(
        url="abc",
        price=TokenAmount(12),
        chain_id=ChainID(42),
        token_network_registry_address=factories.make_token_network_registry_address(),
        payment_address=factories.make_address(),
        message="",
        operator="",
        version="",
    ),
    maximum_fee=TokenAmount(100),
    iou_timeout=BlockNumber(100),
    max_paths=5,
)
CONFIG = {"pfs_config": PFS_CONFIG}

PRIVKEY = b"privkeyprivkeyprivkeyprivkeypriv"


def get_best_routes_with_iou_request_mocked(
    chain_state,
    token_network_state,
    one_to_n_address,
    from_address,
    to_address,
    amount,
    iou_json_data=None,
):
    def iou_side_effect(*_, **kwargs):
        assert "params" in kwargs
        body = kwargs["params"]

        assert is_hex_address(body["sender"])
        assert is_hex_address(body["receiver"])
        assert "timestamp" in body
        assert is_hex(body["signature"])
        assert len(body["signature"]) == 65 * 2 + 2  # 65 hex encoded bytes with 0x prefix

        return mocked_json_response(response_data=iou_json_data)

    with patch.object(requests, "get", side_effect=iou_side_effect) as patched:
        best_routes, feedback_token = get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=None,
            config=CONFIG,
            privkey=PRIVKEY,
        )
        assert_checksum_address_in_url(patched.call_args[0][0])
        return best_routes, feedback_token


@pytest.fixture
def happy_path_fixture(chain_state, token_network_state, our_address):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
        address4: NetworkState.REACHABLE,
    }

    json_data = {
        "result": [
            {
                "path": [
                    to_checksum_address(our_address),
                    to_checksum_address(address2),
                    to_checksum_address(address3),
                    to_checksum_address(address4),
                ],
                "estimated_fee": 0,
            }
        ],
        "feedback_token": DEFAULT_FEEDBACK_TOKEN.hex,
    }

    response = mocked_json_response(response_data=json_data)

    return addresses, chain_state, channel_states, response, token_network_state


def test_routing_mocked_pfs_happy_path(happy_path_fixture, one_to_n_address, our_address):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    _, address2, _, address4 = addresses
    _, channel_state2 = channel_states

    with patch.object(requests, "post", return_value=response) as patched:
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].next_hop_address == address2
    assert routes[0].forward_channel_id == channel_state2.identifier
    assert feedback_token == DEFAULT_FEEDBACK_TOKEN

    # Check for iou arguments in request payload
    iou = patched.call_args[1]["json"]["iou"]
    pfs_config: PFSConfig = CONFIG["pfs_config"]
    for key in ("amount", "expiration_block", "signature", "sender", "receiver"):
        assert key in iou
    assert iou["amount"] <= pfs_config.maximum_fee
    latest_expected_expiration = pfs_config.iou_timeout + chain_state.block_number
    assert iou["expiration_block"] <= latest_expected_expiration


def test_routing_mocked_pfs_happy_path_with_updated_iou(
    happy_path_fixture, one_to_n_address, our_address
):
    addresses, chain_state, channel_states, response, token_network_state = happy_path_fixture
    _, address2, _, address4 = addresses
    _, channel_state2 = channel_states

    iou = make_iou(
        pfs_config=PFS_CONFIG,
        our_address=factories.UNIT_TRANSFER_SENDER,
        one_to_n_address=one_to_n_address,
        privkey=PRIVKEY,
        block_number=BlockNumber(10),
        chain_id=ChainID(5),
        offered_fee=TokenAmount(1),
    )
    last_iou = copy(iou)

    with patch.object(requests, "post", return_value=response) as patched:
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
            iou_json_data=dict(last_iou=last_iou.as_json()),
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].next_hop_address == address2
    assert routes[0].forward_channel_id == channel_state2.identifier
    assert feedback_token == DEFAULT_FEEDBACK_TOKEN

    # Check for iou arguments in request payload
    payload = patched.call_args[1]["json"]
    pfs_config = CONFIG["pfs_config"]
    old_amount = last_iou.amount
    assert old_amount < payload["iou"]["amount"] <= pfs_config.maximum_fee + old_amount
    assert payload["iou"]["expiration_block"] == last_iou.expiration_block
    assert payload["iou"]["sender"] == to_checksum_address(last_iou.sender)
    assert payload["iou"]["receiver"] == to_checksum_address(last_iou.receiver)
    assert "signature" in payload["iou"]


def test_routing_mocked_pfs_request_error(
    chain_state, token_network_state, one_to_n_address, our_address
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    with patch.object(requests, "post", side_effect=requests.RequestException()):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_bad_http_code(
    chain_state, token_network_state, one_to_n_address, our_address
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    # in case the pfs sends a bad http code but the correct path back
    json_data = {
        "result": [
            {
                "path": [
                    to_checksum_address(our_address),
                    to_checksum_address(address2),
                    to_checksum_address(address3),
                    to_checksum_address(address4),
                ],
                "fees": 0,
            }
        ]
    }

    response = mocked_json_response(response_data=json_data, status_code=400)

    with patch.object(requests, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_invalid_json(
    chain_state, token_network_state, one_to_n_address, our_address
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    response = mocked_failed_response(error=ValueError(), status_code=200)

    with patch.object(requests, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_invalid_json_structure(
    chain_state, one_to_n_address, token_network_state, our_address
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    response = mocked_json_response(response_data={}, status_code=400)

    with patch.object(requests, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_unavailable_peer(
    chain_state, token_network_state, one_to_n_address, our_address
):
    token_network_state, addresses, channel_states = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses
    _, channel_state2 = channel_states

    json_data = {
        "result": [
            {
                "path": [
                    to_checksum_address(our_address),
                    to_checksum_address(address2),
                    to_checksum_address(address3),
                    to_checksum_address(address4),
                ],
                "estimated_fee": 0,
            }
        ],
        "feedback_token": DEFAULT_FEEDBACK_TOKEN.hex,
    }

    # test routing with node 2 unavailable
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.UNREACHABLE,
        address3: NetworkState.REACHABLE,
    }

    response = mocked_json_response(response_data=json_data, status_code=200)

    with patch.object(requests, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
        )
        # Node with address2 is not reachable, so even if the only route sent by the PFS
        # is over address2, the internal routing does not provide
        assert routes[0].next_hop_address == address2
        assert routes[0].forward_channel_id == channel_state2.identifier
        assert feedback_token == DEFAULT_FEEDBACK_TOKEN


def test_get_and_update_iou(one_to_n_address):

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
    response = mocked_failed_response(error=ValueError)

    with pytest.raises(ServiceRequestFailed):
        with patch.object(requests, "get", return_value=response):
            get_last_iou(**request_args)

    response = mocked_json_response(response_data={"other_key": "other_value"})
    with patch.object(requests, "get", return_value=response):
        iou = get_last_iou(**request_args)
    assert iou is None, "get_pfs_iou should return None if pfs returns no iou."

    last_iou = make_iou(
        pfs_config=PFS_CONFIG,
        our_address=factories.UNIT_TRANSFER_INITIATOR,
        privkey=PRIVKEY,
        block_number=10,
        one_to_n_address=one_to_n_address,
        chain_id=4,
        offered_fee=TokenAmount(1),
    )

    response = mocked_json_response(response_data=dict(last_iou=last_iou.as_json()))

    with patch.object(requests, "get", return_value=response):
        iou = get_last_iou(**request_args)
    assert iou == last_iou

    new_iou_1 = update_iou(replace(iou), PRIVKEY, added_amount=10)
    assert new_iou_1.amount == last_iou.amount + 10
    assert new_iou_1.sender == last_iou.sender
    assert new_iou_1.receiver == last_iou.receiver
    assert new_iou_1.expiration_block == last_iou.expiration_block
    assert new_iou_1.signature is not None

    new_iou_2 = update_iou(replace(iou), PRIVKEY, expiration_block=45)
    assert new_iou_2.expiration_block == 45
    assert new_iou_1.sender == iou.sender
    assert new_iou_1.receiver == iou.receiver
    assert new_iou_1.expiration_block == iou.expiration_block
    assert new_iou_2.signature is not None


def test_get_pfs_iou(one_to_n_address):
    token_network_address = TokenNetworkAddress(bytes([1] * 20))
    privkey = bytes([2] * 32)
    sender = privatekey_to_address(privkey)
    receiver = factories.make_address()

    response = mocked_json_response(response_data={"last_iou": None})
    with patch.object(requests, "get", return_value=response):
        assert (
            get_last_iou("http://example.com", token_network_address, sender, receiver, PRIVKEY)
            is None
        )

        # Previous IOU
        iou = IOU(
            sender=sender,
            receiver=receiver,
            amount=10,
            expiration_block=1000,
            one_to_n_address=one_to_n_address,
            chain_id=4,
        )
        iou.sign(privkey)

    response = mocked_json_response(response_data={"last_iou": iou.as_json()})
    with patch.object(requests, "get", return_value=response):
        assert (
            get_last_iou("http://example.com", token_network_address, sender, receiver, PRIVKEY)
            == iou
        )


def test_make_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))
    one_to_n_address = Address(bytes([2] * 20))
    chain_id = ChainID(4)
    max_fee = 100

    pfs_config_copy = replace(PFS_CONFIG)
    pfs_config_copy.info = replace(pfs_config_copy.info, payment_address=receiver)
    iou = make_iou(
        pfs_config=pfs_config_copy,
        our_address=sender,
        privkey=privkey,
        block_number=10,
        one_to_n_address=one_to_n_address,
        chain_id=chain_id,
        offered_fee=TokenAmount(1),
    )

    assert iou.sender == sender
    assert iou.receiver == receiver
    assert 0 < iou.amount <= max_fee


def test_update_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))
    one_to_n_address = Address(bytes([2] * 20))

    # prepare iou
    iou = IOU(
        sender=sender,
        receiver=receiver,
        amount=10,
        expiration_block=1000,
        chain_id=4,
        one_to_n_address=one_to_n_address,
    )
    iou.sign(privkey)

    # update and compare
    added_amount = 10
    new_iou = update_iou(iou=replace(iou), privkey=privkey, added_amount=added_amount)
    assert new_iou.amount == iou.amount + added_amount
    assert new_iou.sender == iou.sender
    assert new_iou.receiver == iou.receiver
    assert new_iou.signature != iou.signature

    # Previous IOU with increased amount by evil PFS
    tampered_iou = replace(new_iou)
    tampered_iou.amount += 10
    with pytest.raises(ServiceRequestFailed):
        update_iou(iou=tampered_iou, privkey=privkey, added_amount=added_amount)


def assert_failed_pfs_request(
    paths_args: typing.Dict[str, typing.Any],
    responses: typing.List[typing.Dict],
    status_codes: typing.Sequence[int] = (400, 400),
    expected_requests: int = MAX_PATHS_QUERY_ATTEMPTS,
    expected_get_iou_requests: int = None,
    expected_success: bool = False,
    exception_type: typing.Type = ServiceRequestFailed,
):
    while len(responses) < MAX_PATHS_QUERY_ATTEMPTS:
        responses.append(responses[0])
    for response in responses:
        if "error_code" in response:
            response["errors"] = "broken iou"

    path_mocks = [
        mocked_json_response(response_data=data, status_code=status_code)
        for data, status_code in zip(responses, status_codes)
    ]

    with patch.object(requests, "get", return_value=mocked_json_response()) as get_iou:
        with patch.object(requests, "post", side_effect=path_mocks) as post_paths:
            if expected_success:
                query_paths(**paths_args)
            else:
                with pytest.raises(exception_type) as raised_exception:
                    query_paths(**paths_args)
                    assert "broken iou" in str(raised_exception)
            assert get_iou.call_count == (expected_get_iou_requests or expected_requests)
            assert post_paths.call_count == expected_requests


def test_routing_in_direct_channel(happy_path_fixture, our_address, one_to_n_address):
    addresses, chain_state, channel_states, _, token_network_state = happy_path_fixture
    address1, _, _, _ = addresses
    channel_state1, _ = channel_states

    # with the transfer of 50 the direct channel should be returned,
    # so there must be not a pfs call
    with patch("raiden.routing.get_best_routes_pfs") as pfs_request:
        pfs_request.return_value = True, [], "feedback_token"
        routes, _ = get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address1,
            amount=PaymentAmount(50),
            previous_address=None,
            config=CONFIG,
            privkey=PRIVKEY,
        )
        assert routes[0].next_hop_address == address1
        assert routes[0].forward_channel_id == channel_state1.identifier
        assert not pfs_request.called

    # with the transfer of 51 the direct channel should not be returned,
    # so there must be a pfs call
    with patch("raiden.routing.get_best_routes_pfs") as pfs_request:
        pfs_request.return_value = True, [], "feedback_token"
        get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address1,
            amount=PaymentAmount(51),
            previous_address=None,
            config=CONFIG,
            privkey=PRIVKEY,
        )

        assert pfs_request.called


@pytest.fixture
def query_paths_args(
    chain_id, token_network_state, one_to_n_address, our_address
) -> Dict[str, Any]:
    return dict(
        pfs_config=PFS_CONFIG,
        our_address=our_address,
        privkey=PRIVKEY,
        current_block_number=10,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        chain_id=chain_id,
        route_from=our_address,
        route_to=factories.make_address(),
        value=50,
    )


@pytest.fixture
def valid_response_json():
    return dict(result="some result", feedback_token=DEFAULT_FEEDBACK_TOKEN.hex)


def test_query_paths_with_second_try(query_paths_args, valid_response_json):
    """ IOU rejection errors that are expected to result in an unaltered second attempt """
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
    """ Errors that will result in reattempting with a new iou """
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
        assert_failed_pfs_request(
            query_paths_args,
            response,
            [400, 200],
            expected_success=True,
            expected_get_iou_requests=1,
        )


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


def test_insufficient_payment(query_paths_args, valid_response_json):
    """ When the PFS complains about insufficient fees, the client must update it's fee info """
    insufficient_response = dict(error_code=PFSError.INSUFFICIENT_SERVICE_PAYMENT.value)

    # PFS fails to return info
    assert_failed_pfs_request(
        query_paths_args, [insufficient_response], expected_requests=1, expected_get_iou_requests=2
    )

    # PFS has increased fees
    increased_fee = PFS_CONFIG.info.price + 1
    new_pfs_info = replace(PFS_CONFIG.info, price=increased_fee)
    with patch("raiden.network.pathfinding.get_pfs_info", Mock(return_value=new_pfs_info)):
        assert_failed_pfs_request(
            query_paths_args,
            [insufficient_response, valid_response_json],
            status_codes=[400, 200],
            expected_requests=2,
            expected_get_iou_requests=2,
            expected_success=True,
        )

    # PFS demands higher fees than allowed by client
    too_high_fee = PFS_CONFIG.maximum_fee + 1
    new_pfs_info = replace(PFS_CONFIG.info, price=too_high_fee)
    with patch("raiden.network.pathfinding.get_pfs_info", Mock(return_value=new_pfs_info)):
        assert_failed_pfs_request(
            query_paths_args,
            [insufficient_response],
            expected_requests=1,
            expected_get_iou_requests=1,
        )


# TODO create tests for sufficient payments


def test_query_paths_with_multiple_errors(query_paths_args):
    " Max. number of attempts is not exceeded also if there is a new recoverable issue. "
    different_recoverable_errors = [
        dict(error_code=PFSError.BAD_IOU.value),
        dict(error_code=PFSError.IOU_ALREADY_CLAIMED.value),
    ]
    assert_failed_pfs_request(
        query_paths_args, different_recoverable_errors, exception_type=ServiceRequestIOURejected
    )


def test_post_pfs_feedback(query_paths_args):
    """ Test POST feedback to PFS """

    feedback_token = uuid4()
    token_network_address = factories.make_token_network_address()
    route = [factories.make_address(), factories.make_address()]

    with patch.object(requests, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PFS,
            pfs_config=query_paths_args["pfs_config"],
            token_network_address=token_network_address,
            route=route,
            token=feedback_token,
            successful=True,
        )

        assert feedback.called
        assert feedback.call_args[0][0].find(to_checksum_address(token_network_address)) > 0

        payload = feedback.call_args[1]["json"]
        assert payload["token"] == feedback_token.hex
        assert payload["success"] is True
        assert payload["path"] == [to_checksum_address(addr) for addr in route]

    with patch.object(requests, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PFS,
            pfs_config=query_paths_args["pfs_config"],
            token_network_address=token_network_address,
            route=route,
            token=feedback_token,
            successful=False,
        )

        assert feedback.called
        assert feedback.call_args[0][0].find(to_checksum_address(token_network_address)) > 0

        payload = feedback.call_args[1]["json"]
        assert payload["token"] == feedback_token.hex
        assert payload["success"] is False
        assert payload["path"] == [to_checksum_address(addr) for addr in route]

    with patch.object(requests, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PRIVATE,
            pfs_config=query_paths_args["pfs_config"],
            token_network_address=token_network_address,
            route=route,
            token=feedback_token,
            successful=False,
        )

        assert not feedback.called


def test_no_iou_when_pfs_price_0(query_paths_args):
    """ Test that no IOU is sent when PFS is for free """
    query_paths_args["pfs_config"] = PFSConfig(
        info=PFSInfo(
            url="abc",
            price=TokenAmount(0),
            chain_id=ChainID(42),
            token_network_registry_address=factories.make_token_network_address(),
            payment_address=factories.make_address(),
            message="",
            operator="",
            version="",
        ),
        maximum_fee=TokenAmount(100),
        iou_timeout=BlockNumber(100),
        max_paths=5,
    )

    with patch.object(
        pathfinding, "post_pfs_paths", return_value=mocked_json_response()
    ) as post_path:
        query_paths(
            pfs_config=query_paths_args["pfs_config"],
            our_address=query_paths_args["our_address"],
            privkey=query_paths_args["privkey"],
            current_block_number=query_paths_args["current_block_number"],
            token_network_address=query_paths_args["token_network_address"],
            one_to_n_address=query_paths_args["one_to_n_address"],
            chain_id=query_paths_args["chain_id"],
            route_from=query_paths_args["route_from"],
            route_to=query_paths_args["route_to"],
            value=query_paths_args["value"],
        )
    assert post_path.call_args == call(
        payload={
            "from": to_checksum_address(query_paths_args["route_from"]),
            "to": to_checksum_address(query_paths_args["route_to"]),
            "value": query_paths_args["value"],
            "max_paths": query_paths_args["pfs_config"].max_paths,
        },
        token_network_address=query_paths_args["token_network_address"],
        url=query_paths_args["pfs_config"].info.url,
    )
