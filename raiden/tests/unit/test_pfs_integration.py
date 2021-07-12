import time
from copy import copy
from dataclasses import replace
from unittest.mock import Mock, call, patch
from uuid import UUID, uuid4

import gevent
import pytest
import requests
from eth_utils import encode_hex, is_checksum_address, is_hex, is_hex_address

from raiden.api.v1.encoding import CapabilitiesSchema
from raiden.constants import RoutingMode
from raiden.exceptions import ServiceRequestFailed, ServiceRequestIOURejected
from raiden.network import pathfinding
from raiden.network.pathfinding import (
    IOU,
    MAX_PATHS_QUERY_ATTEMPTS,
    PFSConfig,
    PFSError,
    PFSInfo,
    PFSProxy,
    get_last_iou,
    make_iou,
    post_pfs_feedback,
    session,
    update_iou,
)
from raiden.network.transport.matrix.utils import make_user_id
from raiden.routing import get_best_routes, make_route_state
from raiden.settings import CapabilitiesConfig
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import mocked_failed_response, mocked_json_response
from raiden.transfer.state import (
    ChannelState,
    NettingChannelState,
    NetworkState,
    TokenNetworkState,
)
from raiden.utils import typing
from raiden.utils.capabilities import capconfig_to_dict
from raiden.utils.formatting import to_checksum_address
from raiden.utils.keys import privatekey_to_address
from raiden.utils.signer import Signer
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    Any,
    BlockNumber,
    BlockTimeout,
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


def make_address_metadata(signer: Signer) -> AddressMetadata:
    user_id = make_user_id(signer.address, "homeserver")
    cap_dict = capconfig_to_dict(CapabilitiesConfig())
    caps = CapabilitiesSchema().dump({"capabilities": cap_dict})["capabilities"]

    signature_bytes = signer.sign(str(user_id).encode())
    signature_hex = encode_hex(signature_bytes)

    return dict(
        user_id=user_id,
        capabilities=caps,
        displayname=signature_hex,
    )


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
        user_deposit_address=factories.make_address(),
        payment_address=factories.make_address(),
        message="",
        operator="",
        version="",
        confirmed_block_number=BlockNumber(10),
        matrix_server="http://matrix.example.com",
    ),
    maximum_fee=TokenAmount(100),
    iou_timeout=BlockTimeout(100),
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
    our_address_metadata,
    iou_json_data=None,
):
    def iou_side_effect(*args, **kwargs):
        if args[0].endswith("/info"):
            return mocked_json_response(
                {
                    "price_info": 5,
                    "network_info": {
                        "chain_id": 42,
                        "token_network_registry_address": to_checksum_address(
                            factories.make_token_network_registry_address()
                        ),
                        "user_deposit_address": to_checksum_address(factories.make_address()),
                        "confirmed_block": {"number": 11},
                    },
                    "version": "0.0.3",
                    "operator": "John Doe",
                    "message": "This is your favorite pathfinding service",
                    "payment_address": to_checksum_address(factories.make_address()),
                    "matrix_server": "http://matrix.example.com",
                }
            )
        else:
            assert "params" in kwargs
            body = kwargs["params"]

            assert is_hex_address(body["sender"])
            assert is_hex_address(body["receiver"])
            assert "timestamp" in body
            assert is_hex(body["signature"])
            assert len(body["signature"]) == 65 * 2 + 2  # 65 hex encoded bytes with 0x prefix

            return mocked_json_response(response_data=iou_json_data)

    with patch.object(session, "get", side_effect=iou_side_effect) as patched:
        _, best_routes, feedback_token = get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=None,
            pfs_proxy=PFSProxy(PFS_CONFIG),
            privkey=PRIVKEY,
            our_address_metadata=our_address_metadata,
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


def test_routing_mocked_pfs_happy_path(happy_path_fixture, one_to_n_address, our_signer):
    addresses, chain_state, _, response, token_network_state = happy_path_fixture
    _, address2, _, address4 = addresses

    with patch.object(session, "post", return_value=response) as patched:
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].hop_after(our_signer.address) == address2
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
    happy_path_fixture, one_to_n_address, our_signer
):
    addresses, chain_state, _, response, token_network_state = happy_path_fixture
    _, address2, _, address4 = addresses

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

    with patch.object(session, "post", return_value=response) as patched:
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
            iou_json_data=dict(last_iou=last_iou.as_json()),
        )

    assert_checksum_address_in_url(patched.call_args[0][0])

    assert routes[0].hop_after(our_signer.address) == address2
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
    chain_state, token_network_state, one_to_n_address, our_signer
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_signer.address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    with patch.object(session, "post", side_effect=requests.RequestException()):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_bad_http_code(
    chain_state, token_network_state, one_to_n_address, our_signer
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_signer.address
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
                    to_checksum_address(our_signer.address),
                    to_checksum_address(address2),
                    to_checksum_address(address3),
                    to_checksum_address(address4),
                ],
                "fees": 0,
            }
        ]
    }

    response = mocked_json_response(response_data=json_data, status_code=400)

    with patch.object(session, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_invalid_json(
    chain_state, token_network_state, one_to_n_address, our_signer
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_signer.address
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
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_invalid_json_structure(
    chain_state, one_to_n_address, token_network_state, our_signer
):
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_signer.address
    )
    address1, address2, address3, address4 = addresses

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    response = mocked_json_response(response_data={}, status_code=400)

    with patch.object(session, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )
        # Request to PFS failed, but we do not fall back to internal routing
        assert len(routes) == 0
        assert feedback_token is None


def test_routing_mocked_pfs_unavailable_peer(
    chain_state, token_network_state, one_to_n_address, our_signer
):
    our_address = our_signer.address
    token_network_state, addresses, _ = create_square_network_topology(
        token_network_state=token_network_state, our_address=our_address
    )
    address1, address2, address3, address4 = addresses

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

    with patch.object(session, "post", return_value=response):
        routes, feedback_token = get_best_routes_with_iou_request_mocked(
            chain_state=chain_state,
            token_network_state=token_network_state,
            one_to_n_address=one_to_n_address,
            from_address=our_address,
            to_address=address4,
            amount=50,
            our_address_metadata=make_address_metadata(our_signer),
        )
        # Node with address2 is not reachable, so even if the only route sent by the PFS
        # is over address2, the internal routing does not provide
        assert routes[0].hop_after(our_signer.address) == address2
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
        with patch.object(session, "get", side_effect=requests.RequestException):
            get_last_iou(**request_args)

    # invalid JSON should raise a ServiceRequestFailed
    response = mocked_failed_response(error=ValueError)

    with pytest.raises(ServiceRequestFailed):
        with patch.object(session, "get", return_value=response):
            get_last_iou(**request_args)

    response = mocked_json_response(response_data={"other_key": "other_value"})
    with patch.object(session, "get", return_value=response):
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

    with patch.object(session, "get", return_value=response):
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
    with patch.object(session, "get", return_value=response):
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
    with patch.object(session, "get", return_value=response):
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

    pfs_proxy = PFSProxy(PFS_CONFIG)
    with patch("raiden.network.pathfinding.get_pfs_info") as mocked_pfs_info:
        mocked_pfs_info.return_value = PFS_CONFIG.info
        with patch.object(session, "get", return_value=mocked_json_response()) as get_iou:
            with patch.object(session, "post", side_effect=path_mocks) as post_paths:
                if expected_success:
                    pfs_proxy.query_paths(**paths_args)
                else:
                    with pytest.raises(exception_type) as raised_exception:
                        pfs_proxy.query_paths(**paths_args)
                        assert "broken iou" in str(raised_exception)
                assert get_iou.call_count == (expected_get_iou_requests or expected_requests)
                assert post_paths.call_count == expected_requests


def test_routing_in_direct_channel(happy_path_fixture, our_signer, one_to_n_address):
    addresses, chain_state, _, _, token_network_state = happy_path_fixture
    address1, _, _, _ = addresses

    pfs_proxy = PFSProxy(PFS_CONFIG)
    # with the transfer of 50 the direct channel should be returned,
    # so there must be not a route request to the pfs
    with patch("raiden.routing.get_best_routes_pfs") as pfs_route_request, patch.object(
        pfs_proxy, "query_address_metadata"
    ) as pfs_user_request:
        pfs_route_request.return_value = None, [], "feedback_token"
        pfs_user_request.return_value = None
        _, routes, _ = get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address1,
            amount=PaymentAmount(50),
            previous_address=None,
            pfs_proxy=pfs_proxy,
            privkey=PRIVKEY,
            our_address_metadata=make_address_metadata(our_signer),
        )
        assert routes[0].hop_after(our_signer.address) == address1
        assert not pfs_route_request.called
        assert pfs_user_request.called

    # with the transfer of 51 the direct channel should not be returned,
    # so there must be a pfs call
    with patch("raiden.routing.get_best_routes_pfs") as pfs_request:
        pfs_request.return_value = None, [], "feedback_token"
        get_best_routes(
            chain_state=chain_state,
            token_network_address=token_network_state.address,
            one_to_n_address=one_to_n_address,
            from_address=our_signer.address,
            to_address=address1,
            amount=PaymentAmount(51),
            previous_address=None,
            pfs_proxy=pfs_proxy,
            privkey=PRIVKEY,
            our_address_metadata=make_address_metadata(our_signer),
        )

        assert pfs_request.called


@pytest.fixture
def query_paths_args(
    chain_id, token_network_state, one_to_n_address, our_address
) -> Dict[str, Any]:
    return dict(
        our_address=our_address,
        privkey=PRIVKEY,
        current_block_number=10,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        chain_id=chain_id,
        route_from=our_address,
        route_to=factories.make_address(),
        value=50,
        pfs_wait_for_block=10,
    )


@pytest.fixture
def valid_response_json():
    return dict(result="some result", feedback_token=DEFAULT_FEEDBACK_TOKEN.hex)


def test_query_paths_with_second_try(query_paths_args, valid_response_json):
    """IOU rejection errors that are expected to result in an unaltered second attempt"""
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
    """Errors that will result in reattempting with a new iou"""
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
    "No retries after unrecoverable errors."
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
    """When the PFS complains about insufficient fees, the client must update it's fee info"""
    insufficient_response = dict(error_code=PFSError.INSUFFICIENT_SERVICE_PAYMENT.value)

    # PFS fails to return info
    assert_failed_pfs_request(
        query_paths_args, [insufficient_response], expected_requests=2, expected_get_iou_requests=2
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
            expected_requests=2,
            expected_get_iou_requests=2,
        )


# TODO create tests for sufficient payments


def test_query_paths_with_multiple_errors(query_paths_args):
    "Max. number of attempts is not exceeded also if there is a new recoverable issue."
    different_recoverable_errors = [
        dict(error_code=PFSError.BAD_IOU.value),
        dict(error_code=PFSError.IOU_ALREADY_CLAIMED.value),
    ]
    assert_failed_pfs_request(
        query_paths_args, different_recoverable_errors, exception_type=ServiceRequestIOURejected
    )


def test_post_pfs_feedback():
    """Test POST feedback to PFS"""

    feedback_token = uuid4()
    token_network_address = factories.make_token_network_address()
    route = [factories.make_address(), factories.make_address()]

    with patch.object(session, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PFS,
            pfs_config=PFS_CONFIG,
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

    with patch.object(session, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PFS,
            pfs_config=PFS_CONFIG,
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

    with patch.object(session, "post", return_value=mocked_json_response()) as feedback:
        post_pfs_feedback(
            routing_mode=RoutingMode.PRIVATE,
            pfs_config=PFS_CONFIG,
            token_network_address=token_network_address,
            route=route,
            token=feedback_token,
            successful=False,
        )

        assert not feedback.called


def test_no_iou_when_pfs_price_0(query_paths_args):
    """Test that no IOU is sent when PFS is for free"""
    pfs_config = PFSConfig(
        info=PFSInfo(
            url="abc",
            price=TokenAmount(0),
            chain_id=ChainID(42),
            token_network_registry_address=factories.make_token_network_registry_address(),
            user_deposit_address=factories.make_address(),
            payment_address=factories.make_address(),
            confirmed_block_number=dict(number=BlockNumber(1)),
            message="",
            operator="",
            version="",
            matrix_server="http://matrix.example.com",
        ),
        maximum_fee=TokenAmount(100),
        iou_timeout=BlockNumber(100),
        max_paths=5,
    )
    pfs_proxy = PFSProxy(pfs_config)
    with patch("raiden.network.pathfinding.get_pfs_info") as mocked_pfs_info:
        mocked_pfs_info.return_value = PFS_CONFIG.info

        with patch.object(
            pathfinding, "post_pfs_paths", return_value=mocked_json_response()
        ) as post_path:
            pfs_proxy.query_paths(
                our_address=query_paths_args["our_address"],
                privkey=query_paths_args["privkey"],
                current_block_number=query_paths_args["current_block_number"],
                token_network_address=query_paths_args["token_network_address"],
                one_to_n_address=query_paths_args["one_to_n_address"],
                chain_id=query_paths_args["chain_id"],
                route_from=query_paths_args["route_from"],
                route_to=query_paths_args["route_to"],
                value=query_paths_args["value"],
                pfs_wait_for_block=query_paths_args["pfs_wait_for_block"],
            )
        assert post_path.call_args == call(
            payload={
                "from": to_checksum_address(query_paths_args["route_from"]),
                "to": to_checksum_address(query_paths_args["route_to"]),
                "value": query_paths_args["value"],
                "max_paths": pfs_config.max_paths,
            },
            token_network_address=query_paths_args["token_network_address"],
            url=pfs_config.info.url,
        )


def test_two_parallel_queries(query_paths_args):
    """Test that only one IOU is being processed at a time."""

    # We mock one query to last at least 0.2s
    def mocked_json_response_with_sleep(**kwargs):  # pylint: disable=unused-argument
        gevent.sleep(0.2)
        return mocked_json_response()

    pfs_proxy = PFSProxy(PFS_CONFIG)
    # Now we start two function calls - query_path - in parallel
    with patch("raiden.network.pathfinding.get_pfs_info") as mocked_pfs_info:
        mocked_pfs_info.return_value = PFS_CONFIG.info

        with patch.object(pathfinding, "create_current_iou"):

            with patch.object(
                pathfinding, "post_pfs_paths", side_effect=mocked_json_response_with_sleep
            ):

                query_1 = gevent.spawn(pfs_proxy.query_paths, **query_paths_args)
                query_2 = gevent.spawn(pfs_proxy.query_paths, **query_paths_args)

                before = time.monotonic()
                gevent.joinall({query_1, query_2}, raise_error=True)
                duration = time.monotonic() - before

                # We expect the calls to happen sequentially, so one greenlet must wait for
                # the other. If semaphore in raiden.network.pathfinding is bound to 2,
                # the test fails
                assert duration >= 0.4


def test_make_route_state_address_to_metadata_serialization_regression():
    """Test that the address keys in address_to_metadata are deserialized.
    See: https://github.com/raiden-network/raiden/issues/6943"""
    addresses = [encode_hex(factories.make_address()) for _ in range(3)]

    test_data = dict(
        path=addresses, address_metadata={address: {} for address in addresses}, estimated_fee=None
    )
    with patch(
        "raiden.transfer.views.get_channelstate_by_token_network_and_partner"
    ) as mocked_get_channelstate, patch("raiden.transfer.channel.get_status") as get_status:
        get_status.return_value = ChannelState.STATE_OPENED
        mocked_get_channelstate.return_value = 1
        route_state = make_route_state(
            path_object=test_data,
            previous_address=None,
            chain_state=None,
            token_network_address=factories.make_address(),
            from_address=factories.make_address(),
        )
        assert all(isinstance(x, bytes) for x in route_state.address_to_metadata.keys())
        assert all(encode_hex(x) for x in route_state.address_to_metadata.keys())
