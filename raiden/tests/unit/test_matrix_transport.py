from itertools import cycle
from typing import List
from unittest.mock import Mock, create_autospec
from urllib.parse import urlparse

import gevent
import pytest
import requests
import responses
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_normalized_address
from flask_restful.representations import json
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

import raiden.network.transport.matrix.client
import raiden.network.transport.matrix.utils
from raiden.constants import DeviceIDs, ServerListType
from raiden.exceptions import TransportError
from raiden.messages.synchronization import Processed
from raiden.messages.transfers import RevealSecret
from raiden.network.transport.matrix.utils import (
    MessageAckTimingKeeper,
    login,
    make_client,
    make_message_batches,
    my_place_or_yours,
    sort_servers_closest,
    validate_userid_signature,
)
from raiden.tests.utils.factories import make_secret, make_signature, make_signer
from raiden.tests.utils.transport import ignore_messages
from raiden.utils.cli import get_matrix_servers
from raiden.utils.signer import recover
from raiden.utils.typing import MessageID


def test_login_for_the_first_time_must_set_display_name_and_avatar_url():
    ownserver = "https://ownserver.com"
    api = Mock()
    api.base_url = ownserver
    server_name = urlparse(ownserver).netloc

    client = Mock()
    client.api = api

    # login will assert user is hex-encoded address and pw is server_name signed with that address
    def mock_login(user, pw, sync=True, device_id=None):  # pylint: disable=unused-argument
        recovered = recover(data=server_name.encode(), signature=decode_hex(pw))
        if recovered != to_canonical_address(user):
            raise MatrixRequestError(403)
        client.user_id = f"@{user}:{server_name}"

    client.login = Mock(side_effect=mock_login)

    MockUser = create_autospec(User)

    client.get_user = Mock(side_effect=lambda user_id: MockUser(api, user_id))

    signer = make_signer()

    user = login(
        client=client, signer=signer, device_id=DeviceIDs.RAIDEN, capabilities={"test": 1}
    )

    # avatar_url must have been set
    user.set_avatar_url.assert_called_once_with("mxc://raiden.network/cap?test=1")

    # client.user_id will be set by login
    assert client.user_id.startswith(f"@{to_normalized_address(signer.address)}")
    # login returns our own user object
    assert isinstance(user, User)
    # get_user must have been called once to generate above user
    client.get_user.assert_called_once_with(client.user_id)
    # assert set_display_name was called once on ourselves
    assert user.set_display_name.call_count == 1
    # assert the user.set_display_name was called with the signature of the user_id
    assert (
        recover(
            data=client.user_id.encode(),
            signature=decode_hex(user.set_display_name.call_args[0][0]),
        )
        == signer.address
    )


def test_validate_userid_signature():
    ownserver = "https://ownserver.com"
    api = Mock()
    api.base_url = ownserver
    server_name = urlparse(ownserver).netloc

    signer = make_signer()

    user = Mock(spec=User)
    user.api = api
    user.user_id = f"@{to_normalized_address(signer.address)}:{server_name}"
    user.displayname = None
    user.get_display_name = Mock(side_effect=lambda: user.displayname)

    # displayname is None, get_display_name will be called but continue to give None
    with pytest.raises(AssertionError):
        assert validate_userid_signature(user)

    assert user.get_display_name.call_count == 0

    # successfuly recover valid displayname
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 0

    # assert another call will cache the result and avoid wasteful get_display_name call
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 0

    # non-hex displayname should be gracefully handled
    user.displayname = "random gibberish"
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 0

    # valid signature but from another user should also return None
    user.displayname = encode_hex(make_signer().sign(user.user_id.encode()))
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 0

    # same address, but different user_id, even if valid, should be rejected
    # (prevent personification)
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    user.user_id = f"@{to_normalized_address(signer.address)}.deadbeef:{server_name}"
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 0

    # but non-default but valid user_id should be accepted
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 0

    # non-compliant user_id shouldn't even call get_display_name
    user.user_id = f"@my_user:{server_name}"
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 0


@pytest.mark.skip(reason="flaky, see https://github.com/raiden-network/raiden/issues/5678")
def test_sort_servers_closest(requests_responses):
    with pytest.raises(TransportError):
        # `ftp://` is not a valid scheme
        sort_servers_closest(["ftp://server1.com"])

    def make_dummy_response(response_times: List[float]):
        response_time_iter = cycle(response_times)

        def response(_):
            gevent.sleep(next(response_time_iter))
            return 200, {}, ""

        return response

    # Average response time := 0.1
    requests_responses.add_callback(
        responses.HEAD, "http://url0", callback=make_dummy_response([0.05, 0.05, 0.2])
    )
    # Average response time := 0.05
    requests_responses.add_callback(
        responses.HEAD, "http://url1", callback=make_dummy_response([0.05, 0.05, 0.05])
    )
    # Exceeds 0.3 max timeout defined below
    requests_responses.add_callback(
        responses.HEAD, "http://url2", callback=make_dummy_response([0.5, 0.5, 0.5])
    )
    # Raises an exception
    requests_responses.add(responses.HEAD, "http://url3", body=requests.RequestException())

    sorted_servers = sort_servers_closest(
        ["http://url0", "http://url1", "http://url2", "http://url3"], max_timeout=0.3
    )
    rtts = [round(rtt, 2) for rtt in sorted_servers.values()]

    assert len(sorted_servers) == 2
    assert all(rtts) and rtts == sorted(rtts)
    assert rtts == [0.05, 0.10]

    with pytest.raises(TransportError):
        # Only invalid servers
        sort_servers_closest(["http://url2", "http://url3"], max_timeout=0.3)


def test_make_client(monkeypatch):
    # invalid server url (ftp not supported)
    with pytest.raises(TransportError):
        make_client(ignore_messages, ["ftp://server1.com", "http://server2.com"])

    # no valid server url
    with pytest.raises(TransportError):
        make_client(ignore_messages, [])

    # valid but unreachable servers
    with pytest.raises(TransportError), monkeypatch.context() as m:
        mock_get_http_rtt = Mock(
            spec=raiden.network.transport.matrix.utils.get_average_http_response_time,
            side_effect=lambda url, samples=None, method=None, sample_delay=None: None,
        )

        m.setattr(
            raiden.network.transport.matrix.utils,
            "get_average_http_response_time",
            mock_get_http_rtt,
        )

        make_client(
            ignore_messages,
            [f"http://server{i}.xyz" for i in range(3)],
        )

    mock_send = Mock(side_effect=lambda method, path, *args, **kwargs: True)

    # successful server contact with single (no-auto) server
    with monkeypatch.context() as m:
        m.setattr(raiden.network.transport.matrix.client.GMatrixHttpApi, "_send", mock_send)

        url = "https://server1.xyz"
        client = make_client(ignore_messages, [url])
        assert isinstance(client, raiden.network.transport.matrix.client.GMatrixClient)
        assert client.api.base_url == url


def test_invite_tiebreaker():
    address = str("a" * 32).encode("utf-8")
    address1 = str("b" * 32).encode("utf-8")
    address2 = str("c" * 32).encode("utf-8")

    assert my_place_or_yours(address, address1) == address
    assert my_place_or_yours(address1, address2) == address1


@pytest.mark.parametrize("max_batch_size", [20])
@pytest.mark.parametrize(
    ["message_list", "expected_batch_count", "should_raise"],
    [
        (["a" * 10] * 4, 2, False),
        (["a" * 10] * 5, 3, False),
        (["a" * 15] * 5, 5, False),
        (["a"] * 5, 1, False),
        (["a" * 20], 1, False),
        (["a" * 21], 0, True),
    ],
)
def test_make_message_batches(message_list, expected_batch_count, should_raise, max_batch_size):
    if should_raise:
        with pytest.raises(TransportError):
            list(make_message_batches(message_list, _max_batch_size=max_batch_size))
    else:
        batches = list(make_message_batches(message_list, _max_batch_size=max_batch_size))

        assert len(batches) == expected_batch_count
        assert sum(len(batch.split("\n")) for batch in batches) == len(message_list)


def test_message_ack_timing_keeper_edge_cases():
    matk = MessageAckTimingKeeper()

    # No measurements -> empty report
    assert matk.generate_report() == []

    # Unknown messages must be ignored
    processed = Processed(MessageID(999), make_signature())
    matk.finalize_message(processed)

    assert matk.generate_report() == []

    reveal_secret = RevealSecret(MessageID(1), make_signature(), make_secret())
    matk.add_message(reveal_secret)

    # In flight messages are not included in reports
    assert matk.generate_report() == []


def test_message_ack_timing_keeper():
    matk = MessageAckTimingKeeper()

    matk.add_message(RevealSecret(MessageID(1), make_signature(), make_secret()))

    gevent.sleep(0.05)
    matk.finalize_message(Processed(MessageID(1), make_signature()))

    assert len(matk._durations) == 1
    assert 0.05 <= matk._durations[0] <= 0.06

    # Set duration to a fixed value
    matk._durations[0] = 0.05

    report = matk.generate_report()
    assert len(report) == 1
    assert report == [0.05]


def test_get_matrix_servers(requests_responses: responses.RequestsMock):
    server_list_content = {
        "active_servers": ["http://server1", "http://server2"],
        "all_servers": ["http://server3", "http://server4"],
    }
    requests_responses.add(responses.GET, "http://server-list", json.dumps(server_list_content))

    active_servers_default = get_matrix_servers("http://server-list")
    active_servers_explicit = get_matrix_servers(
        "http://server-list", server_list_type=ServerListType.ACTIVE_SERVERS
    )

    assert (
        active_servers_default == active_servers_explicit == server_list_content["active_servers"]
    )

    all_servers = get_matrix_servers(
        "http://server-list", server_list_type=ServerListType.ALL_SERVERS
    )

    assert all_servers == server_list_content["all_servers"]
