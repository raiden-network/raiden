import random
from unittest.mock import Mock, create_autospec
from urllib.parse import urlparse

import pytest
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_normalized_address
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

import raiden.network.transport.matrix.client
import raiden.network.transport.matrix.utils
from raiden.exceptions import TransportError
from raiden.network.transport.matrix.utils import (
    login,
    make_client,
    make_room_alias,
    my_place_or_yours,
    sort_servers_closest,
    validate_userid_signature,
)
from raiden.tests.utils.factories import make_signer
from raiden.tests.utils.transport import ignore_messages
from raiden.utils.signer import recover


def test_login_for_the_first_time_must_set_the_display_name():
    ownserver = "https://ownserver.com"
    api = Mock()
    api.base_url = ownserver
    server_name = urlparse(ownserver).netloc

    client = Mock()
    client.api = api

    # login will assert user is hex-encoded address and pw is server_name signed with that address
    def mock_login(user, pw, sync=True):  # pylint: disable=unused-argument
        recovered = recover(data=server_name.encode(), signature=decode_hex(pw))
        if recovered != to_canonical_address(user):
            raise MatrixRequestError(403)
        client.user_id = f"@{user}:{server_name}"

    client.login = Mock(side_effect=mock_login)

    MockUser = create_autospec(User)

    client.get_user = Mock(side_effect=lambda user_id: MockUser(api, user_id))

    signer = make_signer()

    user = login(client=client, signer=signer)

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


def test_sort_servers_closest(monkeypatch):
    cnt = 0

    def random_or_none(url, timeout):  # pylint: disable=unused-argument
        nonlocal cnt
        cnt += 1
        return (url, random.random() if cnt % 3 else None)

    mock_get_http_rtt = Mock(
        spec=raiden.network.transport.matrix.utils.return_after_retries, side_effect=random_or_none
    )

    monkeypatch.setattr(
        raiden.network.transport.matrix.utils, "return_after_retries", mock_get_http_rtt
    )

    with pytest.raises(TransportError):
        sort_servers_closest(["ftp://server1.com", "server2.com"])

    server_count = 9
    sorted_servers = sort_servers_closest([f"https://server{i}.xyz" for i in range(server_count)])
    rtts = list(sorted_servers.values())

    assert len(sorted_servers) <= server_count
    assert all(rtts) and rtts == sorted(rtts)


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
            spec=raiden.network.transport.matrix.utils.return_after_retries,
            side_effect=lambda url, timeout: None,
        )

        m.setattr(raiden.network.transport.matrix.utils, "return_after_retries", mock_get_http_rtt)

        make_client(ignore_messages, [f"http://server{i}.xyz" for i in range(3)])

    mock_send = Mock(side_effect=lambda method, path, *args, **kwargs: True)

    # successful server contact with single (no-auto) server
    with monkeypatch.context() as m:
        m.setattr(raiden.network.transport.matrix.client.GMatrixHttpApi, "_send", mock_send)

        url = "https://server1.xyz"
        client = make_client(ignore_messages, [url])
        assert isinstance(client, raiden.network.transport.matrix.client.GMatrixClient)
        assert client.api.base_url == url


def test_make_room_alias():
    assert make_room_alias(1, "discovery") == "raiden_mainnet_discovery"
    assert make_room_alias(3, "0xdeadbeef", "0xabbacada") == "raiden_ropsten_0xdeadbeef_0xabbacada"
    assert make_room_alias(1337, "monitoring") == "raiden_1337_monitoring"


def test_invite_tiebreaker():
    address = str("a" * 32).encode("utf-8")
    address1 = str("b" * 32).encode("utf-8")
    address2 = str("c" * 32).encode("utf-8")

    assert my_place_or_yours(address, address1) == address
    assert my_place_or_yours(address1, address2) == address1
