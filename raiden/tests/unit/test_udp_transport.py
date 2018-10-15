import random

import pytest
from gevent import server

from raiden.constants import UINT64_MAX
from raiden.messages import SecretRequest
from raiden.network.throttle import TokenBucket
from raiden.network.transport.udp import UDPTransport
from raiden.tests.utils.factories import ADDR, UNIT_SECRETHASH, make_address
from raiden.tests.utils.transport import MockDiscovery, MockRaidenService


@pytest.fixture
def mock_udp(
        raiden_udp_ports,
        throttle_capacity,
        throttle_fill_rate,
        retry_interval,
        retries_before_backoff,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
):
    throttle_policy = TokenBucket(throttle_capacity, throttle_fill_rate)
    host = '127.0.0.1'
    port = raiden_udp_ports[0]
    address = make_address()

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        nat_invitation_timeout=nat_invitation_timeout,
        nat_keepalive_retries=nat_keepalive_retries,
        nat_keepalive_timeout=nat_keepalive_timeout,
    )

    transport = UDPTransport(
        address,
        MockDiscovery,
        server._udp_socket((host, port)),  # pylint: disable=protected-access
        throttle_policy,
        config,
    )

    transport.raiden = MockRaidenService(ADDR)

    return transport


def test_token_bucket():
    capacity = 2
    fill_rate = 2
    token_refill = 1. / fill_rate

    # return constant time to have a predictable refill result
    time = lambda: 1

    bucket = TokenBucket(
        capacity,
        fill_rate,
        time,
    )

    assert bucket.consume(1) == 0
    assert bucket.consume(1) == 0

    for num in range(1, 9):
        assert num * token_refill == bucket.consume(1)


def test_udp_receive_invalid_length(mock_udp):
    data = bytearray(random.getrandbits(8) for _ in range(mock_udp.UDP_MAX_MESSAGE_SIZE + 1))
    host_port = None
    assert not mock_udp.receive(data, host_port)


def test_udp_decode_invalid_message(mock_udp):
    message = SecretRequest(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        secrethash=UNIT_SECRETHASH,
        amount=1,
        expiration=10,
    )
    data = message.encode()
    wrong_command_id_data = b'\x99' + data[1:]
    host_port = None
    assert not mock_udp.receive(wrong_command_id_data, host_port)


def test_udp_decode_invalid_size_message(mock_udp):
    message = SecretRequest(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        secrethash=UNIT_SECRETHASH,
        amount=1,
        expiration=10,
    )
    data = message.encode()
    wrong_command_id_data = data[:-1]
    host_port = None
    assert not mock_udp.receive(wrong_command_id_data, host_port)
