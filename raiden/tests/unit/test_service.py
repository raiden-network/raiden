# -*- coding: utf-8 -*-
import pytest

from raiden.utils import sha3
from raiden.messages import (
    decode,
    Processed,
    Ping,
)
from raiden.tests.utils.transport import UnreliableTransport
from raiden.tests.utils.messages import setup_messages_cb


@pytest.mark.parametrize('number_of_nodes', [2])
def test_ping(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    async_result = app0.raiden.protocol.send_raw_with_result(
        ping_encoded,
        app1.raiden.address,
    )
    assert async_result.wait(2), 'The message was not processed'

    expected_echohash = sha3(ping_encoded + app1.raiden.address)

    messages_decoded = [decode(m) for m in messages]
    processed_message = next(
        decoded
        for decoded in messages_decoded
        if isinstance(decoded, Processed) and decoded.echo == expected_echohash
    )

    # the ping message was sent and processed
    assert ping_encoded in messages
    assert processed_message


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_ping_unreachable(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # drop everything to force disabling of re-sends
    app0.raiden.protocol.transport.droprate = 1
    app1.raiden.protocol.transport.droprate = 1

    app0.raiden.protocol.retry_interval = 0.1  # for fast tests

    messages = setup_messages_cb()

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    async_result = app0.raiden.protocol.send_raw_with_result(
        ping_encoded,
        app1.raiden.address,
    )

    assert async_result.wait(2) is None, "The message was dropped, it can't be acknowledged"

    # Raiden node will start pinging as soon as a new channel
    #  is established. We need to test if
    #  a) there is our original message in the queue
    #  b) there are only Ping message types in
    messages_decoded = [decode(m) for m in messages]
    assert ping_message in messages_decoded
    for message in messages_decoded:
        assert isinstance(message, Ping)
