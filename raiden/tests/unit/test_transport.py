# -*- coding: utf-8 -*-
import pytest
import gevent
from ethereum import slogging

from raiden.utils import sha3
from raiden.messages import Ping, Ack, decode
from raiden.network.transport import UDPTransport, TokenBucket, DummyPolicy
from raiden.tests.utils.messages import setup_messages_cb

slogging.configure(':DEBUG')


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UDPTransport])
def test_throttle_policy_ping(monkeypatch, raiden_network):

    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # initial policy is DummyPolicy
    assert isinstance(app0.raiden.protocol.transport.throttle_policy, DummyPolicy)

    for app in (app0, app1):
        monkeypatch.setattr(
            app.raiden.protocol.transport,
            'throttle_policy',
            TokenBucket(capacity=2, fill_rate=2)
        )

    # monkey patching successful
    assert app0.raiden.protocol.transport.throttle_policy.capacity == 2.

    messages = setup_messages_cb()

    # we will send 10 pings and let them trickle in according to our policy:
    for nonce in range(10):
        ping = Ping(nonce=nonce)
        app0.raiden.sign(ping)
        app0.raiden.protocol.send_async(app1.raiden.address, ping)

    # each side has two initial tokens available
    gevent.sleep(0.01)
    assert len(messages) == 4  # Ping, Ack

    # per additional second two more tokens become available
    gevent.sleep(3)
    assert len(messages) == 16  # Ping, Ack

    # one more interval and all could be sent
    gevent.sleep(1)
    assert len(messages) == 20  # Ping, Ack

    # sanity check for messages order
    assert decode(messages[0]).nonce == 0
    decoded = decode(messages[-1])
    assert isinstance(decoded, Ack)
    last_ping = Ping(nonce=9)
    app0.raiden.sign(last_ping)
    assert decoded.echo == sha3(last_ping.encode() + app1.raiden.address)
