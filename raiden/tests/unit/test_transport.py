# -*- coding: utf-8 -*-
import time

import pytest
import gevent
from ethereum import slogging

from raiden.utils import sha3
from raiden.messages import Ping, Ack, decode
from raiden.network.transport import UDPTransport, TokenBucket, DummyPolicy
from raiden.tests.utils.messages import setup_messages_cb

slogging.configure(':DEBUG')


class IntervalCheck(object):
    def __init__(self):
        self.t1 = time.time()

    def inside(self, tolerance):
        t2 = time.time()
        assert abs(t2 - self.t1) < tolerance
        self.t1 = t2

    def stepped(self, span, tolerance):
        t2 = time.time()
        assert abs(t2 - (self.t1 + span)) < tolerance
        self.t1 = t2


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

    # In total 10 packets will be sent and the timing interval will be asserted.
    packets = list()
    for nonce in range(10):
        ping = Ping(nonce=nonce)
        app0.raiden.sign(ping)
        packets.append(ping)

    # We need to take into account some indeterminism of task switching and the
    # additional time for the Ack, let's allow for a 10% difference of the
    # "perfect" value of a message every 0.5s
    token_refill = 0.5
    tolerance = 0.05

    # time sensitive test, the interval is instantiated just before the protocol
    # is used.
    check = IntervalCheck()

    # send all the packets, the throughput must be limited by the policy
    events = [
        app0.raiden.protocol.send_async(app1.raiden.address, p)
        for p in packets
    ]

    # Each token corresponds to a single message, the initial capacity is 2
    # meaning the first burst is of 2 packets.
    events[1].wait()
    check.inside(tolerance)

    assert len(messages) == 4  # two Pings and the corresponding Acks

    # Now check the fill_rate for the remaining packets
    for i in range(2, 10):
        events[i].wait()
        check.stepped(token_refill, tolerance)

    # all 10 Pings and their Acks
    assert len(messages) == 20

    # sanity check messages
    pings = list()
    pings_raw = list()
    acks = list()
    for packet in messages:
        message = decode(packet)

        if isinstance(message, Ping):
            pings.append(message)
            pings_raw.append(packet)

        if isinstance(message, Ack):
            acks.append(message)

    for nonce, message in enumerate(pings):
        assert message.nonce == nonce

    for ping_packet, ack in zip(pings_raw, acks):
        assert ack.echo == sha3(ping_packet + app1.raiden.address)
