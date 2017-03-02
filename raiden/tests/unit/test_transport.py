# -*- coding: utf-8 -*-
import pytest

from raiden.utils import sha3
from raiden.messages import Ping, Ack, decode
import raiden.network.transport
from raiden.network.transport import UDPTransport, TokenBucket, DummyPolicy
from raiden.tests.utils.messages import setup_messages_cb


class sleeper(object):
    """Mock class to provide a `sleep` method that tracks sleep times.
    """

    def __init__(self):
        self.sleeptimes = []

    def sleep(self, amount):
        self.sleeptimes.append(amount)


class fake_time(object):
    """Mock class to provide an alternative `time` module for deterministic
    test timing.
    """
    def __init__(self):
        self.count = 1.

    def time(self):
        return self.count

    def now(self):
        return self.count


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UDPTransport])
def test_throttle_policy_ping(monkeypatch, raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # initial policy is DummyPolicy
    assert isinstance(app0.raiden.protocol.transport.throttle_policy, DummyPolicy)

    test_time = fake_time()

    sleeps = sleeper()

    monkeypatch.setattr(
        raiden.network.transport,
        'time',
        test_time
    )
    monkeypatch.setattr(
        raiden.network.transport.gevent,
        'sleep',
        sleeps.sleep
    )

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

    # the token refill rate is 1s / 2 = 0.5s per token
    token_refill = 1. / app0.raiden.protocol.transport.throttle_policy.fill_rate
    assert token_refill == 0.5

    # send all the packets, the throughput must be limited by the policy
    events = [
        app0.raiden.protocol.send_async(app1.raiden.address, p)
        for p in packets
    ]

    events[-1].wait()
    # Each token corresponds to a single message, the initial capacity is 2
    # meaning the first burst is of 2 packets.
    node_count = 2
    initial_packets = 2

    # The initial sequence Ping, Ack, Ping, Ack has no sleeptimes/throttling
    assert all(
        t == 0.0
        for t in sleeps.sleeptimes[:node_count * initial_packets]
    ), sleeps.sleeptimes

    # the pattern of sleeps is the same for pinging and acking node:
    ping_sleeps = [sleeps.sleeptimes[i] for i in range(0, len(messages), 2)]
    ack_sleeps = [sleeps.sleeptimes[i + 1] for i in range(0, len(messages), 2)]

    assert ping_sleeps == ack_sleeps

    # since we didn't progress time in test, the sleep times will add up:
    for num, t in enumerate(ping_sleeps[initial_packets:], 1):
        assert num * token_refill == t

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
