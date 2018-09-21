import gevent
import pytest

from raiden.api.python import RaidenAPI
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.network import CHAIN
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.utils import wait_until
from raiden.utils.echo_node import EchoNode


@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
def test_event_transfer_received_success(
        token_addresses,
        raiden_chain,
        network_wait,
):
    app0, app1, app2, receiver_app = raiden_chain
    token_address = token_addresses[0]

    expected = dict()

    for num, app in enumerate([app0, app1, app2]):
        amount = 1 + num
        transfer_event = RaidenAPI(app.raiden).transfer_async(
            app.raiden.default_registry.address,
            token_address,
            amount,
            receiver_app.raiden.address,
        )
        transfer_event.wait(timeout=20)
        expected[app.raiden.address] = amount

    # sleep is for the receiver's node to have time to process all events
    gevent.sleep(1)

    def test_events(amount, address):
        return must_contain_entry(
            receiver_app.raiden.wal.storage.get_events(),
            EventPaymentReceivedSuccess,
            {'amount': amount, 'initiator': address},
        )

    amounts = [1, 2, 3]
    addrs = [app0.raiden.address, app1.raiden.address, app2.raiden.address]
    for amount, address in zip(amounts, addrs):
        assert wait_until(
            lambda: test_events(amount, address),
            network_wait,
        )


@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
def test_echo_node_response(token_addresses, raiden_chain, network_wait):
    app0, app1, app2, echo_app = raiden_chain
    address_to_app = {app.raiden.address: app for app in raiden_chain}
    token_address = token_addresses[0]
    echo_api = RaidenAPI(echo_app.raiden)

    echo_node = EchoNode(echo_api, token_address)
    echo_node.ready.wait(timeout=30)
    assert echo_node.ready.is_set()
    expected = list()

    # Create some transfers
    for num, app in enumerate([app0, app1, app2]):
        amount = 1 + num
        transfer_event = RaidenAPI(app.raiden).transfer_async(
            app.raiden.default_registry.address,
            token_address,
            amount,
            echo_app.raiden.address,
            10 ** (num + 1),
        )
        transfer_event.wait(timeout=20)
        expected.append(amount)

    while echo_node.num_handled_transfers < len(expected):
        gevent.sleep(.5)

    # Check that all transfers were handled correctly
    def test_events(handled_transfer):
        app = address_to_app[handled_transfer.initiator]
        events = RaidenAPI(app.raiden).get_raiden_events_payment_history(
            token_address=token_address,
        )

        received = {
            event.identifier: event
            for event in events
            if type(event) == EventPaymentReceivedSuccess
        }

        if len(received) != 1:
            return
        transfer = received.popitem()[1]

        is_not_valid = (
            transfer.initiator != echo_app.raiden.address or
            transfer.identifier != handled_transfer.identifier + transfer.amount
        )

        if is_not_valid:
            return
        return transfer

    for handled_transfer in echo_node.seen_transfers:
        assert wait_until(lambda: test_events(handled_transfer), network_wait)

    echo_node.stop()


@pytest.mark.parametrize('number_of_nodes', [8])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
def test_echo_node_lottery(token_addresses, raiden_chain, network_wait):
    app0, app1, app2, app3, echo_app, app4, app5, app6 = raiden_chain
    address_to_app = {app.raiden.address: app for app in raiden_chain}
    token_address = token_addresses[0]
    echo_api = RaidenAPI(echo_app.raiden)

    echo_node = EchoNode(echo_api, token_address)
    echo_node.ready.wait(timeout=30)
    assert echo_node.ready.is_set()

    expected = list()

    # Let 6 participants enter the pool
    amount = 7
    for num, app in enumerate([app0, app1, app2, app3, app4, app5]):
        transfer_event = RaidenAPI(app.raiden).transfer_async(
            app.raiden.default_registry.address,
            token_address,
            amount,
            echo_app.raiden.address,
            10 ** (num + 1),
        )
        transfer_event.wait(timeout=20)
        expected.append(amount)

    # test duplicated identifier + amount is ignored
    transfer_event = RaidenAPI(app5.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,  # same amount as before
        echo_app.raiden.address,
        10 ** 6,  # app5 used this identifier before
    ).wait(timeout=20)

    # test pool size querying
    pool_query_identifier = 77  # unused identifier different from previous one
    transfer_event = RaidenAPI(app5.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,
        echo_app.raiden.address,
        pool_query_identifier,
    ).wait(timeout=20)
    expected.append(amount)

    # fill the pool
    transfer_event = RaidenAPI(app6.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,
        echo_app.raiden.address,
        10 ** 7,
    ).wait(timeout=20)
    expected.append(amount)

    while echo_node.num_handled_transfers < len(expected):
        gevent.sleep(.5)

    def get_echoed_transfer(sent_transfer):
        """For a given transfer sent to echo node, get the corresponding echoed transfer"""
        app = address_to_app[sent_transfer.initiator]
        events = RaidenAPI(app.raiden).get_raiden_events_payment_history(
            token_address=token_address,
        )

        def is_valid(event):
            return (
                type(event) == EventPaymentReceivedSuccess and
                event.initiator == echo_app.raiden.address and
                event.identifier == sent_transfer.identifier + event.amount
            )

        received = {
            event.identifier: event
            for event in events
            if is_valid(event)
        }

        if len(received) != 1:
            return
        return received.popitem()[1]

    def received_is_of_size(size):
        """Return transfers received from echo_node when there's size transfers"""
        received = {}
        # Check that payout was generated and pool_size_query answered
        for handled_transfer in echo_node.seen_transfers:
            event = get_echoed_transfer(handled_transfer)
            if not event:
                continue
            received[event.identifier] = event
        if len(received) == size:
            return received

    # wait for the expected echoed transfers to be handled
    received = wait_until(lambda: received_is_of_size(2), 2 * network_wait)
    assert received

    received = sorted(received.values(), key=lambda transfer: transfer.amount)

    pool_query = received[0]
    assert pool_query.amount == 6
    assert pool_query.identifier == pool_query_identifier + 6

    winning_transfer = received[1]
    assert winning_transfer.initiator == echo_app.raiden.address
    assert winning_transfer.amount == 49
    assert (winning_transfer.identifier - 49) % 10 == 0

    echo_node.stop()
