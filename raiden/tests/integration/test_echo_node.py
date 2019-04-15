import gevent
import pytest
from eth_utils import to_hex

from raiden.api.python import RaidenAPI
from raiden.messages import Unlock
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.utils import random_secret, sha3, wait_until
from raiden.utils.echo_node import EchoNode


@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
@pytest.mark.skip('Issue: 3750')
def test_event_transfer_received_success(
        token_addresses,
        raiden_chain,
):
    raise_on_failure(
        raiden_chain,
        run_test_event_transfer_received_success,
        token_addresses=token_addresses,
        raiden_chain=raiden_chain,
    )


def run_test_event_transfer_received_success(
        token_addresses,
        raiden_chain,
):
    sender_apps = raiden_chain[:-1]
    target_app = raiden_chain[-1]

    token_address = token_addresses[0]
    registry_address = target_app.raiden.default_registry.address
    target_address = target_app.raiden.address

    message_handler = WaitForMessage()
    target_app.raiden.message_handler = message_handler

    wait_for = list()
    for amount, app in enumerate(sender_apps, 1):
        secret = random_secret()

        wait = message_handler.wait_for_message(
            Unlock,
            {'secret': secret},
        )
        wait_for.append((wait, app.raiden.address, amount))

        RaidenAPI(app.raiden).transfer_async(
            registry_address=registry_address,
            token_address=token_address,
            amount=amount,
            identifier=amount,
            target=target_address,
            secret=to_hex(secret),
            secret_hash=to_hex(sha3(secret)),
        )

    for wait, sender, amount in wait_for:
        wait.wait()
        assert search_for_item(
            target_app.raiden.wal.storage.get_events(),
            EventPaymentReceivedSuccess,
            {
                'amount': amount,
                'identifier': amount,
                'initiator': sender,
                'payment_network_identifier': registry_address,
                # 'token_network_identifier': ,
            },
        )


@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
@pytest.mark.skip('Issue: 3750')
def test_echo_node_response(token_addresses, raiden_chain, network_wait):
    raise_on_failure(
        raiden_chain,
        run_test_echo_node_response,
        token_addresses=token_addresses,
        raiden_chain=raiden_chain,
        network_wait=network_wait,
    )


def run_test_echo_node_response(token_addresses, raiden_chain, network_wait):
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
        payment_status = RaidenAPI(app.raiden).transfer_async(
            app.raiden.default_registry.address,
            token_address,
            amount,
            echo_app.raiden.address,
            10 ** (num + 1),
        )
        payment_status.payment_done.wait(timeout=20)
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
            return None
        transfer = received.popitem()[1]

        is_not_valid = (
            transfer.initiator != echo_app.raiden.address or
            transfer.identifier != handled_transfer.identifier + transfer.amount
        )

        if is_not_valid:
            return None
        return transfer

    for handled_transfer in echo_node.seen_transfers:
        assert wait_until(lambda: test_events(handled_transfer), network_wait)

    echo_node.stop()


@pytest.mark.parametrize('number_of_nodes', [8])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [15])
@pytest.mark.parametrize('settle_timeout', [120])
@pytest.mark.skip('Issue: 3750')
def test_echo_node_lottery(token_addresses, raiden_chain, network_wait):
    raise_on_failure(
        raiden_chain,
        run_test_echo_node_lottery,
        token_addresses=token_addresses,
        raiden_chain=raiden_chain,
        network_wait=network_wait,
    )


def run_test_echo_node_lottery(token_addresses, raiden_chain, network_wait):
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
        payment_status = RaidenAPI(app.raiden).transfer_async(
            app.raiden.default_registry.address,
            token_address,
            amount,
            echo_app.raiden.address,
            10 ** (num + 1),
        )
        payment_status.payment_done.wait(timeout=20)
        expected.append(amount)

    # test duplicated identifier + amount is ignored
    payment_status = RaidenAPI(app5.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,  # same amount as before
        echo_app.raiden.address,
        10 ** 6,  # app5 used this identifier before
    ).payment_done.wait(timeout=20)

    # test pool size querying
    pool_query_identifier = 77  # unused identifier different from previous one
    payment_status = RaidenAPI(app5.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,
        echo_app.raiden.address,
        pool_query_identifier,
    ).payment_done.wait(timeout=20)
    expected.append(amount)

    # fill the pool
    payment_status = RaidenAPI(app6.raiden).transfer_async(
        app.raiden.default_registry.address,
        token_address,
        amount,
        echo_app.raiden.address,
        10 ** 7,
    ).payment_done.wait(timeout=20)
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
            return None
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

        return None

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
