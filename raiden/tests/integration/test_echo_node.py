# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.utils.echo_node import EchoNode
from raiden.api.python import RaidenAPI
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils import get_channel_events_for_token


# `RaidenAPI.get_channel_events` is not supported in tester
@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [18])
@pytest.mark.parametrize('settle_timeout', [64])
def test_event_transfer_received_success(
    token_addresses,
    raiden_chain,
):
    app0, app1, app2, receiver_app = raiden_chain
    token_address = token_addresses[0]
    start_block = receiver_app.raiden.get_block_number()

    expected = dict()

    for num, app in enumerate([app0, app1, app2]):
        amount = 1 + num
        transfer_event = RaidenAPI(app.raiden).transfer_async(
            token_address,
            amount,
            receiver_app.raiden.address,
        )
        transfer_event.wait(timeout=20)
        expected[app.raiden.address] = amount

    initiators = list()
    received = list()
    events = get_channel_events_for_token(receiver_app, token_address, start_block)
    for event in events:
        if event['_event_type'] == 'EventTransferReceivedSuccess':
            received.append(event)
            initiators.append(event['initiator'])

    assert len(received) == 3
    assert len(initiators) == 3
    without_receiver_app = [app0.raiden.address, app1.raiden.address, app2.raiden.address]
    assert set(without_receiver_app) == set(initiators)
    for event in received:
        assert expected[event['initiator']] == event['amount']


# `RaidenAPI.get_channel_events` is not supported in tester
@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('reveal_timeout', [18])
@pytest.mark.parametrize('settle_timeout', [64])
def test_echo_node_response(
    token_addresses,
    raiden_chain,
):
    app0, app1, app2, echo_app = raiden_chain
    address_to_app = {app.raiden.address: app for app in raiden_chain}
    token_address = token_addresses[0]
    echo_api = RaidenAPI(echo_app.raiden)

    echo_node = EchoNode(echo_api, token_address)

    expected = list()

    # Create some transfers
    for num, app in enumerate([app0, app1, app2]):
        amount = 1 + num
        transfer_event = RaidenAPI(app.raiden).transfer_async(
            token_address,
            amount,
            echo_app.raiden.address,
            10 ** (num + 1)
        )
        transfer_event.wait(timeout=20)
        expected.append(amount)

    while len(echo_node.handled_transfers) < len(expected):
        gevent.sleep(.5)

    # Check that all transfers were handled correctly
    for handled_transfer in echo_node.handled_transfers:
        app = address_to_app[handled_transfer['initiator']]
        events = get_channel_events_for_token(app, token_address, 0)
        received = {}

        for event in events:
            if event['_event_type'] == 'EventTransferReceivedSuccess':
                # FIXME: This is a bit iffy. The *exact same* event seems to appear in multiple
                #        channels. Needs more investigation.
                received[repr(event)] = event

        assert len(received) == 1
        transfer = received.values()[0]
        assert transfer['initiator'] == echo_app.raiden.address
        assert transfer['identifier'] == (
            handled_transfer['identifier'] + transfer['amount']
        )

    echo_node.stop()
