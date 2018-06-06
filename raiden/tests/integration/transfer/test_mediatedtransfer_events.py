# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import mediated_transfer
from raiden.tests.utils.events import must_contain_entry
from raiden.transfer import views
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    EventUnlockClaimSuccess,
    SendRevealSecret,
    SendSecretRequest,
)


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('network_wait', [0.4])
def test_mediated_transfer_events(raiden_network, token_addresses, network_wait):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    node_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait,
    )

    initiator_blockevents = app0.raiden.wal.storage.get_events_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    initiator_events = [blocknumber_event[1] for blocknumber_event in initiator_blockevents]
    assert must_contain_entry(initiator_events, SendRevealSecret, {})
    assert must_contain_entry(initiator_events, EventUnlockSuccess, {})

    mediator_blockevents = app1.raiden.wal.storage.get_events_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    mediator_events = [blocknumber_event[1] for blocknumber_event in mediator_blockevents]
    assert must_contain_entry(mediator_events, EventUnlockSuccess, {})
    assert must_contain_entry(mediator_events, EventUnlockClaimSuccess, {})

    target_blockevents = app2.raiden.wal.storage.get_events_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    target_events = [blocknumber_event[1] for blocknumber_event in target_blockevents]
    assert must_contain_entry(target_events, SendSecretRequest, {})
    assert must_contain_entry(target_events, SendRevealSecret, {})
    assert must_contain_entry(target_events, EventUnlockClaimSuccess, {})
