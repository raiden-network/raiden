# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.transfer import direct_transfer
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferReceivedSuccess,
)


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('privatekey_seed', ['test_initiator_log_directransfer_success:{}'])
def test_initiator_log_directransfer_success(
        raiden_chain,
        token_addresses,
        deposit):

    token_address = token_addresses[0]
    amount = int(deposit / 2.)
    identifier = 7

    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier,
    )

    app0_events = app0.raiden.wal.storage.get_events_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    app0_all_events = [event for _, event in app0_events]
    must_contain_entry(app0_all_events, EventTransferSentSuccess, {
        'identifier': identifier,
        'amount': amount,
        'target': app1.raiden.address,
    })

    app1_state_events = app1.raiden.wal.storage.get_events_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    app1_all_events = [event for _, event in app1_state_events]
    must_contain_entry(app1_all_events, EventTransferReceivedSuccess, {
        'identifier': identifier,
        'amount': amount,
        'initiator': app0.raiden.address,
    })
