# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import (
    direct_transfer,
)
from raiden.transfer.state_change import (
    ActionTransferDirect,
    ReceiveTransferDirect,
)
from raiden.transfer.events import (
    EventTransferReceivedSuccess,
    EventTransferSentSuccess,
)
from raiden.tests.utils.log import (
    get_all_state_changes,
    get_all_state_events,
)


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_initiator_log_directransfer_action(
        raiden_chain,
        token_addresses,
        deposit):
    """ The action that start a direct transfer must be logged in the WAL. """

    token_address = token_addresses[0]
    amount = int(deposit / 2.)
    identifier = 13

    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier,
    )

    app0_state_changes = get_all_state_changes(app0.raiden.transaction_log)
    direct_transfers = [
        state_change
        for _, state_change in app0_state_changes
        if isinstance(state_change, ActionTransferDirect)
    ]
    assert direct_transfers[0] == ActionTransferDirect(
        identifier,
        amount,
        token_address,
        app1.raiden.address,
    )


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
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

    app0_events = get_all_state_events(app0.raiden.transaction_log)
    sucessful_transfers = [
        event.event_object for event in app0_events
        if isinstance(event.event_object, EventTransferSentSuccess)
    ]
    assert sucessful_transfers[0] == EventTransferSentSuccess(
        identifier,
        amount,
        app1.raiden.address,
    )


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_target_log_directransfer_message(
        raiden_chain,
        token_addresses,
        deposit):

    token_address = token_addresses[0]
    amount = int(deposit / 2.)
    identifier = 21

    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier,
    )

    app1_state_changes = get_all_state_changes(app1.raiden.transaction_log)
    received_transfers = [
        state_change
        for _, state_change in app1_state_changes
        if isinstance(state_change, ReceiveTransferDirect)
    ]
    assert received_transfers[0] == ReceiveTransferDirect(
        identifier,
        amount,
        token_address,
        app0.raiden.address,
    )


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_target_log_directransfer_successevent(
        raiden_chain,
        token_addresses,
        deposit):

    token_address = token_addresses[0]
    amount = int(deposit / 2.)
    identifier = 23

    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier,
    )

    app1_state_events = get_all_state_events(app1.raiden.transaction_log)
    sucessful_received_transfers = [
        event.event_object for event in app1_state_events
        if isinstance(event.event_object, EventTransferReceivedSuccess)
    ]
    assert sucessful_received_transfers[0] == EventTransferReceivedSuccess(
        identifier,
        amount,
        app0.raiden.address,
    )
