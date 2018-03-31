# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import direct_transfer
from raiden.tests.utils.events import must_contain_entry
from raiden.transfer.state_change import ActionForTokenNetwork


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_log_directransfer(raiden_chain, token_addresses, deposit):
    """The action that starts a direct transfer must be logged in the WAL."""
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = token_addresses[0]

    amount = int(deposit / 2.)
    identifier = 13

    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier,
    )

    app0_state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    # ActionTransferDirect
    assert must_contain_entry(app0_state_changes, ActionForTokenNetwork, {
        'token_network_identifier': token_address,
        'sub_state_change': {
            'identifier': identifier,
            'amount': amount,
            'receiver_address': app1.raiden.address,
        }
    })

    # ReceiveTransferDirect
    app1_state_changes = app1.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    assert must_contain_entry(app1_state_changes, ActionForTokenNetwork, {
        'token_network_identifier': token_address,
        'sub_state_change': {
            'transfer_identifier': identifier,
            'balance_proof': {
                'transferred_amount': amount,
                'sender': app0.raiden.address,
            }
        }
    })
