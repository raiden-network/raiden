import pytest

from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.transfer import direct_transfer
from raiden.transfer import views
from raiden.transfer.events import EventPaymentReceivedSuccess, EventPaymentSentSuccess


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('privatekey_seed', ['test_initiator_log_directransfer_success:{}'])
def test_initiator_log_directransfer_success(raiden_chain, token_addresses, deposit):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = token_addresses[0]
    amount = int(deposit / 2.)
    identifier = 7
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    direct_transfer(
        app0,
        app1,
        token_network_identifier,
        amount,
        identifier,
    )

    app0_all_events = app0.raiden.wal.storage.get_events()
    assert must_contain_entry(app0_all_events, EventPaymentSentSuccess, {
        'identifier': identifier,
        'amount': amount,
        'target': app1.raiden.address,
    })

    app1_all_events = app1.raiden.wal.storage.get_events()
    assert must_contain_entry(app1_all_events, EventPaymentReceivedSuccess, {
        'identifier': identifier,
        'amount': amount,
        'initiator': app0.raiden.address,
    })
