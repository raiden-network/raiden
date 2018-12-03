import pytest

from raiden.api.python import event_filter_for_payments
from raiden.api.v1.encoding import EventPaymentSentFailedSchema
from raiden.blockchain.events import get_contract_events
from raiden.exceptions import InvalidBlockNumberInput
from raiden.storage.utils import TimestampedEvent
from raiden.tests.utils import factories
from raiden.tests.utils.factories import ADDR
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)


def test_get_contract_events_invalid_blocknumber():
    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], -1, 0)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 999999999999999999999999, 0)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, -1)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, 999999999999999999999999)


def test_v1_event_payment_sent_failed_schema():
    event = EventPaymentSentFailed(
        payment_network_identifier=factories.make_payment_network_identifier(),
        token_network_identifier=factories.make_address(),
        identifier=1,
        target=factories.make_address(),
        reason='whatever',
    )
    log_time = '2018-09-07T20:02:35.000'

    timestamped = TimestampedEvent(event, log_time)

    dumped = EventPaymentSentFailedSchema().dump(timestamped)

    expected = {
        'event': 'EventPaymentSentFailed',
        'log_time': log_time,
        'reason': 'whatever',
    }

    assert all(dumped.data.get(key) == value for key, value in expected.items())


def test_event_filter_for_payments():
    token_network_identifier = factories.make_address()
    payment_network_identifier = factories.make_payment_network_identifier()
    identifier = 1
    target = factories.make_address()
    event = EventPaymentSentSuccess(
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        identifier=identifier,
        amount=5,
        target=target,
    )
    assert event_filter_for_payments(event, token_network_identifier, None)
    assert event_filter_for_payments(event, token_network_identifier, target)
    assert not event_filter_for_payments(event, token_network_identifier, factories.make_address())

    event = EventPaymentReceivedSuccess(
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        identifier=identifier,
        amount=5,
        initiator=target,
    )
    assert event_filter_for_payments(event, token_network_identifier, None)
    assert event_filter_for_payments(event, token_network_identifier, target)
    assert not event_filter_for_payments(event, token_network_identifier, factories.make_address())

    event = EventPaymentSentFailed(
        payment_network_identifier=factories.make_payment_network_identifier(),
        token_network_identifier=token_network_identifier,
        identifier=identifier,
        target=target,
        reason='whatever',
    )
    assert event_filter_for_payments(event, token_network_identifier, None)
    assert event_filter_for_payments(event, token_network_identifier, target)
    assert not event_filter_for_payments(event, token_network_identifier, factories.make_address())
