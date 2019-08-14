import datetime

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
        token_network_registry_address=factories.make_token_network_registry_address(),
        token_network_address=factories.make_address(),
        identifier=1,
        target=factories.make_address(),
        reason="whatever",
    )
    log_time = datetime.datetime.now()

    timestamped = TimestampedEvent(event, log_time)

    dumped = EventPaymentSentFailedSchema().dump(timestamped)

    expected = {
        "event": "EventPaymentSentFailed",
        "log_time": log_time.isoformat(),
        "reason": "whatever",
    }

    assert all(dumped.get(key) == value for key, value in expected.items())


def test_event_filter_for_payments():
    token_network_address = factories.make_address()
    secret = factories.make_secret()
    token_network_registry_address = factories.make_token_network_registry_address()
    identifier = 1
    target = factories.make_address()
    event = EventPaymentSentSuccess(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        identifier=identifier,
        amount=5,
        target=target,
        secret=secret,
        route=[],
    )
    assert event_filter_for_payments(event=event, partner_address=None)
    assert event_filter_for_payments(event=event, partner_address=target)
    assert not event_filter_for_payments(event=event, partner_address=factories.make_address())

    event = EventPaymentReceivedSuccess(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        identifier=identifier,
        amount=5,
        initiator=target,
    )
    assert event_filter_for_payments(event=event, partner_address=None)
    assert event_filter_for_payments(event=event, partner_address=target)
    assert not event_filter_for_payments(event=event, partner_address=factories.make_address())

    event = EventPaymentSentFailed(
        token_network_registry_address=factories.make_token_network_registry_address(),
        token_network_address=token_network_address,
        identifier=identifier,
        target=target,
        reason="whatever",
    )
    assert event_filter_for_payments(event=event, partner_address=None)
    assert event_filter_for_payments(event=event, partner_address=target)
    assert not event_filter_for_payments(event=event, partner_address=factories.make_address())
