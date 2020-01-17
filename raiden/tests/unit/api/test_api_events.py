import datetime

import pytest

from raiden.api.python import event_filter_for_payments
from raiden.api.v1.encoding import EventPaymentSentFailedSchema
from raiden.blockchain.events import get_contract_events
from raiden.exceptions import InvalidBlockNumberInput
from raiden.storage.utils import TimestampedEvent
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    ADDR,
    UNIT_TOKEN_NETWORK_ADDRESS,
    UNIT_TOKEN_NETWORK_REGISTRY_ADDRESS,
)
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.utils.typing import Address, InitiatorAddress, PaymentAmount, PaymentID, TargetAddress


def test_get_contract_events_invalid_blocknumber():
    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], -1, 0)  # type:ignore

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 999999999999999999999999, 0)  # type:ignore

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, -1)  # type:ignore

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, 999999999999999999999999)  # type:ignore


def test_v1_event_payment_sent_failed_schema():
    event = EventPaymentSentFailed(
        token_network_registry_address=UNIT_TOKEN_NETWORK_REGISTRY_ADDRESS,
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
        identifier=PaymentID(1),
        target=TargetAddress(factories.make_address()),
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
    secret = factories.make_secret()
    identifier = PaymentID(1)
    target = TargetAddress(factories.make_address())
    event1 = EventPaymentSentSuccess(
        token_network_registry_address=UNIT_TOKEN_NETWORK_REGISTRY_ADDRESS,
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
        identifier=identifier,
        amount=PaymentAmount(5),
        target=target,
        secret=secret,
        route=[],
    )
    assert event_filter_for_payments(event=event1, partner_address=None)
    assert event_filter_for_payments(event=event1, partner_address=Address(target))
    assert not event_filter_for_payments(event=event1, partner_address=factories.make_address())

    initiator = InitiatorAddress(factories.make_address())
    event2 = EventPaymentReceivedSuccess(
        token_network_registry_address=UNIT_TOKEN_NETWORK_REGISTRY_ADDRESS,
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
        identifier=identifier,
        amount=PaymentAmount(5),
        initiator=initiator,
    )
    assert event_filter_for_payments(event=event2, partner_address=None)
    assert event_filter_for_payments(event=event2, partner_address=Address(initiator))
    assert not event_filter_for_payments(event=event2, partner_address=factories.make_address())

    event3 = EventPaymentSentFailed(
        token_network_registry_address=UNIT_TOKEN_NETWORK_REGISTRY_ADDRESS,
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
        identifier=identifier,
        target=target,
        reason="whatever",
    )
    assert event_filter_for_payments(event=event3, partner_address=None)
    assert event_filter_for_payments(event=event3, partner_address=Address(target))
    assert not event_filter_for_payments(event=event3, partner_address=factories.make_address())
