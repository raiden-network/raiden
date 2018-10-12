import pytest

from raiden.api.v1.encoding import EventPaymentSentFailedSchema
from raiden.blockchain.events import get_contract_events
from raiden.exceptions import InvalidBlockNumberInput
from raiden.storage.utils import TimestampedEvent
from raiden.tests.utils import factories
from raiden.tests.utils.factories import ADDR
from raiden.transfer.events import EventPaymentSentFailed


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
        factories.make_payment_network_identifier(),
        factories.make_address(),
        1,
        factories.make_address(),
        'whatever',
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
