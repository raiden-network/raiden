import pytest

from raiden.exceptions import InvalidBlockNumberInput
from raiden.blockchain.events import get_contract_events
from raiden.tests.utils.factories import ADDR


def test_get_contract_events_invalid_blocknumber():
    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], -1, 0)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 999999999999999999999999, 0)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, -1)

    with pytest.raises(InvalidBlockNumberInput):
        get_contract_events(None, {}, ADDR, [], 1, 999999999999999999999999)
