import pytest

from raiden.constants import UINT256_MAX
from raiden.tests.utils import factories
from raiden.transfer.events import EventPaymentReceivedSuccess


def test_invalid_instantiation_event_payment_received_success():
    kwargs = dict(
        payment_network_address=factories.UNIT_PAYMENT_NETWORK_IDENTIFIER,
        token_network_address=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        identifier=factories.UNIT_TRANSFER_IDENTIFIER,
        initiator=factories.make_address(),
    )

    with pytest.raises(ValueError):
        EventPaymentReceivedSuccess(amount=UINT256_MAX + 1, **kwargs)

    with pytest.raises(ValueError):
        EventPaymentReceivedSuccess(amount=-5, **kwargs)
