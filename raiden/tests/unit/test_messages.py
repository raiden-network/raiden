import pytest

from raiden.messages import Ping
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_lock,
    make_mediated_transfer,
    make_refund_transfer,
    MEDIATED_TRANSFER_INVALID_VALUES,
    REFUND_TRANSFER_INVALID_VALUES,
    DIRECT_TRANSFER_INVALID_VALUES,
)
from raiden.tests.utils.factories import make_privkey_address

PRIVKEY, ADDRESS = make_privkey_address()


def test_signature():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY)
    assert ping.sender == ADDRESS


def test_mediated_transfer_out_of_bounds_values():
    for args in MEDIATED_TRANSFER_INVALID_VALUES:
        with pytest.raises(ValueError):
            make_mediated_transfer(**args)


def test_refund_transfer_out_of_bounds_values():
    for args in REFUND_TRANSFER_INVALID_VALUES:
        with pytest.raises(ValueError):
            make_refund_transfer(**args)


def test_direct_transfer_out_of_bounds_values():
    for args in DIRECT_TRANSFER_INVALID_VALUES:
        with pytest.raises(ValueError):
            make_direct_transfer(**args)


@pytest.mark.parametrize('amount', [-1, 2 ** 256])
@pytest.mark.parametrize(
    'make',
    [
        make_lock,
        make_mediated_transfer,
    ],
)
def test_amount_out_of_bounds(amount, make):
    with pytest.raises(ValueError):
        make(amount=amount)
