import pytest

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import DirectTransfer, LockedTransfer, RefundTransfer
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_mediated_transfer,
    make_refund_transfer,
)

PRIVKEY, ADDRESS = make_privkey_address()


@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
def test_direct_transfer_min_max(payment_identifier, nonce, transferred_amount):
    direct_transfer = make_direct_transfer(
        payment_identifier=payment_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    direct_transfer.sign(PRIVKEY)
    assert DirectTransfer.from_dict(direct_transfer.to_dict()) == direct_transfer


@pytest.mark.parametrize('amount', [0, UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
@pytest.mark.parametrize('fee', [0, UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, fee, nonce, transferred_amount):
    mediated_transfer = make_mediated_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
    )

    mediated_transfer.sign(PRIVKEY)
    assert LockedTransfer.from_dict(mediated_transfer.to_dict()) == mediated_transfer


@pytest.mark.parametrize('amount', [0, UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
def test_refund_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    refund_transfer = make_refund_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    refund_transfer.sign(PRIVKEY)
    assert RefundTransfer.from_dict(refund_transfer.to_dict()) == refund_transfer
