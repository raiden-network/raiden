# -*- coding: utf-8 -*-
import pytest

from raiden.messages import (
    DirectTransfer,
    MediatedTransfer,
    RefundTransfer,
)
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_mediated_transfer,
    make_refund_transfer,
)
from raiden.tests.utils.factories import make_privkey_address

PRIVKEY, ADDRESS = make_privkey_address()


@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
def test_direct_transfer_min_max(identifier, nonce, transferred_amount):
    direct_transfer = make_direct_transfer(
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    direct_transfer.sign(PRIVKEY, ADDRESS)
    assert DirectTransfer.from_dict(direct_transfer.to_dict()) == direct_transfer


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('fee', [0, 2 ** 256 - 1])
def test_mediated_transfer_min_max(amount, identifier, fee, nonce, transferred_amount):
    mediated_transfer = make_mediated_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
    )

    mediated_transfer.sign(PRIVKEY, ADDRESS)
    assert MediatedTransfer.from_dict(mediated_transfer.to_dict()) == mediated_transfer


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
def test_refund_transfer_min_max(amount, identifier, nonce, transferred_amount):
    refund_transfer = make_refund_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    refund_transfer.sign(PRIVKEY, ADDRESS)
    assert RefundTransfer.from_dict(refund_transfer.to_dict()) == refund_transfer
