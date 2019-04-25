import pytest

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import LockedTransfer, RefundTransfer
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner

PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


@pytest.mark.parametrize("amount", [0, UINT256_MAX])
@pytest.mark.parametrize("payment_identifier", [0, UINT64_MAX])
@pytest.mark.parametrize("nonce", [1, UINT64_MAX])
@pytest.mark.parametrize("transferred_amount", [0, UINT256_MAX])
@pytest.mark.parametrize("fee", [0, UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, fee, nonce, transferred_amount):
    mediated_transfer = factories.create(
        factories.LockedTransferProperties(
            amount=amount,
            payment_identifier=payment_identifier,
            nonce=nonce,
            fee=fee,
            transferred_amount=transferred_amount,
        )
    )
    assert LockedTransfer.from_dict(mediated_transfer.to_dict()) == mediated_transfer


@pytest.mark.parametrize("amount", [0, UINT256_MAX])
@pytest.mark.parametrize("payment_identifier", [0, UINT64_MAX])
@pytest.mark.parametrize("nonce", [1, UINT64_MAX])
@pytest.mark.parametrize("transferred_amount", [0, UINT256_MAX])
def test_refund_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    refund_transfer = factories.create(
        factories.RefundTransferProperties(
            amount=amount,
            payment_identifier=payment_identifier,
            nonce=nonce,
            transferred_amount=transferred_amount,
        )
    )
    assert RefundTransfer.from_dict(refund_transfer.to_dict()) == refund_transfer
