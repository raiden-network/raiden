import pytest

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.storage.serialization import JSONSerializer
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner

PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


@pytest.mark.parametrize("amount", [0, UINT256_MAX])
@pytest.mark.parametrize("payment_identifier", [0, UINT64_MAX])
@pytest.mark.parametrize("nonce", [1, UINT64_MAX])
@pytest.mark.parametrize("transferred_amount", [0, UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    mediated_transfer = factories.create(
        factories.LockedTransferProperties(
            amount=amount,
            payment_identifier=payment_identifier,
            nonce=nonce,
            transferred_amount=transferred_amount,
        )
    )

    mediated_transfer.sign(signer)
    data = JSONSerializer.serialize(mediated_transfer)
    assert JSONSerializer.deserialize(data) == mediated_transfer


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

    refund_transfer.sign(signer)

    data = JSONSerializer.serialize(refund_transfer)
    assert JSONSerializer.deserialize(data) == refund_transfer
