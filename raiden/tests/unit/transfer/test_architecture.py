from os import urandom

import pytest

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.tests.utils import factories


def test_balance_proof_invalid_attributes():
    invalid_nonces = [-10, 0, UINT64_MAX + 1]
    invalid_transferred_amounts = [-1, UINT256_MAX + 1]
    invalid_locksroots = [urandom(31), urandom(33)]
    invalid_signatures = [urandom(64), urandom(66)]

    properties_unsigned = factories.BalanceProofProperties()
    properties_signed = factories.BalanceProofSignedStateProperties(signature=urandom(64))

    for properties in (properties_unsigned, properties_signed):
        for nonce in invalid_nonces:
            with pytest.raises(ValueError):
                factories.create(factories.replace(properties, nonce=nonce))

        for amount in invalid_transferred_amounts:
            with pytest.raises(ValueError):
                factories.create(factories.replace(properties, transferred_amount=amount))

        for locksroot in invalid_locksroots:
            with pytest.raises(ValueError):
                factories.create(factories.replace(properties, locksroot=locksroot))

    for signature in invalid_signatures:
        with pytest.raises(ValueError):
            factories.create(factories.replace(properties_signed, signature=signature))
