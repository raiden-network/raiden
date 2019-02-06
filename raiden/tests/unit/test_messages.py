import pytest

from raiden.messages import Ping, RequestMonitoring, SignedBlindedBalanceProof
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.messages import (
    MEDIATED_TRANSFER_INVALID_VALUES,
    PRIVKEY as PARTNER_PRIVKEY,
    REFUND_TRANSFER_INVALID_VALUES,
    make_balance_proof,
    make_lock,
    make_mediated_transfer,
    make_refund_transfer,
)
from raiden.utils.signer import LocalSigner

PRIVKEY, ADDRESS = make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_signature():
    ping = Ping(nonce=0, current_protocol_version=0)
    ping.sign(signer)
    assert ping.sender == ADDRESS


def test_mediated_transfer_out_of_bounds_values():
    for args in MEDIATED_TRANSFER_INVALID_VALUES:
        with pytest.raises(ValueError):
            make_mediated_transfer(**args)


def test_refund_transfer_out_of_bounds_values():
    for args in REFUND_TRANSFER_INVALID_VALUES:
        with pytest.raises(ValueError):
            make_refund_transfer(**args)


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


def test_request_monitoring():
    partner_signer = LocalSigner(PARTNER_PRIVKEY)
    balance_proof = make_balance_proof(signer=partner_signer, amount=1)
    partner_signed_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
        balance_proof,
    )
    request_monitoring = RequestMonitoring(
        onchain_balance_proof=partner_signed_balance_proof,
        reward_amount=55,
    )
    assert request_monitoring
    with pytest.raises(ValueError):
        request_monitoring.to_dict()
    request_monitoring.sign(signer)
    as_dict = request_monitoring.to_dict()
    assert RequestMonitoring.from_dict(as_dict) == request_monitoring
    packed = request_monitoring.pack(request_monitoring.packed())
    assert RequestMonitoring.unpack(packed) == request_monitoring
