import pytest

from raiden.messages import Ping, RequestMonitoring, SignedBlindedBalanceProof, UpdatePFS
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.messages import (
    ADDRESS as PARTNER_ADDRESS,
    MEDIATED_TRANSFER_INVALID_VALUES,
    PRIVKEY as PARTNER_PRIVKEY,
    REFUND_TRANSFER_INVALID_VALUES,
    make_balance_proof,
    make_lock,
    make_mediated_transfer,
    make_refund_transfer,
)
from raiden.transfer.balance_proof import (
    pack_balance_proof,
    pack_balance_proof_update,
    pack_reward_proof,
)
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.utils import CanonicalIdentifier
from raiden.utils.signer import LocalSigner, recover

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
    # RequestMonitoring can be created directly from BalanceProofSignedState
    direct_created = RequestMonitoring.from_balance_proof_signed_state(
        balance_proof,
        reward_amount=55,
    )
    with pytest.raises(ValueError):
        # equality test uses `validated` packed format
        assert direct_created == request_monitoring

    direct_created.sign(signer)
    # Instances created from same balance proof are equal
    assert direct_created == request_monitoring
    other_balance_proof = make_balance_proof(signer=partner_signer, amount=2)
    other_instance = RequestMonitoring.from_balance_proof_signed_state(
        other_balance_proof,
        reward_amount=55,
    )
    other_instance.sign(signer)
    # different balance proof ==> non-equality
    assert other_instance != request_monitoring

    # test signature verification
    reward_proof_data = pack_reward_proof(
        request_monitoring.balance_proof.channel_identifier,
        request_monitoring.reward_amount,
        request_monitoring.balance_proof.token_network_address,
        request_monitoring.balance_proof.chain_id,
        request_monitoring.balance_proof.nonce,
    )

    assert recover(reward_proof_data, request_monitoring.reward_proof_signature) == ADDRESS

    blinded_data = pack_balance_proof_update(
        nonce=request_monitoring.balance_proof.nonce,
        balance_hash=request_monitoring.balance_proof.balance_hash,
        additional_hash=request_monitoring.balance_proof.additional_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=request_monitoring.balance_proof.chain_id,
            token_network_address=request_monitoring.balance_proof.token_network_address,
            channel_identifier=request_monitoring.balance_proof.channel_identifier,
        ),
        partner_signature=request_monitoring.balance_proof.signature,
    )
    assert recover(blinded_data, request_monitoring.non_closing_signature) == ADDRESS

    balance_proof_data = pack_balance_proof(
        nonce=request_monitoring.balance_proof.nonce,
        balance_hash=request_monitoring.balance_proof.balance_hash,
        additional_hash=request_monitoring.balance_proof.additional_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=request_monitoring.balance_proof.chain_id,
            token_network_address=request_monitoring.balance_proof.token_network_address,
            channel_identifier=request_monitoring.balance_proof.channel_identifier,
        ),
    )
    assert recover(
        balance_proof_data,
        request_monitoring.balance_proof.signature,
    ) == PARTNER_ADDRESS

    assert request_monitoring.verify_request_monitoring(PARTNER_ADDRESS, ADDRESS)


def test_update_pfs():
    balance_proof = BalanceProofUnsignedState.from_dict(
        make_balance_proof(signer=signer, amount=1).to_dict(),
    )
    message = UpdatePFS.from_balance_proof(
        balance_proof=balance_proof,
        reveal_timeout=1,
    )
    assert message.signature == b''
    message.sign(signer)
    assert recover(message._data_to_sign(), message.signature) == ADDRESS
