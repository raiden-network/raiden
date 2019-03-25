import pytest

from raiden.messages import Ping, RequestMonitoring, SignedBlindedBalanceProof, UpdatePFS
from raiden.tests.utils.factories import (
    make_canonical_identifier,
    make_channel_state,
    make_privkey_address,
)
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
        canonical_identifier=make_canonical_identifier(
            chain_identifier=request_monitoring.balance_proof.chain_id,
            token_network_address=request_monitoring.balance_proof.token_network_address,
            channel_identifier=request_monitoring.balance_proof.channel_identifier,
        ),
        reward_amount=request_monitoring.reward_amount,
        nonce=request_monitoring.balance_proof.nonce,
    )

    assert recover(reward_proof_data, request_monitoring.reward_proof_signature) == ADDRESS

    blinded_data = pack_balance_proof_update(
        nonce=request_monitoring.balance_proof.nonce,
        balance_hash=request_monitoring.balance_proof.balance_hash,
        additional_hash=request_monitoring.balance_proof.additional_hash,
        canonical_identifier=make_canonical_identifier(
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
        canonical_identifier=make_canonical_identifier(
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
    balance_proof = make_balance_proof(signer=signer, amount=1)

    channel_state = make_channel_state()
    channel_state.our_state.balance_proof = balance_proof
    channel_state.partner_state.balance_proof = balance_proof
    message = UpdatePFS.from_channel_state(channel_state=channel_state)

    assert message.signature == b''
    privkey2, address2 = make_privkey_address()
    signer2 = LocalSigner(privkey2)
    message.sign(signer2)
    assert recover(message._data_to_sign(), message.signature) == address2

    assert message == UpdatePFS.from_dict(message.to_dict())


def test_tamper_request_monitoring():
    """ This test shows ways, how the current implementation of the RequestMonitoring's
    signature scheme might be used by an attacker to tamper with the BalanceProof that is
    incorporated in the RequestMonitoring message, if not all three signatures are verified."""
    partner_signer = LocalSigner(PARTNER_PRIVKEY)

    balance_proof = make_balance_proof(signer=partner_signer, amount=1)
    partner_signed_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
        balance_proof,
    )
    request_monitoring = RequestMonitoring(
        onchain_balance_proof=partner_signed_balance_proof,
        reward_amount=55,
    )
    request_monitoring.sign(signer)

    # This is the signature, that is supposed to authenticate the message that a monitoring
    # service receives from a node. Note: It is generated on a valid Balance proof here and reused
    # to authenticate invalid messages throughout the rest of the test.
    exploited_signature = request_monitoring.reward_proof_signature

    reward_proof_data = pack_reward_proof(
        canonical_identifier=make_canonical_identifier(
            chain_identifier=request_monitoring.balance_proof.chain_id,
            token_network_address=request_monitoring.balance_proof.token_network_address,
            channel_identifier=request_monitoring.balance_proof.channel_identifier,
        ),
        reward_amount=request_monitoring.reward_amount,
        nonce=request_monitoring.balance_proof.nonce,
    )

    # An attacker might change the balance hash
    partner_signed_balance_proof.balance_hash = 'tampered'.encode()

    tampered_balance_hash_request_monitoring = RequestMonitoring(
        onchain_balance_proof=partner_signed_balance_proof,
        reward_amount=55,
    )

    tampered_bp = tampered_balance_hash_request_monitoring.balance_proof
    tampered_balance_hash_reward_proof_data = pack_reward_proof(
        canonical_identifier=make_canonical_identifier(
            chain_identifier=tampered_bp.chain_id,
            token_network_address=tampered_bp.token_network_address,
            channel_identifier=tampered_bp.channel_identifier,
        ),
        reward_amount=tampered_balance_hash_request_monitoring.reward_amount,
        nonce=tampered_balance_hash_request_monitoring.balance_proof.nonce,
    )
    # The signature works/is unaffected by that change...
    recovered_address_tampered = recover(
        tampered_balance_hash_reward_proof_data,
        exploited_signature,
    )

    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recover(tampered_balance_hash_reward_proof_data, exploited_signature) == ADDRESS

    # ...but overall verification fails
    assert not tampered_balance_hash_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS,
        ADDRESS,
    )

    # An attacker might change the additional_hash
    partner_signed_balance_proof.additional_hash = 'tampered'.encode()

    tampered_additional_hash_request_monitoring = RequestMonitoring(
        onchain_balance_proof=partner_signed_balance_proof,
        reward_amount=55,
    )

    tampered_bp = tampered_additional_hash_request_monitoring.balance_proof
    tampered_additional_hash_reward_proof_data = pack_reward_proof(
        canonical_identifier=make_canonical_identifier(
            chain_identifier=tampered_bp.chain_id,
            token_network_address=tampered_bp.token_network_address,
            channel_identifier=tampered_bp.channel_identifier,
        ),
        reward_amount=tampered_additional_hash_request_monitoring.reward_amount,
        nonce=tampered_additional_hash_request_monitoring.balance_proof.nonce,
    )

    # The signature works/is unaffected by that change...

    recovered_address_tampered = recover(
        tampered_additional_hash_reward_proof_data,
        exploited_signature,
    )

    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recovered_address_tampered == ADDRESS

    # ...but overall verification fails
    assert not tampered_balance_hash_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS,
        ADDRESS,
    )
    # An attacker can change the non_closing_signature
    partner_signed_balance_proof.non_closing_signature = 'tampered'.encode()

    tampered_non_closing_signature_request_monitoring = RequestMonitoring(
        onchain_balance_proof=partner_signed_balance_proof,
        reward_amount=55,
    )

    tampered_bp = tampered_non_closing_signature_request_monitoring.balance_proof
    tampered_non_closing_signature_reward_proof_data = pack_reward_proof(
        canonical_identifier=make_canonical_identifier(
            chain_identifier=tampered_bp.chain_id,
            token_network_address=tampered_bp.token_network_address,
            channel_identifier=tampered_bp.channel_identifier,
        ),
        reward_amount=tampered_non_closing_signature_request_monitoring.reward_amount,
        nonce=tampered_non_closing_signature_request_monitoring.balance_proof.nonce,
    )

    # The signature works/is unaffected by that change...

    recovered_address_tampered = recover(
        tampered_non_closing_signature_reward_proof_data,
        exploited_signature,
    )
    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recovered_address_tampered == ADDRESS

    # ...but overall verification fails
    assert not tampered_non_closing_signature_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS,
        ADDRESS,
    )
