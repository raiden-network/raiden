import pytest
from eth_utils import keccak

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX, UINT256_MAX
from raiden.messages.healthcheck import Ping
from raiden.messages.monitoring_service import RequestMonitoring, SignedBlindedBalanceProof
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.tests import fixture_all_combinations
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.utils.packing import pack_balance_proof, pack_reward_proof, pack_signed_balance_proof
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MonitoringServiceAddress, TokenAmount
from raiden_contracts.constants import MessageTypeId

MSC_ADDRESS = MonitoringServiceAddress(bytes([1] * 20))
PARTNER_PRIVKEY, PARTNER_ADDRESS = factories.make_privkey_address()
PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_signature():
    ping = Ping(nonce=0, current_protocol_version=0, signature=EMPTY_SIGNATURE)
    ping.sign(signer)
    assert ping.sender == ADDRESS


def test_request_monitoring() -> None:
    properties = factories.BalanceProofSignedStateProperties(pkey=PARTNER_PRIVKEY)
    balance_proof = factories.create(properties)
    partner_signed_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
        balance_proof
    )
    request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        non_closing_participant=ADDRESS,
        reward_amount=TokenAmount(55),
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
    )
    assert request_monitoring
    request_monitoring.sign(signer)
    as_dict = DictSerializer.serialize(request_monitoring)
    assert DictSerializer.deserialize(as_dict) == request_monitoring
    # RequestMonitoring can be created directly from BalanceProofSignedState
    direct_created = RequestMonitoring.from_balance_proof_signed_state(
        balance_proof=balance_proof,
        non_closing_participant=ADDRESS,
        reward_amount=TokenAmount(55),
        monitoring_service_contract_address=MSC_ADDRESS,
    )
    # `direct_created` is not signed while request_monitoring is
    assert DictSerializer().serialize(direct_created) != DictSerializer().serialize(
        request_monitoring
    )

    direct_created.sign(signer)
    # Instances created from same balance proof are equal
    assert direct_created == request_monitoring
    other_balance_proof = factories.create(
        factories.replace(properties, message_hash=keccak(b"2"))
    )
    other_instance = RequestMonitoring.from_balance_proof_signed_state(
        balance_proof=other_balance_proof,
        non_closing_participant=ADDRESS,
        reward_amount=TokenAmount(55),
        monitoring_service_contract_address=MSC_ADDRESS,
    )
    other_instance.sign(signer)
    # different balance proof ==> non-equality
    assert other_instance != request_monitoring

    # test signature verification
    assert request_monitoring.non_closing_signature
    reward_proof_data = pack_reward_proof(
        token_network_address=request_monitoring.balance_proof.token_network_address,
        chain_id=request_monitoring.balance_proof.chain_id,
        reward_amount=request_monitoring.reward_amount,
        monitoring_service_contract_address=MSC_ADDRESS,
        non_closing_participant=ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    assert request_monitoring.reward_proof_signature
    assert recover(reward_proof_data, request_monitoring.reward_proof_signature) == ADDRESS

    blinded_data = pack_signed_balance_proof(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
        nonce=request_monitoring.balance_proof.nonce,
        balance_hash=request_monitoring.balance_proof.balance_hash,
        additional_hash=request_monitoring.balance_proof.additional_hash,
        canonical_identifier=factories.make_canonical_identifier(
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
        canonical_identifier=factories.make_canonical_identifier(
            chain_identifier=request_monitoring.balance_proof.chain_id,
            token_network_address=request_monitoring.balance_proof.token_network_address,
            channel_identifier=request_monitoring.balance_proof.channel_identifier,
        ),
    )
    assert (
        recover(balance_proof_data, request_monitoring.balance_proof.signature) == PARTNER_ADDRESS
    )

    assert request_monitoring.verify_request_monitoring(PARTNER_ADDRESS, ADDRESS)


def test_update_pfs():
    properties = factories.BalanceProofSignedStateProperties(pkey=PRIVKEY)
    balance_proof = factories.create(properties)
    channel_state = factories.create(factories.NettingChannelStateProperties())
    channel_state.our_state.balance_proof = balance_proof
    channel_state.partner_state.balance_proof = balance_proof
    message = PFSCapacityUpdate.from_channel_state(channel_state=channel_state)

    assert message.signature == EMPTY_SIGNATURE
    privkey2, address2 = factories.make_privkey_address()
    signer2 = LocalSigner(privkey2)
    message.sign(signer2)
    assert recover(message._data_to_sign(), message.signature) == address2

    assert message == DictSerializer.deserialize(DictSerializer.serialize(message))


def test_fee_update():
    channel_state = factories.create(factories.NettingChannelStateProperties())
    message = PFSFeeUpdate.from_channel_state(channel_state)
    message.sign(signer)

    assert message == DictSerializer.deserialize(DictSerializer.serialize(message))


def test_fee_schedule_state():
    """Don't serialize internal functions

    Regression test for https://github.com/raiden-network/raiden/issues/4367
    """
    state = FeeScheduleState(imbalance_penalty=[])
    assert "_penalty_func" not in DictSerializer.serialize(state)


def test_tamper_request_monitoring():
    """This test shows ways, how the current implementation of the RequestMonitoring's
    signature scheme might be used by an attacker to tamper with the BalanceProof that is
    incorporated in the RequestMonitoring message, if not all three signatures are verified."""
    msc_address = bytes([1] * 20)
    properties = factories.BalanceProofSignedStateProperties(pkey=PARTNER_PRIVKEY)
    balance_proof = factories.create(properties)

    partner_signed_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
        balance_proof
    )
    request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        reward_amount=55,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=msc_address,
        non_closing_participant=ADDRESS,
    )
    request_monitoring.sign(signer)

    # This is the signature, that is supposed to authenticate the message that a monitoring
    # service receives from a node. Note: It is generated on a valid Balance proof here and reused
    # to authenticate invalid messages throughout the rest of the test.
    exploited_signature = request_monitoring.reward_proof_signature

    reward_proof_data = pack_reward_proof(
        chain_id=request_monitoring.balance_proof.chain_id,
        token_network_address=request_monitoring.balance_proof.token_network_address,
        reward_amount=request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
        non_closing_participant=ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    # An attacker might change the balance hash
    partner_signed_balance_proof.balance_hash = "tampered".encode()

    tampered_balance_hash_request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        reward_amount=55,
        non_closing_participant=ADDRESS,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
    )

    tampered_bp = tampered_balance_hash_request_monitoring.balance_proof
    tampered_balance_hash_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        token_network_address=request_monitoring.balance_proof.token_network_address,
        reward_amount=tampered_balance_hash_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
        non_closing_participant=ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )
    # The signature works/is unaffected by that change...
    recovered_address_tampered = recover(
        tampered_balance_hash_reward_proof_data, exploited_signature
    )

    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recover(tampered_balance_hash_reward_proof_data, exploited_signature) == ADDRESS

    # ...but overall verification fails
    assert not tampered_balance_hash_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS, ADDRESS
    )

    # An attacker might change the additional_hash
    partner_signed_balance_proof.additional_hash = "tampered".encode()

    tampered_additional_hash_request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        reward_amount=55,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
        non_closing_participant=ADDRESS,
    )

    tampered_bp = tampered_additional_hash_request_monitoring.balance_proof
    tampered_additional_hash_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        token_network_address=(
            tampered_additional_hash_request_monitoring.balance_proof.token_network_address
        ),
        reward_amount=tampered_additional_hash_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
        non_closing_participant=ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    # The signature works/is unaffected by that change...

    recovered_address_tampered = recover(
        tampered_additional_hash_reward_proof_data, exploited_signature
    )

    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recovered_address_tampered == ADDRESS

    # ...but overall verification fails
    assert not tampered_balance_hash_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS, ADDRESS
    )
    # An attacker can change the non_closing_signature
    partner_signed_balance_proof.non_closing_signature = "tampered".encode()

    tampered_non_closing_signature_request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        reward_amount=55,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
        non_closing_participant=ADDRESS,
    )

    tampered_bp = tampered_non_closing_signature_request_monitoring.balance_proof
    tampered_non_closing_signature_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        token_network_address=(
            tampered_non_closing_signature_request_monitoring.balance_proof.token_network_address
        ),
        reward_amount=tampered_non_closing_signature_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
        non_closing_participant=ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    # The signature works/is unaffected by that change...

    recovered_address_tampered = recover(
        tampered_non_closing_signature_reward_proof_data, exploited_signature
    )
    assert recover(reward_proof_data, exploited_signature) == recovered_address_tampered
    assert recovered_address_tampered == ADDRESS

    # ...but overall verification fails
    assert not tampered_non_closing_signature_request_monitoring.verify_request_monitoring(
        PARTNER_ADDRESS, ADDRESS
    )


@pytest.fixture
def invalid_values():
    invalid_addresses = [b" ", b" " * 19, b" " * 21]
    # zero is used to indicate novalue in solidity, that is why it's an invalid nonce value
    return fixture_all_combinations(
        {
            "nonce": [0, -1, UINT64_MAX + 1],
            "payment_identifier": [-1, UINT64_MAX + 1],
            "token": invalid_addresses,
            "recipient": invalid_addresses,
            "transferred_amount": [-1, UINT256_MAX + 1],
            "target": invalid_addresses,
            "initiator": invalid_addresses,
        }
    )


def test_mediated_transfer_invalid_values(invalid_values):
    for invalid_value in invalid_values:
        with pytest.raises(ValueError):
            factories.create(factories.LockedTransferProperties(**invalid_value))


def test_refund_transfer_invalid_values(invalid_values):
    for invalid_value in invalid_values:
        with pytest.raises(ValueError):
            factories.create(factories.RefundTransferProperties(**invalid_value))
