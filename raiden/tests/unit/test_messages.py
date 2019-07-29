from unittest.mock import Mock

import pytest

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX, UINT256_MAX
from raiden.message_handler import MessageHandler
from raiden.messages.healthcheck import Ping
from raiden.messages.monitoring_service import RequestMonitoring, SignedBlindedBalanceProof
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.messages.synchronization import Delivered, Processed
from raiden.messages.transfers import RevealSecret, SecretRequest
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.tests import fixture_all_combinations
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
)
from raiden.transfer.state_change import ReceiveDelivered, ReceiveProcessed, ReceiveUnlock
from raiden.utils import sha3
from raiden.utils.packing import pack_balance_proof, pack_reward_proof, pack_signed_balance_proof
from raiden.utils.signer import LocalSigner, recover

MSC_ADDRESS = bytes([1] * 20)
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
        reward_amount=55,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
    )
    assert request_monitoring
    request_monitoring.sign(signer)
    as_dict = DictSerializer.serialize(request_monitoring)
    assert DictSerializer.deserialize(as_dict) == request_monitoring
    # RequestMonitoring can be created directly from BalanceProofSignedState
    direct_created = RequestMonitoring.from_balance_proof_signed_state(
        balance_proof, reward_amount=55, monitoring_service_contract_address=MSC_ADDRESS
    )
    # `direct_created` is not signed while request_monitoring is
    assert DictSerializer().serialize(direct_created) != DictSerializer().serialize(
        request_monitoring
    )

    direct_created.sign(signer)
    # Instances created from same balance proof are equal
    assert direct_created == request_monitoring
    other_balance_proof = factories.create(factories.replace(properties, message_hash=sha3(b"2")))
    other_instance = RequestMonitoring.from_balance_proof_signed_state(
        other_balance_proof, reward_amount=55, monitoring_service_contract_address=MSC_ADDRESS
    )
    other_instance.sign(signer)
    # different balance proof ==> non-equality
    assert other_instance != request_monitoring

    # test signature verification
    reward_proof_data = pack_reward_proof(
        chain_id=request_monitoring.balance_proof.chain_id,
        reward_amount=request_monitoring.reward_amount,
        monitoring_service_contract_address=MSC_ADDRESS,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    assert recover(reward_proof_data, request_monitoring.reward_proof_signature) == ADDRESS

    blinded_data = pack_signed_balance_proof(
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


def test_tamper_request_monitoring():
    """ This test shows ways, how the current implementation of the RequestMonitoring's
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
    )
    request_monitoring.sign(signer)

    # This is the signature, that is supposed to authenticate the message that a monitoring
    # service receives from a node. Note: It is generated on a valid Balance proof here and reused
    # to authenticate invalid messages throughout the rest of the test.
    exploited_signature = request_monitoring.reward_proof_signature

    reward_proof_data = pack_reward_proof(
        chain_id=request_monitoring.balance_proof.chain_id,
        reward_amount=request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
        non_closing_signature=request_monitoring.non_closing_signature,
    )

    # An attacker might change the balance hash
    partner_signed_balance_proof.balance_hash = "tampered".encode()

    tampered_balance_hash_request_monitoring = RequestMonitoring(
        balance_proof=partner_signed_balance_proof,
        reward_amount=55,
        signature=EMPTY_SIGNATURE,
        monitoring_service_contract_address=MSC_ADDRESS,
    )

    tampered_bp = tampered_balance_hash_request_monitoring.balance_proof
    tampered_balance_hash_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        reward_amount=tampered_balance_hash_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
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
    )

    tampered_bp = tampered_additional_hash_request_monitoring.balance_proof
    tampered_additional_hash_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        reward_amount=tampered_additional_hash_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
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
    )

    tampered_bp = tampered_non_closing_signature_request_monitoring.balance_proof
    tampered_non_closing_signature_reward_proof_data = pack_reward_proof(
        chain_id=tampered_bp.chain_id,
        reward_amount=tampered_non_closing_signature_request_monitoring.reward_amount,
        monitoring_service_contract_address=msc_address,
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
            "fee": [UINT256_MAX + 1],
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


def assert_method_call(mock, method, *args, **kwargs):
    child_mock = getattr(mock, method)
    child_mock.assert_called_once_with(*args, **kwargs)
    child_mock.reset_mock()


def test_message_handler():
    """
    Test for MessageHandler.on_message and the different methods it dispatches into.
    Each of them results in a call to a RaidenService method, which is checked with a Mock.
    """

    our_address = factories.make_address()
    sender_privkey, sender = factories.make_privkey_address()
    signer = LocalSigner(sender_privkey)
    message_handler = MessageHandler()
    mock_raiden = Mock(
        address=our_address, default_secret_registry=Mock(is_secret_registered=lambda **_: False)
    )

    properties = factories.LockedTransferProperties(sender=sender, pkey=sender_privkey)
    locked_transfer = factories.create(properties)
    message_handler.on_message(mock_raiden, locked_transfer)
    assert_method_call(mock_raiden, "mediate_mediated_transfer", locked_transfer)

    locked_transfer_for_us = factories.create(factories.replace(properties, target=our_address))
    message_handler.on_message(mock_raiden, locked_transfer_for_us)
    assert_method_call(mock_raiden, "target_mediated_transfer", locked_transfer_for_us)

    mock_raiden.default_secret_registry.is_secret_registered = lambda **_: True
    message_handler.on_message(mock_raiden, locked_transfer)
    assert not mock_raiden.mediate_mediated_transfer.called
    assert not mock_raiden.target_mediated_transfer.called
    mock_raiden.default_secret_registry.is_secret_registered = lambda **_: False

    params = dict(
        payment_identifier=13, amount=14, expiration=15, secrethash=factories.UNIT_SECRETHASH
    )
    secret_request = SecretRequest(
        message_identifier=16, signature=factories.EMPTY_SIGNATURE, **params
    )
    secret_request.sign(signer)
    receive = ReceiveSecretRequest(sender=sender, **params)
    message_handler.on_message(mock_raiden, secret_request)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])

    secret = factories.make_secret()
    reveal_secret = RevealSecret(
        message_identifier=100, signature=factories.EMPTY_SIGNATURE, secret=secret
    )
    reveal_secret.sign(signer)
    receive = ReceiveSecretReveal(sender=sender, secret=secret)
    message_handler.on_message(mock_raiden, reveal_secret)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])

    properties: factories.UnlockProperties = factories.create_properties(
        factories.UnlockProperties()
    )
    unlock = factories.create(properties)
    unlock.sign(signer)
    balance_proof = factories.make_signed_balance_proof_from_unsigned(
        factories.create(properties.balance_proof), signer, unlock.message_hash
    )
    receive = ReceiveUnlock(
        message_identifier=properties.message_identifier,
        secret=properties.secret,
        balance_proof=balance_proof,
        sender=sender,
    )
    message_handler.on_message(mock_raiden, unlock)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])

    properties: factories.LockExpiredProperties = factories.create_properties(
        factories.LockExpiredProperties()
    )
    lock_expired = factories.create(properties)
    lock_expired.sign(signer)
    balance_proof = factories.make_signed_balance_proof_from_unsigned(
        factories.create(properties.balance_proof), signer, lock_expired.message_hash
    )
    receive = ReceiveLockExpired(
        balance_proof=balance_proof,
        message_identifier=properties.message_identifier,
        secrethash=properties.secrethash,  # pylint: disable=no-member
        sender=sender,
    )
    message_handler.on_message(mock_raiden, lock_expired)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])

    delivered = Delivered(delivered_message_identifier=1, signature=factories.EMPTY_SIGNATURE)
    delivered.sign(signer)
    receive = ReceiveDelivered(message_identifier=1, sender=sender)
    message_handler.on_message(mock_raiden, delivered)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])

    processed = Processed(message_identifier=42, signature=factories.EMPTY_SIGNATURE)
    processed.sign(signer)
    receive = ReceiveProcessed(message_identifier=42, sender=sender)
    message_handler.on_message(mock_raiden, processed)
    assert_method_call(mock_raiden, "handle_and_track_state_changes", [receive])
