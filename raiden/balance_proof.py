from typing import TYPE_CHECKING

from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import BalanceProofSignedState
from raiden.transfer.utils import hash_balance_data
from raiden.utils.signer import recover
from raiden.utils.signing import pack_data
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    Nonce,
    Optional,
    Signature,
    SuccessOrError,
    TokenAmount,
)
from raiden_contracts.constants import MessageTypeId

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.messages import EnvelopeMessage


def balanceproof_from_envelope(
        envelope_message: 'EnvelopeMessage',
) -> Optional['BalanceProofSignedState']:
    if not envelope_message.sender:
        return None

    balance_proof = BalanceProofSignedState(
        nonce=envelope_message.nonce,
        transferred_amount=envelope_message.transferred_amount,
        locked_amount=envelope_message.locked_amount,
        locksroot=envelope_message.locksroot,
        message_hash=envelope_message.message_hash,
        signature=envelope_message.signature,
        sender=envelope_message.sender,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=envelope_message.chain_id,
            token_network_address=envelope_message.token_network_address,
            channel_identifier=envelope_message.channel_identifier,
        ),
    )

    signature_is_valid = is_valid_signature(
        balance_proof=balance_proof,
        sender_address=envelope_message.sender,
    )

    if signature_is_valid:
        return balance_proof
    return None


def is_valid_signature(
        balance_proof: BalanceProofSignedState,
        sender_address: Address,
) -> SuccessOrError:
    balance_hash = hash_balance_data(
        balance_proof.transferred_amount,
        balance_proof.locked_amount,
        balance_proof.locksroot,
    )

    # The balance proof must be tied to a single channel instance, through the
    # chain_id, token_network_identifier, and channel_identifier, otherwise the
    # on-chain contract would be susceptible to replay attacks across channels.
    #
    # The balance proof must also authenticate the offchain balance (blinded in
    # the balance_hash field), and authenticate the rest of message data
    # (blinded in additional_hash).
    data_that_was_signed = pack_balance_proof(
        nonce=balance_proof.nonce,
        balance_hash=balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=balance_proof.chain_id,
            token_network_address=balance_proof.token_network_identifier,
            channel_identifier=balance_proof.channel_identifier,
        ),
    )

    try:
        signer_address = recover(
            data=data_that_was_signed,
            signature=balance_proof.signature,
        )
        # InvalidSignature is raised by raiden.utils.signer.recover if signature
        # is not bytes or has the incorrect length
        #
        # ValueError is raised if the PublicKey instantiation failed, let it
        # propagate because it's a memory pressure problem.
        #
        # Exception is raised if the public key recovery failed.
    except Exception:  # pylint: disable=broad-except
        msg = 'Signature invalid, could not be recovered.'
        return (False, msg)

    is_correct_sender = sender_address == signer_address
    if is_correct_sender:
        return (True, None)

    msg = 'Signature was valid but the expected address does not match.'
    return (False, msg)


def pack_balance_proof(
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        canonical_identifier: CanonicalIdentifier,
        msg_type: MessageTypeId = MessageTypeId.BALANCE_PROOF,
) -> bytes:
    """Packs balance proof data to be signed

    Packs the given arguments in a byte array in the same configuration the
    contracts expect the signed data to have.
    """
    return pack_data([
        'address',
        'uint256',
        'uint256',
        'uint256',
        'bytes32',
        'uint256',
        'bytes32',
    ], [
        canonical_identifier.token_network_address,
        canonical_identifier.chain_identifier,
        msg_type,
        canonical_identifier.channel_identifier,
        balance_hash,
        nonce,
        additional_hash,
    ])


def pack_balance_proof_update(
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        canonical_identifier: CanonicalIdentifier,
        partner_signature: Signature,
) -> bytes:
    """Packs balance proof data to be signed for updateNonClosingBalanceProof

    Packs the given arguments in a byte array in the same configuration the
    contracts expect the signed data for updateNonClosingBalanceProof to have.
    """
    return pack_balance_proof(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=additional_hash,
        canonical_identifier=canonical_identifier,
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + partner_signature


def pack_reward_proof(
        canonical_identifier: CanonicalIdentifier,
        reward_amount: TokenAmount,
        nonce: Nonce,
) -> bytes:
    channel_identifier = canonical_identifier.channel_identifier
    token_network_address = canonical_identifier.token_network_address
    chain_id = canonical_identifier.chain_identifier
    return pack_data([
        'uint256',
        'uint256',
        'address',
        'uint256',
        'uint256',
    ], [
        channel_identifier,
        reward_amount,
        token_network_address,
        chain_id,
        nonce,
    ])
