from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.formatting import to_hex_address
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    ChainID,
    MonitoringServiceAddress,
    Nonce,
    Signature,
    TokenAmount,
    TokenNetworkAddress,
    WithdrawAmount,
)
from raiden_contracts.constants import MessageTypeId
from raiden_contracts.utils import proofs


def pack_balance_proof(
    nonce: Nonce,
    balance_hash: BalanceHash,
    additional_hash: AdditionalHash,
    canonical_identifier: CanonicalIdentifier,
) -> bytes:
    """Packs balance proof data to be signed

    Packs the given arguments in a byte array in the same configuration the
    contracts expect the signed data to have.
    """
    return proofs.pack_balance_proof(
        token_network_address=to_hex_address(canonical_identifier.token_network_address),
        chain_identifier=canonical_identifier.chain_identifier,
        channel_identifier=canonical_identifier.channel_identifier,
        msg_type=MessageTypeId.BALANCE_PROOF,
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=additional_hash,
    )


def pack_signed_balance_proof(
    msg_type: MessageTypeId,
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
    return proofs.pack_balance_proof_message(
        token_network_address=to_hex_address(canonical_identifier.token_network_address),
        chain_identifier=canonical_identifier.chain_identifier,
        channel_identifier=canonical_identifier.channel_identifier,
        msg_type=msg_type,
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=additional_hash,
        closing_signature=partner_signature,
    )


def pack_reward_proof(
    chain_id: ChainID,
    token_network_address: TokenNetworkAddress,
    reward_amount: TokenAmount,
    monitoring_service_contract_address: MonitoringServiceAddress,
    non_closing_participant: Address,
    non_closing_signature: Signature,
) -> bytes:
    return proofs.pack_reward_proof(
        monitoring_service_contract_address=to_hex_address(monitoring_service_contract_address),
        chain_id=chain_id,
        token_network_address=to_hex_address(token_network_address),
        non_closing_participant=to_hex_address(non_closing_participant),
        non_closing_signature=non_closing_signature,
        reward_amount=reward_amount,
    )


def pack_withdraw(
    canonical_identifier: CanonicalIdentifier,
    participant: Address,
    total_withdraw: WithdrawAmount,
    expiration_block: BlockExpiration,
) -> bytes:
    """Packs withdraw data to be signed

    Packs the given arguments in a byte array in the same configuration the
    contracts expect the signed data to have.
    """
    return proofs.pack_withdraw_message(
        token_network_address=to_hex_address(canonical_identifier.token_network_address),
        chain_identifier=canonical_identifier.chain_identifier,
        channel_identifier=canonical_identifier.channel_identifier,
        participant=to_hex_address(participant),
        amount_to_withdraw=TokenAmount(total_withdraw),
        expiration_block=expiration_block,
    )
