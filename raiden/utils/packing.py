from eth_utils import to_checksum_address

from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.signing import pack_data
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    ChainID,
    Nonce,
    Signature,
    TokenAmount,
    WithdrawAmount,
)
from raiden_contracts.constants import MessageTypeId
from raiden_contracts.utils import proofs


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
    return pack_data(
        (canonical_identifier.token_network_address, "address"),
        (canonical_identifier.chain_identifier, "uint256"),
        (msg_type, "uint256"),
        (canonical_identifier.channel_identifier, "uint256"),
        (balance_hash, "bytes32"),
        (nonce, "uint256"),
        (additional_hash, "bytes32"),
    )


def pack_signed_balance_proof(
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
    return (
        pack_balance_proof(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            canonical_identifier=canonical_identifier,
            msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
        )
        + partner_signature
    )


def pack_reward_proof(
    chain_id: ChainID,
    reward_amount: TokenAmount,
    monitoring_service_contract_address: Address,
    non_closing_signature: Signature,
) -> bytes:
    return proofs.pack_reward_proof(
        to_checksum_address(monitoring_service_contract_address),
        chain_id,
        non_closing_signature,
        reward_amount,
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
    token_network_address,
    chain_id,
    uint256(MessageTypeId.Withdraw),
    channel_identifier,
    participant_address,
    total_withdraw
    """
    return pack_data(
        (canonical_identifier.token_network_address, "address"),
        (canonical_identifier.chain_identifier, "uint256"),
        (MessageTypeId.WITHDRAW, "uint256"),
        (canonical_identifier.channel_identifier, "uint256"),
        (participant, "address"),
        (total_withdraw, "uint256"),
        (expiration_block, "uint256"),
    )
