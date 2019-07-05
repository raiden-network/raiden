from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.signing import pack_data
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    Nonce,
    Signature,
    TokenAmount,
    WithdrawAmount,
)
from raiden_contracts.constants import MessageTypeId


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
    canonical_identifier: CanonicalIdentifier,
    reward_amount: TokenAmount,
    nonce: Nonce,
    monitoring_service_contract_address: Address,
) -> bytes:
    channel_identifier = canonical_identifier.channel_identifier
    token_network_address = canonical_identifier.token_network_address
    chain_id = canonical_identifier.chain_identifier
    return pack_data(
        (monitoring_service_contract_address, "address"),
        (chain_id, "uint256"),
        (MessageTypeId.MSReward, "uint256"),
        (channel_identifier, "uint256"),
        (reward_amount, "uint256"),
        (token_network_address, "address"),
        (nonce, "uint256"),
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
