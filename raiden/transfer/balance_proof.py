from raiden.utils.signing import pack_data
from raiden.utils.typing import (
    AdditionalHash,
    BalanceHash,
    ChainID,
    ChannelID,
    Nonce,
    Signature,
    TokenAmount,
    TokenNetworkID,
)
from raiden_contracts.constants import MessageTypeId


def pack_balance_proof(
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        channel_identifier: ChannelID,
        token_network_identifier: TokenNetworkID,
        chain_id: ChainID,
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
        token_network_identifier,
        chain_id,
        msg_type,
        channel_identifier,
        balance_hash,
        nonce,
        additional_hash,
    ])


def pack_balance_proof_update(
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        channel_identifier: ChannelID,
        token_network_identifier: TokenNetworkID,
        chain_id: ChainID,
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
        channel_identifier=channel_identifier,
        token_network_identifier=token_network_identifier,
        chain_id=chain_id,
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + partner_signature


def pack_reward_proof(
        channel_identifier: ChannelID,
        reward_amount: TokenAmount,
        token_network_address: TokenNetworkID,
        chain_id: ChainID,
        nonce: Nonce,
) -> bytes:
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
