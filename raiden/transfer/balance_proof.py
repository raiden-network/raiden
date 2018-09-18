from raiden.utils import typing
from raiden_contracts.constants import MessageTypeId
from raiden_libs.utils.signing import pack_data


def pack_balance_proof(
        nonce: typing.Nonce,
        balance_hash: typing.BalanceHash,
        additional_hash: typing.AdditionalHash,
        channel_identifier: typing.ChannelID,
        token_network_identifier: typing.TokenNetworkID,
        chain_id: typing.ChainID,
        msg_type: MessageTypeId = MessageTypeId.BALANCE_PROOF,
) -> bytes:
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
        nonce: typing.Nonce,
        balance_hash: typing.BalanceHash,
        additional_hash: typing.AdditionalHash,
        channel_identifier: typing.ChannelID,
        token_network_identifier: typing.TokenNetworkID,
        chain_id: typing.ChainID,
        partner_signature: typing.Signature,
) -> bytes:
    return pack_balance_proof(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=additional_hash,
        channel_identifier=channel_identifier,
        token_network_identifier=token_network_identifier,
        chain_id=chain_id,
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + partner_signature
