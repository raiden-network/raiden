from raiden_libs.utils.signing import pack_data, eth_sign
from raiden_contracts.constants import MessageTypeId

from raiden.transfer.state import BalanceProofSignedState
from raiden.utils import typing


def pack_signing_data(
        nonce,
        balance_hash,
        additional_hash,
        channel_identifier,
        token_network_identifier,
        chain_id,
        msg_type: MessageTypeId=MessageTypeId.BALANCE_PROOF,
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


def signing_update_data(
        balance_proof: BalanceProofSignedState,
        privkey: bytes,
) -> typing.Signature:
    update_data = pack_signing_data(
        balance_proof.nonce,
        balance_proof.balance_hash,
        balance_proof.message_hash,
        balance_proof.channel_identifier,
        balance_proof.token_network_identifier,
        balance_proof.chain_id,
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + balance_proof.signature

    return eth_sign(privkey=privkey, data=update_data)
