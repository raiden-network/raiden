from eth_utils import encode_hex

from raiden_libs.utils import (
    pack_data,
    sign_data,
    to_checksum_address,
)

from raiden.transfer.state import BalanceProofSignedState
from raiden.encoding.messages import (
    nonce as nonce_field,
    transferred_amount as transferred_amount_field,
    locked_amount as locked_amount_field,
)
from raiden.utils import typing


def signing_data(
        nonce: int,
        transferred_amount: int,
        locked_amount: int,
        channel_address: bytes,
        locksroot: bytes,
        extra_hash: bytes,
) -> bytes:

    nonce_bytes = nonce_field.encoder.encode(nonce, nonce_field.size_bytes)
    pad_size = nonce_field.size_bytes - len(nonce_bytes)
    nonce_bytes_padded = nonce_bytes.rjust(pad_size, b'\x00')

    transferred_amount_bytes = transferred_amount_field.encoder.encode(
        transferred_amount,
        transferred_amount_field.size_bytes,
    )
    transferred_amount_bytes_padded = transferred_amount_bytes.rjust(pad_size, b'\x00')

    locked_amount_bytes = locked_amount_field.encoder.encode(
        locked_amount,
        locked_amount_field.size_bytes,
    )
    locked_amount_bytes_padded = locked_amount_bytes.rjust(pad_size, b'\x00')

    data_that_was_signed = (
        nonce_bytes_padded +
        transferred_amount_bytes_padded +
        locked_amount_bytes_padded +
        locksroot +
        channel_address +
        extra_hash
    )

    return data_that_was_signed


def pack_signing_data(
        nonce,
        balance_hash,
        additional_hash,
        channel_identifier,
        token_network_identifier,
        chain_id,
) -> bytes:
    return pack_data([
        'bytes32',
        'uint256',
        'bytes32',
        'bytes32',
        'address',
        'uint256',
    ], [
        balance_hash,
        nonce,
        additional_hash,
        channel_identifier,
        to_checksum_address(token_network_identifier),
        chain_id,
    ])


def signing_update_data(
        balance_proof: BalanceProofSignedState,
        privkey: bytes,
) -> typing.Signature:
    update_data = pack_signing_data(
        balance_proof.nonce,
        balance_proof.balance_hash,
        balance_proof.message_hash,
        balance_proof.channel_address,
        balance_proof.token_network_identifier,
        balance_proof.chain_id,
    ) + balance_proof.signature

    return sign_data(encode_hex(privkey), update_data)
