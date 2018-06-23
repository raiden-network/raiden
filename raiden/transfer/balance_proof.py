from eth_utils import encode_hex, decode_hex

import raiden_libs.messages
from raiden_libs.utils import sign_data

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
        nonce: bytes,
        transferred_amount: bytes,
        locked_amount: bytes,
        channel_address: bytes,
        locksroot: bytes,
        extra_hash: bytes,
) -> bytes:

    data_that_was_signed = (
        nonce +
        transferred_amount +
        locked_amount +
        locksroot +
        channel_address +
        extra_hash
    )

    return data_that_was_signed


def pack_signing_data2(
        nonce,
        balance_hash,
        additional_hash,
        channel_identifier,
        token_network_identifier,
        chain_id,
) -> bytes:
    balance_proof = raiden_libs.messages.BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=token_network_identifier,
        balance_hash=balance_hash,
        nonce=nonce,
        additional_hash=additional_hash,
        chain_id=chain_id,
    )

    return balance_proof.serialize_bin()


def signing_update_data(
        balance_proof: BalanceProofSignedState,
        chain_id: int,
        privkey: bytes,
) -> typing.Signature:
    update_data = pack_signing_data2(
        balance_proof.nonce,
        balance_proof.balance_hash,
        balance_proof.message_hash,
        balance_proof.channel_address,
        balance_proof.token_network_identifier,
        chain_id,
    ) + decode_hex(balance_proof.signature)

    return encode_hex(sign_data(privkey, update_data))
