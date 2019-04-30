from dataclasses_json.mm import TYPES
from marshmallow import fields

from raiden.storage.serialization.fields import AddressField, BytesField
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    FeeAmount,
    LockedAmount,
    MessageID,
    Nonce,
    PaymentAmount,
    PaymentID,
    PaymentNetworkID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    Signature,
    TokenNetworkAddress,
    TokenNetworkID,
    TransactionHash,
    TransferID,
)

TYPES.update({
    # Addresses
    Address: AddressField,
    PaymentNetworkID: AddressField,
    SecretRegistryAddress: AddressField,
    TokenNetworkAddress: AddressField,
    TokenNetworkID: AddressField,

    # Bytes
    AdditionalHash: BytesField,
    BalanceHash: BytesField,
    BlockGasLimit: BytesField,
    BlockHash: BytesField,
    Secret: BytesField,
    SecretHash: BytesField,
    Signature: BytesField,
    TransactionHash: BytesField,

    # Ints
    BlockExpiration: fields.Int,
    BlockNumber: fields.Int,
    ChainID: fields.Int,
    ChannelID: fields.Int,
    FeeAmount: fields.Int,
    LockedAmount: fields.Int,
    MessageID: fields.Int,
    Nonce: fields.Int,
    PaymentAmount: fields.Int,
    PaymentID: fields.Int,
    PaymentWithFeeAmount: fields.Int,
    TransferID: fields.Int,
})
