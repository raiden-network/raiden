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
    EncodedData,
    FeeAmount,
    InitiatorAddress,
    LockedAmount,
    LockHash,
    Locksroot,
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
    TargetAddress,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkID,
    TransactionHash,
    TransferID,
    Union,
)


def determine_types(*args):
    first_type = type(args[0])

    for arg in args:
        if type(arg) != first_type:
            return None
    return args[0]


TYPES.update({
    # Addresses
    Address: AddressField,
    InitiatorAddress: AddressField,
    PaymentNetworkID: AddressField,
    SecretRegistryAddress: AddressField,
    TargetAddress: AddressField,
    TokenAddress: AddressField,
    TokenNetworkAddress: AddressField,
    TokenNetworkID: AddressField,

    # Bytes
    EncodedData: BytesField,
    AdditionalHash: BytesField,
    BalanceHash: BytesField,
    BlockGasLimit: BytesField,
    BlockHash: BytesField,
    Locksroot: BytesField,
    LockHash: BytesField,
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

    # Union
    Union: determine_types,
})
