from random import Random

from marshmallow import fields
from marshmallow_dataclass import _native_to_marshmallow

from raiden.storage.serialization.fields import (
    AddressField,
    BytesField,
    IntegerToStringField,
    PRNGField,
)
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
    Keccak256,
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

_native_to_marshmallow.update(
    {
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
        BlockHash: BytesField,
        Keccak256: BytesField,
        Locksroot: BytesField,
        LockHash: BytesField,
        Secret: BytesField,
        SecretHash: BytesField,
        Signature: BytesField,
        TransactionHash: BytesField,
        # Ints
        BlockExpiration: fields.Int,
        BlockNumber: fields.Int,
        FeeAmount: fields.Int,
        LockedAmount: fields.Int,
        BlockGasLimit: fields.Int,
        MessageID: fields.Int,
        Nonce: fields.Int,
        PaymentAmount: fields.Int,
        PaymentID: fields.Int,
        PaymentWithFeeAmount: fields.Int,
        TransferID: fields.Int,
        # Integers which should be converted to strings
        # This is done for querying purposes as sqlite
        # integer type is smaller than python's.
        ChainID: IntegerToStringField,
        ChannelID: IntegerToStringField,
        # Union
        Union[TokenNetworkAddress, TokenNetworkID]: AddressField,
        # Other
        Random: PRNGField,
    }
)
