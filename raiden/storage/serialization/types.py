from random import Random

from marshmallow import Schema, fields
from marshmallow_dataclass import _native_to_marshmallow

from raiden.storage.serialization.cache import SchemaCache
from raiden.storage.serialization.fields import (
    AddressField,
    BytesField,
    CallablePolyField,
    IntegerToStringField,
    PRNGField,
    QueueIdentifierField,
)
from raiden.transfer.architecture import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    TransferTask,
)
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    Any,
    BalanceHash,
    BlockExpiration,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    EncodedData,
    FeeAmount,
    InitiatorAddress,
    Keccak256,
    LockedAmount,
    LockHash,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
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


def transfer_task_schema_serialization(task: TransferTask, parent: Any) -> Schema:
    # pylint: disable=unused-argument
    return SchemaCache.get_or_create_schema(task.__class__)


def transfer_task_schema_deserialization(
    task_dict: Dict[str, Any], parent: Dict[str, Any]
) -> Optional[Schema]:
    # pylint: disable=unused-argument
    # Avoid cyclic dependencies
    from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask

    task_type = task_dict.get("_type")
    if task_type is None:
        return None

    if task_type.endswith("InitiatorTask"):
        return SchemaCache.get_or_create_schema(InitiatorTask)
    if task_type.endswith("MediatorTask"):
        return SchemaCache.get_or_create_schema(MediatorTask)
    if task_type.endswith("TargetTask"):
        return SchemaCache.get_or_create_schema(TargetTask)

    return None


def balance_proof_schema_serialization(
    balance_proof: Union[BalanceProofSignedState, BalanceProofUnsignedState], parent: Any
) -> Schema:
    # pylint: disable=unused-argument
    return SchemaCache.get_or_create_schema(balance_proof.__class__)


def balance_proof_schema_deserialization(
    balance_proof_dict: Dict[str, Any], parent: Dict[str, Any]
) -> Optional[Schema]:
    # pylint: disable=unused-argument
    bp_type = balance_proof_dict.get("_type")
    if bp_type is None:
        return None

    if bp_type.endswith("UnsignedState"):
        return SchemaCache.get_or_create_schema(BalanceProofUnsignedState)
    elif bp_type.endswith("SignedState"):
        return SchemaCache.get_or_create_schema(BalanceProofSignedState)

    return None


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
        Union[BalanceProofUnsignedState, BalanceProofSignedState]: CallablePolyField(
            serialization_schema_selector=balance_proof_schema_serialization,
            deserialization_schema_selector=balance_proof_schema_deserialization,
        ),
        Optional[Union[BalanceProofUnsignedState, BalanceProofSignedState]]: CallablePolyField(
            serialization_schema_selector=balance_proof_schema_serialization,
            deserialization_schema_selector=balance_proof_schema_deserialization,
            allow_none=True,
        ),
        # Polymorphic fields
        TransferTask: CallablePolyField(
            serialization_schema_selector=transfer_task_schema_serialization,
            deserialization_schema_selector=transfer_task_schema_deserialization,
        ),
        QueueIdentifier: QueueIdentifierField,
        # Other
        Random: PRNGField,
    }
)
