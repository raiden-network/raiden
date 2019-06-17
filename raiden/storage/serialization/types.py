from random import Random

import networkx
from marshmallow import Schema
from marshmallow_dataclass import _native_to_marshmallow

from raiden.storage.serialization.cache import SchemaCache
from raiden.storage.serialization.fields import (
    AddressField,
    BytesField,
    CallablePolyField,
    IntegerToStringField,
    NetworkXGraphField,
    OptionalIntegerToStringField,
    PRNGField,
    QueueIdentifierField,
)
from raiden.transfer.architecture import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    TransferTask,
)
from raiden.transfer.events import SendMessageEvent
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
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentNetworkAddress,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    Signature,
    TargetAddress,
    TokenAddress,
    TokenNetworkAddress,
    TransactionHash,
    TransferID,
    Union,
    WithdrawAmount,
)


def transfer_task_schema_serialization(task: TransferTask, parent: Any) -> Schema:
    # pylint: disable=unused-argument
    return SchemaCache.get_or_create_schema(task.__class__)


def transfer_task_schema_deserialization(
    task_dict: Dict[str, Any], parent: Dict[str, Any]
) -> Optional[Schema]:
    # pylint: disable=unused-argument
    # Avoid cyclic dependencies
    task_type = task_dict.get("_type")
    if task_type is None:
        return None

    if task_type.endswith("InitiatorTask"):
        from raiden.transfer.mediated_transfer.tasks import InitiatorTask

        return SchemaCache.get_or_create_schema(InitiatorTask)
    if task_type.endswith("MediatorTask"):
        from raiden.transfer.mediated_transfer.tasks import MediatorTask

        return SchemaCache.get_or_create_schema(MediatorTask)
    if task_type.endswith("TargetTask"):
        from raiden.transfer.mediated_transfer.tasks import TargetTask

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


def message_event_schema_serialization(message_event: SendMessageEvent, parent: Any) -> Schema:
    # pylint: disable=unused-argument
    return SchemaCache.get_or_create_schema(message_event.__class__)


def message_event_schema_deserialization(
    message_event_dict: Dict[str, Any], parent: Dict[str, Any]
) -> Optional[Schema]:
    # pylint: disable=unused-argument
    message_type = message_event_dict.get("_type")
    if message_type is None:
        return None

    if message_type.endswith("SendLockExpired"):
        from raiden.transfer.mediated_transfer.events import SendLockExpired

        return SchemaCache.get_or_create_schema(SendLockExpired)
    elif message_type.endswith("SendLockedTransfer"):
        from raiden.transfer.mediated_transfer.events import SendLockedTransfer

        return SchemaCache.get_or_create_schema(SendLockedTransfer)
    elif message_type.endswith("SendSecretReveal"):
        from raiden.transfer.mediated_transfer.events import SendSecretReveal

        return SchemaCache.get_or_create_schema(SendSecretReveal)
    elif message_type.endswith("SendBalanceProof"):
        from raiden.transfer.mediated_transfer.events import SendBalanceProof

        return SchemaCache.get_or_create_schema(SendBalanceProof)
    elif message_type.endswith("SendSecretRequest"):
        from raiden.transfer.mediated_transfer.events import SendSecretRequest

        return SchemaCache.get_or_create_schema(SendSecretRequest)
    elif message_type.endswith("SendRefundTransfer"):
        from raiden.transfer.mediated_transfer.events import SendRefundTransfer

        return SchemaCache.get_or_create_schema(SendRefundTransfer)

    elif message_type.endswith("SendProcessed"):
        from raiden.transfer.events import SendProcessed

        return SchemaCache.get_or_create_schema(SendProcessed)

    return None


_native_to_marshmallow.update(
    {
        # Addresses
        Address: AddressField,
        InitiatorAddress: AddressField,
        PaymentNetworkAddress: AddressField,
        SecretRegistryAddress: AddressField,
        TargetAddress: AddressField,
        TokenAddress: AddressField,
        TokenNetworkAddress: AddressField,
        # Bytes
        EncodedData: BytesField,
        AdditionalHash: BytesField,
        BalanceHash: BytesField,
        BlockHash: BytesField,
        Keccak256: BytesField,
        Locksroot: BytesField,
        Secret: BytesField,
        SecretHash: BytesField,
        Signature: BytesField,
        TransactionHash: BytesField,
        # Ints
        BlockExpiration: IntegerToStringField,
        BlockNumber: IntegerToStringField,
        FeeAmount: IntegerToStringField,
        LockedAmount: IntegerToStringField,
        BlockGasLimit: IntegerToStringField,
        MessageID: IntegerToStringField,
        Nonce: IntegerToStringField,
        PaymentAmount: IntegerToStringField,
        PaymentID: IntegerToStringField,
        PaymentWithFeeAmount: IntegerToStringField,
        TransferID: IntegerToStringField,
        WithdrawAmount: IntegerToStringField,
        Optional[BlockNumber]: OptionalIntegerToStringField,
        # Integers which should be converted to strings
        # This is done for querying purposes as sqlite
        # integer type is smaller than python's.
        ChainID: IntegerToStringField,
        ChannelID: IntegerToStringField,
        # Polymorphic fields
        TransferTask: CallablePolyField(
            serialization_schema_selector=transfer_task_schema_serialization,
            deserialization_schema_selector=transfer_task_schema_deserialization,
        ),
        Union[BalanceProofUnsignedState, BalanceProofSignedState]: CallablePolyField(
            serialization_schema_selector=balance_proof_schema_serialization,
            deserialization_schema_selector=balance_proof_schema_deserialization,
        ),
        Optional[Union[BalanceProofUnsignedState, BalanceProofSignedState]]: CallablePolyField(
            serialization_schema_selector=balance_proof_schema_serialization,
            deserialization_schema_selector=balance_proof_schema_deserialization,
            allow_none=True,
        ),
        SendMessageEvent: CallablePolyField(
            serialization_schema_selector=message_event_schema_serialization,
            deserialization_schema_selector=message_event_schema_deserialization,
            allow_none=True,
        ),
        # QueueIdentifier (Special case)
        QueueIdentifier: QueueIdentifierField,
        # Other
        networkx.Graph: NetworkXGraphField,
        Random: PRNGField,
    }
)
