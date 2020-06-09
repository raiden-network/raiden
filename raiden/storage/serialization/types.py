from random import Random

import networkx
from marshmallow_dataclass import _native_to_marshmallow

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
    ContractSendEvent,
    TransferTask,
)
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelWithdraw,
    ContractSendSecretReveal,
    SendMessageEvent,
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.mediated_transfer.events import (
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretRequest,
    SendSecretReveal,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    EncodedData,
    FeeAmount,
    InitiatorAddress,
    LockedAmount,
    Locksroot,
    MessageID,
    MonitoringServiceAddress,
    Nonce,
    OneToNAddress,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    ProportionalFeeAmount,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    Signature,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
    TransferID,
    Union,
    UserDepositAddress,
    WithdrawAmount,
)

MESSAGE_NAME_TO_QUALIFIED_NAME = {
    "AuthenticatedMessage": "raiden.messages.abstract.AuthenticatedMessage",
    "Delivered": "raiden.messages.synchronization.Delivered",
    "EnvelopeMessage": "raiden.messages.transfers.EnvelopeMessage",
    "LockedTransferBase": "raiden.messages.transfers.LockedTransferBase",
    "LockedTransfer": "raiden.messages.transfers.LockedTransfer",
    "LockExpired": "raiden.messages.transfers.LockExpired",
    "PFSCapacityUpdate": "raiden.messages.path_finding_service.PFSCapacityUpdate",
    "PFSFeeUpdate": "raiden.messages.path_finding_service.PFSFeeUpdate",
    "Ping": "raiden.messages.healthcheck.Ping",
    "Pong": "raiden.messages.healthcheck.Pong",
    "Processed": "raiden.messages.synchronization.Processed",
    "RefundTransfer": "raiden.messages.transfers.RefundTransfer",
    "RequestMonitoring": "raiden.messages.monitoring_service.RequestMonitoring",
    "RevealSecret": "raiden.messages.transfers.RevealSecret",
    "SecretRequest": "raiden.messages.transfers.SecretRequest",
    "SignedMessage": "raiden.messages.abstract.SignedMessage",
    "SignedRetrieableMessage": "raiden.messages.abstract.SignedRetrieableMessage",
    "Unlock": "raiden.messages.transfers.Unlock",
    "WithdrawConfirmation": "raiden.messages.withdraw.WithdrawConfirmation",
    "WithdrawExpired": "raiden.messages.withdraw.WithdrawExpired",
    "WithdrawRequest": "raiden.messages.withdraw.WithdrawRequest",
}


_native_to_marshmallow.update(
    {
        # Addresses
        Address: AddressField,
        InitiatorAddress: AddressField,
        MonitoringServiceAddress: AddressField,
        OneToNAddress: AddressField,
        TokenNetworkRegistryAddress: AddressField,
        SecretRegistryAddress: AddressField,
        TargetAddress: AddressField,
        TokenAddress: AddressField,
        TokenNetworkAddress: AddressField,
        UserDepositAddress: AddressField,
        # Bytes
        EncodedData: BytesField,
        AdditionalHash: BytesField,
        BalanceHash: BytesField,
        BlockHash: BytesField,
        Locksroot: BytesField,
        Secret: BytesField,
        SecretHash: BytesField,
        Signature: BytesField,
        TransactionHash: BytesField,
        # Ints
        BlockExpiration: IntegerToStringField,
        BlockNumber: IntegerToStringField,
        BlockTimeout: IntegerToStringField,
        TokenAmount: IntegerToStringField,
        FeeAmount: IntegerToStringField,
        ProportionalFeeAmount: IntegerToStringField,
        LockedAmount: IntegerToStringField,
        BlockGasLimit: IntegerToStringField,
        MessageID: IntegerToStringField,
        Nonce: IntegerToStringField,
        PaymentAmount: IntegerToStringField,
        PaymentID: IntegerToStringField,
        PaymentWithFeeAmount: IntegerToStringField,
        TransferID: IntegerToStringField,
        WithdrawAmount: IntegerToStringField,
        Optional[BlockNumber]: OptionalIntegerToStringField,  # type: ignore
        # Integers which should be converted to strings
        # This is done for querying purposes as sqlite
        # integer type is smaller than python's.
        ChainID: IntegerToStringField,
        ChannelID: IntegerToStringField,
        # Polymorphic fields
        TransferTask: CallablePolyField(allowed_classes=[InitiatorTask, MediatorTask, TargetTask]),
        Union[  # type: ignore
            BalanceProofUnsignedState, BalanceProofSignedState
        ]: CallablePolyField(allowed_classes=[BalanceProofUnsignedState, BalanceProofSignedState]),
        Optional[  # type: ignore
            Union[BalanceProofUnsignedState, BalanceProofSignedState]
        ]: CallablePolyField(
            allowed_classes=[BalanceProofUnsignedState, BalanceProofSignedState], allow_none=True
        ),
        SendMessageEvent: CallablePolyField(
            allowed_classes=[
                SendLockExpired,
                SendLockedTransfer,
                SendSecretReveal,
                SendUnlock,
                SendSecretRequest,
                SendRefundTransfer,
                SendWithdrawRequest,
                SendWithdrawConfirmation,
                SendWithdrawExpired,
                SendProcessed,
            ],
            allow_none=True,
        ),
        ContractSendEvent: CallablePolyField(
            allowed_classes=[
                ContractSendChannelWithdraw,
                ContractSendChannelClose,
                ContractSendChannelSettle,
                ContractSendChannelUpdateTransfer,
                ContractSendSecretReveal,
            ],
            allow_none=False,
        ),
        # QueueIdentifier (Special case)
        QueueIdentifier: QueueIdentifierField,
        # Other
        networkx.Graph: NetworkXGraphField,
        Random: PRNGField,
    }
)
