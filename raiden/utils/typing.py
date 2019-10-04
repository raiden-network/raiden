from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import TYPE_CHECKING, Any, Dict, List, NewType, Tuple, Type, Union

from eth_typing import Address, ChecksumAddress

from raiden_contracts.contract_manager import CompiledContract  # NOQA pylint:disable=unused-import
from raiden_contracts.utils.type_aliases import (  # NOQA pylint:disable=unused-import
    ChainID,
    T_ChainID,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.state import (  # noqa: F401
        HashTimeLockState,
        NettingChannelState,
        UnlockPartialProofState,
        NetworkState,
    )
    from raiden.transfer.mediated_transfer.state import (  # noqa: F401
        InitiatorTransferState,
        LockedTransferSignedState,
        LockedTransferUnsignedState,
    )
    from raiden.messages.monitoring_service import SignedBlindedBalanceProof  # noqa: F401
    from raiden.exceptions import RaidenUnrecoverableError, RaidenRecoverableError  # noqa: F401


MYPY_ANNOTATION = "This assert is used to tell mypy what is the type of the variable"


def typecheck(value: Any, expected: Type):
    if not isinstance(value, expected):
        raise ValueError(f"Expected a value of type {expected}, got value of type {type(value)}")


ABI = List[Dict[str, Any]]
BlockchainEvent = Dict[str, Any]

T_EVMBytecode = bytes
EVMBytecode = NewType("EVMBytecode", T_EVMBytecode)

GasMeasurements = Dict[str, int]

T_Address = bytes

AddressHex = ChecksumAddress

# An absolute number of blocks
T_BlockExpiration = int
BlockExpiration = NewType("BlockExpiration", T_BlockExpiration)

T_Balance = int
Balance = NewType("Balance", T_Balance)

T_GasPrice = int
GasPrice = NewType("GasPrice", T_GasPrice)

T_BalanceHash = bytes
BalanceHash = NewType("BalanceHash", T_BalanceHash)

T_BlockGasLimit = int
BlockGasLimit = NewType("BlockGasLimit", T_BlockGasLimit)

T_BlockHash = bytes
BlockHash = NewType("BlockHash", T_BlockHash)

T_BlockNumber = int
BlockNumber = NewType("BlockNumber", T_BlockNumber)

# A relative number of blocks
T_BlockTimeout = int
BlockTimeout = NewType("BlockTimeout", T_BlockTimeout)

T_ChannelID = int
ChannelID = NewType("ChannelID", T_ChannelID)

T_ChannelState = int
ChannelState = NewType("ChannelState", T_ChannelState)

T_InitiatorAddress = bytes
InitiatorAddress = NewType("InitiatorAddress", T_InitiatorAddress)

T_Locksroot = bytes
Locksroot = NewType("Locksroot", T_Locksroot)

T_MessageID = int
MessageID = NewType("MessageID", T_MessageID)

T_Nonce = int
Nonce = NewType("Nonce", T_Nonce)

T_AdditionalHash = bytes
AdditionalHash = NewType("AdditionalHash", T_AdditionalHash)

T_NetworkTimeout = float
NetworkTimeout = NewType("NetworkTimeout", T_NetworkTimeout)

T_PaymentID = int
PaymentID = NewType("PaymentID", T_PaymentID)

# PaymentAmount is for amounts of tokens paid end-to-end
T_PaymentAmount = int
PaymentAmount = NewType("PaymentAmount", T_PaymentAmount)

T_PrivateKey = bytes
PrivateKey = NewType("PrivateKey", T_PrivateKey)

T_PublicKey = bytes
PublicKey = NewType("PublicKey", T_PublicKey)

T_FeeAmount = int
FeeAmount = NewType("FeeAmount", T_FeeAmount)

# A proportional fee, unit is parts-per-million
# 1_000_000 means 100%, 25_000 is 2.5%
T_ProportionalFeeAmount = int
ProportionalFeeAmount = NewType("ProportionalFeeAmount", T_ProportionalFeeAmount)

T_LockedAmount = int
LockedAmount = NewType("LockedAmount", T_LockedAmount)

T_PaymentWithFeeAmount = int
PaymentWithFeeAmount = NewType("PaymentWithFeeAmount", T_FeeAmount)

T_TokenNetworkRegistryAddress = bytes
TokenNetworkRegistryAddress = NewType("TokenNetworkRegistryAddress", T_TokenNetworkRegistryAddress)

T_RaidenProtocolVersion = int
RaidenProtocolVersion = NewType("RaidenProtocolVersion", T_RaidenProtocolVersion)

T_RaidenDBVersion = int
RaidenDBVersion = NewType("RaidenDBVersion", T_RaidenDBVersion)

T_Keccak256 = bytes
Keccak256 = NewType("Keccak256", T_Keccak256)

T_TargetAddress = bytes
TargetAddress = NewType("TargetAddress", T_TargetAddress)

T_TokenAddress = bytes
TokenAddress = NewType("TokenAddress", T_TokenAddress)

T_TokenNetworkAddress = bytes
TokenNetworkAddress = NewType("TokenNetworkAddress", T_TokenNetworkAddress)

T_TokenAmount = int
TokenAmount = NewType("TokenAmount", T_TokenAmount)

T_TransferID = bytes
TransferID = NewType("TransferID", T_TransferID)

T_Secret = bytes
Secret = NewType("Secret", T_Secret)

T_SecretHash = bytes
SecretHash = NewType("SecretHash", T_SecretHash)

T_SecretRegistryAddress = bytes
SecretRegistryAddress = NewType("SecretRegistryAddress", T_SecretRegistryAddress)

T_Signature = bytes
Signature = NewType("Signature", T_Signature)

T_TransactionHash = bytes
TransactionHash = NewType("TransactionHash", T_TransactionHash)

T_EncodedData = bytes
EncodedData = NewType("EncodedData", T_EncodedData)

T_WithdrawAmount = int
WithdrawAmount = NewType("WithdrawAmount", T_WithdrawAmount)

BlockSpecification = Union[str, T_BlockNumber, T_BlockHash]

NodeNetworkStateMap = Dict[Address, "NetworkState"]

Host = NewType("Host", str)
Port = NewType("Port", int)
HostPort = Tuple[Host, Port]
Endpoint = NewType("Endpoint", str)

LockType = Union["HashTimeLockState", "UnlockPartialProofState"]
ErrorType = Union[Type["RaidenRecoverableError"], Type["RaidenUnrecoverableError"]]
LockedTransferType = Union["LockedTransferUnsignedState", "LockedTransferSignedState"]
