from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import Dict, List, NewType, Optional, Tuple, Union

T_ABI = dict
ABI = NewType('ABI', T_ABI)

T_Address = bytes
Address = NewType('Address', T_Address)

T_AddressHex = str
AddressHex = NewType('AddressHex', T_AddressHex)

# An absolute number of blocks
T_BlockExpiration = int
BlockExpiration = NewType('BlockExpiration', T_BlockExpiration)

T_Balance = int
Balance = NewType('Balance', T_Balance)

T_BalanceHash = bytes
BalanceHash = NewType('BalanceHash', T_BalanceHash)

T_BlockGasLimit = int
BlockGasLimit = NewType('BlockGasLimit', T_BlockGasLimit)

T_BlockGasPrice = int
BlockGasPrice = NewType('BlockGasPrice', T_BlockGasPrice)

T_BlockHash = bytes
BlockHash = NewType('BlockHash', T_BlockHash)

T_BlockNumber = int
BlockNumber = NewType('BlockNumber', T_BlockNumber)

# A relative number of blocks
T_BlockTimeout = int
BlockTimeout = NewType('BlockTimeout', T_BlockTimeout)

T_ChannelID = int
ChannelID = NewType('ChannelID', T_ChannelID)

T_ChannelState = int
ChannelState = NewType('ChannelState', T_ChannelState)

T_InitiatorAddress = bytes
InitiatorAddress = NewType('InitiatorAddress', T_InitiatorAddress)

T_Locksroot = bytes
Locksroot = NewType('Locksroot', T_Locksroot)

T_LockHash = bytes
LockHash = NewType('LockHash', T_LockHash)

T_MerkleTreeLeaves = List['HashTimeLockState']
MerkleTreeLeaves = NewType('MerkleTreeLeaves', T_MerkleTreeLeaves)

T_MessageID = int
MessageID = NewType('MessageID', T_MessageID)

T_Nonce = int
Nonce = NewType('Nonce', T_Nonce)

T_AdditionalHash = bytes
AdditionalHash = NewType('AdditionalHash', T_AdditionalHash)

T_NetworkTimeout = float
NetworkTimeout = NewType('NetworkTimeout', T_NetworkTimeout)

T_PaymentID = int
PaymentID = NewType('PaymentID', T_PaymentID)

T_PaymentAmount = int
PaymentAmount = NewType('PaymentAmount', T_PaymentAmount)

T_PaymentNetworkID = bytes
PaymentNetworkID = NewType('PaymentNetworkID', T_PaymentNetworkID)

T_RaidenProtocolVersion = int
RaidenProtocolVersion = NewType('RaidenProtocolVersion', T_RaidenProtocolVersion)

T_ChainID = int
ChainID = NewType('ChainID', T_ChainID)

T_Keccak256 = bytes
Keccak256 = NewType('Keccak256', T_Keccak256)

T_TargetAddress = bytes
TargetAddress = NewType('TargetAddress', T_TargetAddress)

T_TokenAddress = bytes
TokenAddress = NewType('TokenAddress', T_TokenAddress)

T_TokenNetworkAddress = bytes
TokenNetworkAddress = NewType('TokenNetworkAddress', T_TokenNetworkAddress)

T_TokenNetworkID = bytes
TokenNetworkID = NewType('TokenNetworkID', T_TokenNetworkID)

T_TokenAmount = int
TokenAmount = NewType('TokenAmount', T_TokenAmount)

T_TransferID = bytes
TransferID = NewType('TransferID', T_TransferID)

T_Secret = bytes
Secret = NewType('Secret', T_Secret)

T_SecretHash = bytes
SecretHash = NewType('SecretHash', T_SecretHash)

T_SecretRegistryAddress = bytes
SecretRegistryAddress = NewType('SecretRegistryAddress', T_SecretRegistryAddress)

T_Signature = bytes
Signature = NewType('Signature', T_Signature)

T_TransactionHash = bytes
TransactionHash = NewType('TransactionHash', T_TransactionHash)

# This should be changed to `Optional[str]`
SuccessOrError = Tuple[bool, Optional[str]]

BlockSpecification = Union[str, T_BlockNumber]

ChannelMap = Dict[ChannelID, 'NettingChannelState']
