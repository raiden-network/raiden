from dataclasses import dataclass

from marshmallow import EXCLUDE

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedRetrieableMessage
from raiden.messages.cmdid import CmdId
from raiden.transfer.events import (
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    ChainID,
    ChannelID,
    ClassVar,
    Nonce,
    TokenNetworkAddress,
    WithdrawAmount,
)
from raiden_contracts.constants import MessageTypeId


@dataclass(repr=False, eq=False)
class WithdrawRequest(SignedRetrieableMessage):
    """Requests a signed on-chain withdraw confirmation from partner."""

    cmdid: ClassVar[CmdId] = CmdId.WITHDRAW_REQUEST
    message_type: ClassVar[int] = MessageTypeId.WITHDRAW

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_withdraw: WithdrawAmount
    nonce: Nonce
    expiration: BlockExpiration
    coop_settle: bool = False

    class Meta:
        unknown = EXCLUDE
        serialize_missing = False

    @classmethod
    def from_event(cls, event: SendWithdrawRequest) -> "WithdrawRequest":
        return cls(
            message_identifier=event.message_identifier,
            chain_id=event.canonical_identifier.chain_identifier,
            token_network_address=event.canonical_identifier.token_network_address,
            channel_identifier=event.canonical_identifier.channel_identifier,
            total_withdraw=event.total_withdraw,
            participant=event.participant,
            nonce=event.nonce,
            expiration=event.expiration,
            coop_settle=event.coop_settle,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return (
            self.token_network_address
            + self.chain_id.to_bytes(32, byteorder="big")
            + self.message_type.to_bytes(32, byteorder="big")
            + self.channel_identifier.to_bytes(32, byteorder="big")
            + self.participant
            + self.total_withdraw.to_bytes(32, byteorder="big")
            + self.expiration.to_bytes(32, byteorder="big")
        )


@dataclass(repr=False, eq=False)
class WithdrawConfirmation(SignedRetrieableMessage):
    """Confirms withdraw to partner with a signature"""

    cmdid: ClassVar[CmdId] = CmdId.WITHDRAW_CONFIRMATION
    message_type: ClassVar[int] = MessageTypeId.WITHDRAW

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_withdraw: WithdrawAmount
    nonce: Nonce
    expiration: BlockExpiration

    @classmethod
    def from_event(cls, event: SendWithdrawConfirmation) -> "WithdrawConfirmation":
        return cls(
            message_identifier=event.message_identifier,
            chain_id=event.canonical_identifier.chain_identifier,
            token_network_address=event.canonical_identifier.token_network_address,
            channel_identifier=event.canonical_identifier.channel_identifier,
            total_withdraw=event.total_withdraw,
            participant=event.participant,
            nonce=event.nonce,
            expiration=event.expiration,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return (
            self.token_network_address
            + self.chain_id.to_bytes(32, byteorder="big")
            + self.message_type.to_bytes(32, byteorder="big")
            + self.channel_identifier.to_bytes(32, byteorder="big")
            + self.participant
            + self.total_withdraw.to_bytes(32, byteorder="big")
            + self.expiration.to_bytes(32, byteorder="big")
        )


@dataclass(eq=False)
class WithdrawExpired(SignedRetrieableMessage):
    """Notifies about withdraw expiration/cancellation from partner."""

    cmdid: ClassVar[CmdId] = CmdId.WITHDRAW_EXPIRED
    message_type: ClassVar[int] = MessageTypeId.WITHDRAW

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_withdraw: WithdrawAmount
    expiration: BlockExpiration
    nonce: Nonce

    @classmethod
    def from_event(cls, event: SendWithdrawExpired) -> "WithdrawExpired":
        return cls(
            message_identifier=event.message_identifier,
            chain_id=event.canonical_identifier.chain_identifier,
            token_network_address=event.canonical_identifier.token_network_address,
            channel_identifier=event.canonical_identifier.channel_identifier,
            total_withdraw=event.total_withdraw,
            participant=event.participant,
            nonce=event.nonce,
            expiration=event.expiration,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return (
            bytes([self.cmdid.value, 0, 0, 0])
            + self.nonce.to_bytes(32, byteorder="big")
            + self.message_identifier.to_bytes(8, byteorder="big")
            + self.token_network_address
            + self.chain_id.to_bytes(32, byteorder="big")
            + self.message_type.to_bytes(32, byteorder="big")
            + self.channel_identifier.to_bytes(32, byteorder="big")
            + self.participant
            + self.total_withdraw.to_bytes(32, byteorder="big")
            + self.expiration.to_bytes(32, byteorder="big")
        )
