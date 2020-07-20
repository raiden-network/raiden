from dataclasses import dataclass

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedRetrieableMessage
from raiden.messages.cmdid import CmdId
from raiden.transfer.events import SendBurnConfirmation, SendBurnRequest
from raiden.utils.typing import (
    Address,
    BurnAmount,
    ChainID,
    ChannelID,
    ClassVar,
    Nonce,
    TokenNetworkAddress,
)
from raiden_contracts.constants import MessageTypeId


@dataclass(repr=False, eq=False)
class BurnRequest(SignedRetrieableMessage):
    """ Requests a signed on-chain withdraw confirmation from partner. """

    cmdid: ClassVar[CmdId] = CmdId.BURN_REQUEST

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_burn: BurnAmount
    nonce: Nonce

    @classmethod
    def from_event(cls, event: SendBurnRequest) -> "BurnRequest":
        return cls(
            message_identifier=event.message_identifier,
            chain_id=event.canonical_identifier.chain_identifier,
            token_network_address=event.canonical_identifier.token_network_address,
            channel_identifier=event.canonical_identifier.channel_identifier,
            total_burn=event.total_burn,
            participant=event.participant,
            nonce=event.nonce,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return (
            self.token_network_address
            + self.chain_id.to_bytes(32, byteorder="big")
            + self.channel_identifier.to_bytes(32, byteorder="big")
            + self.participant
            + self.total_burn.to_bytes(32, byteorder="big")
        )


@dataclass(repr=False, eq=False)
class BurnConfirmation(SignedRetrieableMessage):
    """ Confirms withdraw to partner with a signature """

    cmdid: ClassVar[CmdId] = CmdId.BURN_CONFIRMATION
    message_type: ClassVar[int] = MessageTypeId.BURN

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_burn: BurnAmount
    nonce: Nonce

    @classmethod
    def from_event(cls, event: SendBurnConfirmation) -> "BurnConfirmation":
        return cls(
            message_identifier=event.message_identifier,
            chain_id=event.canonical_identifier.chain_identifier,
            token_network_address=event.canonical_identifier.token_network_address,
            channel_identifier=event.canonical_identifier.channel_identifier,
            total_burn=event.total_burn,
            participant=event.participant,
            nonce=event.nonce,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return (
            self.token_network_address
            + self.chain_id.to_bytes(32, byteorder="big")
            + self.message_type.to_bytes(32, byteorder="big")
            + self.channel_identifier.to_bytes(32, byteorder="big")
            + self.participant
            + self.total_burn.to_bytes(32, byteorder="big")
        )
