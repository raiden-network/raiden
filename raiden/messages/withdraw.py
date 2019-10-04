from dataclasses import dataclass

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedRetrieableMessage
from raiden.messages.cmdid import CmdId
from raiden.utils.signing import pack_data
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
    """ Requests a signed on-chain withdraw confirmation from partner. """

    cmdid: ClassVar[CmdId] = CmdId.WITHDRAW_REQUEST
    message_type: ClassVar[int] = MessageTypeId.WITHDRAW

    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID
    participant: Address
    total_withdraw: WithdrawAmount
    nonce: Nonce
    expiration: BlockExpiration

    @classmethod
    def from_event(cls, event):
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
        return pack_data(
            (self.token_network_address, "address"),
            (self.chain_id, "uint256"),
            (self.message_type, "uint256"),
            (self.channel_identifier, "uint256"),
            (self.participant, "address"),
            (self.total_withdraw, "uint256"),
            (self.expiration, "uint256"),
        )


@dataclass(repr=False, eq=False)
class WithdrawConfirmation(SignedRetrieableMessage):
    """ Confirms withdraw to partner with a signature """

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
    def from_event(cls, event):
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
        return pack_data(
            (self.token_network_address, "address"),
            (self.chain_id, "uint256"),
            (self.message_type, "uint256"),
            (self.channel_identifier, "uint256"),
            (self.participant, "address"),
            (self.total_withdraw, "uint256"),
            (self.expiration, "uint256"),
        )


@dataclass
class WithdrawExpired(SignedRetrieableMessage):
    """ Notifies about withdraw expiration/cancellation from partner. """

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
    def from_event(cls, event):
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
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.nonce, "uint256"),
            (self.message_identifier, "uint64"),
            (self.token_network_address, "address"),
            (self.chain_id, "uint256"),
            (self.message_type, "uint256"),
            (self.channel_identifier, "uint256"),
            (self.participant, "address"),
            (self.total_withdraw, "uint256"),
            (self.expiration, "uint256"),
        )
