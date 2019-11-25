from dataclasses import dataclass, field
from datetime import datetime

import marshmallow.fields
import rlp

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedMessage
from raiden.transfer import channel
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import NettingChannelState
from raiden.utils.signing import pack_data
from raiden.utils.typing import Address, Nonce, TokenAmount


@dataclass(repr=False, eq=False)
class PFSCapacityUpdate(SignedMessage):
    """ Message to inform a pathfinding service about a capacity change. """

    canonical_identifier: CanonicalIdentifier
    updating_participant: Address
    other_participant: Address
    updating_nonce: Nonce
    other_nonce: Nonce
    updating_capacity: TokenAmount
    other_capacity: TokenAmount
    reveal_timeout: int

    def __post_init__(self) -> None:
        if self.signature is None:
            self.signature = EMPTY_SIGNATURE

    @classmethod
    def from_channel_state(cls, channel_state: NettingChannelState) -> "PFSCapacityUpdate":
        # pylint: disable=unexpected-keyword-arg
        return cls(
            canonical_identifier=channel_state.canonical_identifier,
            updating_participant=channel_state.our_state.address,
            other_participant=channel_state.partner_state.address,
            updating_nonce=channel.get_current_nonce(channel_state.our_state),
            other_nonce=channel.get_current_nonce(channel_state.partner_state),
            updating_capacity=channel.get_distributable(
                sender=channel_state.our_state, receiver=channel_state.partner_state
            ),
            other_capacity=channel.get_distributable(
                sender=channel_state.partner_state, receiver=channel_state.our_state
            ),
            reveal_timeout=channel_state.reveal_timeout,
            signature=EMPTY_SIGNATURE,
        )

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.canonical_identifier.chain_identifier, "uint256"),
            (self.canonical_identifier.token_network_address, "address"),
            (self.canonical_identifier.channel_identifier, "uint256"),
            (self.updating_participant, "address"),
            (self.other_participant, "address"),
            (self.updating_nonce, "uint64"),
            (self.other_nonce, "uint64"),
            (self.updating_capacity, "uint256"),
            (self.other_capacity, "uint256"),
            (self.reveal_timeout, "uint256"),
        )


@dataclass
class PFSFeeUpdate(SignedMessage):
    """Informs the PFS of mediation fees demanded by the client"""

    canonical_identifier: CanonicalIdentifier
    updating_participant: Address
    fee_schedule: FeeScheduleState
    timestamp: datetime = field(metadata={"marshmallow_field": marshmallow.fields.NaiveDateTime()})

    def __post_init__(self) -> None:
        if self.signature is None:
            self.signature = EMPTY_SIGNATURE

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.canonical_identifier.chain_identifier, "uint256"),
            (self.canonical_identifier.token_network_address, "address"),
            (self.canonical_identifier.channel_identifier, "uint256"),
            (self.updating_participant, "address"),
            (self.fee_schedule.cap_fees, "bool"),
            (self.fee_schedule.flat, "uint256"),
            (self.fee_schedule.proportional, "uint256"),
            (rlp.encode(self.fee_schedule.imbalance_penalty or 0), "bytes"),
            (
                marshmallow.fields.NaiveDateTime()._serialize(self.timestamp, "timestamp", self),
                "string",
            ),
        )

    @classmethod
    def from_channel_state(cls, channel_state: NettingChannelState) -> "PFSFeeUpdate":
        return cls(
            canonical_identifier=channel_state.canonical_identifier,
            updating_participant=channel_state.our_state.address,
            fee_schedule=channel_state.fee_schedule,
            timestamp=datetime.utcnow(),
            signature=EMPTY_SIGNATURE,
        )
