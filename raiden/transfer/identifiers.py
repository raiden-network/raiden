from dataclasses import dataclass

from eth_utils import to_checksum_address

from raiden.constants import EMPTY_ADDRESS, UINT256_MAX
from raiden.utils.typing import (
    Address,
    ChainID,
    ChannelID,
    T_Address,
    T_ChainID,
    T_ChannelID,
    TokenNetworkAddress,
    typecheck,
)


@dataclass(frozen=True, order=True)
class CanonicalIdentifier:
    chain_identifier: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID

    def validate(self) -> None:
        typecheck(self.chain_identifier, T_ChainID)
        typecheck(self.token_network_address, T_Address)
        typecheck(self.channel_identifier, T_ChannelID)

        if self.channel_identifier < 0 or self.channel_identifier > UINT256_MAX:
            raise ValueError("channel id is invalid")

    def __str__(self) -> str:
        return (
            "CanonicalIdentifier("
            f"chain_identifier={self.chain_identifier}, "
            f"token_network_address={to_checksum_address(self.token_network_address)}, "
            f"channel_identifier={self.channel_identifier}"
            ")"
        )


@dataclass(frozen=True)
class QueueIdentifier:
    recipient: Address
    canonical_identifier: CanonicalIdentifier

    def __str__(self) -> str:
        return (
            "QueueIdentifier("
            f"recipient={to_checksum_address(self.recipient)}, "
            f"canonical_identifier={self.canonical_identifier}"
            ")"
        )


CANONICAL_IDENTIFIER_GLOBAL_QUEUE = CanonicalIdentifier(
    ChainID(0), TokenNetworkAddress(EMPTY_ADDRESS), ChannelID(0)
)
