from dataclasses import dataclass

from raiden import constants
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

        if self.channel_identifier < 0 or self.channel_identifier > constants.UINT256_MAX:
            raise ValueError("channel id is invalid")


@dataclass(frozen=True)
class QueueIdentifier:
    recipient: Address
    canonical_identifier: CanonicalIdentifier
