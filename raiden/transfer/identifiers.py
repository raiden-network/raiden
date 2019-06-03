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
)


@dataclass(frozen=True, order=True)
class CanonicalIdentifier:
    chain_identifier: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID

    def validate(self) -> None:
        if not isinstance(self.token_network_address, T_Address):
            raise ValueError("token_network_address must be an address instance")

        if not isinstance(self.channel_identifier, T_ChannelID):
            raise ValueError("channel_identifier must be an ChannelID instance")

        if not isinstance(self.chain_identifier, T_ChainID):
            raise ValueError("chain_id must be a ChainID instance")

        if self.channel_identifier < 0 or self.channel_identifier > constants.UINT256_MAX:
            raise ValueError("channel id is invalid")


@dataclass(frozen=True)
class QueueIdentifier:
    recipient: Address
    canonical_identifier: CanonicalIdentifier
