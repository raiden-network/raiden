from raiden import constants
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    ChainID,
    ChannelID,
    T_Address,
    T_ChainID,
    T_ChannelID,
    TokenNetworkAddress,
    TokenNetworkID,
    Union,
)

if TYPE_CHECKING:
    from dataclasses import dataclass
else:
    from raiden.storage.serialization import dataclass


@dataclass
class QueueIdentifier:
    recipient: Address
    channel_identifier: ChannelID


@dataclass
class CanonicalIdentifier:
    chain_identifier: ChainID
    # introducing the type as Union, to avoid casting for now.
    # Should be only `..Address` later
    token_network_address: Union[TokenNetworkAddress, TokenNetworkID]
    channel_identifier: ChannelID

    def validate(self) -> None:
        if not isinstance(self.token_network_address, T_Address):
            raise ValueError("token_network_identifier must be an address instance")

        if not isinstance(self.channel_identifier, T_ChannelID):
            raise ValueError("channel_identifier must be an ChannelID instance")

        if not isinstance(self.chain_identifier, T_ChainID):
            raise ValueError("chain_id must be a ChainID instance")

        if self.channel_identifier < 0 or self.channel_identifier > constants.UINT256_MAX:
            raise ValueError("channel id is invalid")
