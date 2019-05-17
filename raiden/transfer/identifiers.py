from dataclasses import dataclass

from raiden import constants
from raiden.utils.typing import (
    Address,
    Any,
    ChainID,
    ChannelID,
    T_Address,
    T_ChainID,
    T_ChannelID,
    TokenNetworkAddress,
)


@dataclass
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


@dataclass
class QueueIdentifier:
    recipient: Address
    canonical_identifier: CanonicalIdentifier

    @property
    def channel_identifier(self):
        return self.canonical_identifier.channel_identifier

    def __hash__(self) -> int:  # TODO
        return hash((self.recipient, self.channel_identifier))

    def __eq__(self, other: Any) -> bool:  # TODO
        return (
            isinstance(other, QueueIdentifier) and
            self.recipient == other.recipient and
            self.channel_identifier == other.channel_identifier
        )


# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
CANONICAL_IDENTIFIER_GLOBAL_QUEUE = CanonicalIdentifier(
    ChainID(0),
    TokenNetworkAddress(b''),
    ChannelID(0),
)


def wrap_id(channel_identifier: ChannelID) -> CanonicalIdentifier:
    # temporarily needed function while we reorganize queue identifiers
    if channel_identifier == 0:
        return CANONICAL_IDENTIFIER_GLOBAL_QUEUE
    return CanonicalIdentifier(
        chain_identifier=ChainID(0),
        token_network_address=TokenNetworkAddress(b''),
        channel_identifier=channel_identifier,
    )
