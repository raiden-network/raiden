from eth_utils import to_bytes, to_canonical_address, to_checksum_address, to_hex

from raiden.utils import pex
from raiden.utils.typing import (
    Address,
    Any,
    ChainID,
    ChannelID,
    Dict,
    TokenNetworkAddress,
    TokenNetworkID,
    Union,
)

# Placeholder chain ID for refactoring in scope of #3493
CHAIN_ID_UNSPECIFIED = ChainID(-1)
# Placeholder channel ID for refactoring in scope of #3493
CHANNEL_ID_UNSPECIFIED = ChannelID(-2)


class QueueIdentifier:
    def __init__(
            self,
            recipient: Address,
            channel_identifier: ChannelID,
    ) -> None:
        self.recipient = recipient
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<QueueIdentifier recipient:{} channel_identifier:{}>'.format(
            pex(self.recipient),
            self.channel_identifier,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, QueueIdentifier) and
            self.recipient == other.recipient and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.recipient, self.channel_identifier))

    def to_dict(self) -> Dict[str, Any]:
        return {
            'recipient': to_checksum_address(self.recipient),
            'channel_identifier': self.channel_identifier,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueueIdentifier':
        restored = cls(
            recipient=to_canonical_address(data['recipient']),
            channel_identifier=data['channel_identifier'],
        )

        return restored


class CanonicalIdentifier:
    def __init__(
            self,
            chain_identifier: ChainID,
            # introducing the type as Union, to avoid casting for now.
            # Should be only `..Address` later
            token_network_address: Union[TokenNetworkAddress, TokenNetworkID],
            channel_identifier: ChannelID,
    ):
        self.chain_identifier = chain_identifier
        self.token_network_address = token_network_address
        self.channel_identifier = channel_identifier

    def __str__(self):
        return (
            f'<CanonicalIdentifier '
            f'chain_id:{self.chain_identifier} '
            f'token_network_address:{pex(self.token_network_address)} '
            f'channel_id:{self.channel_identifier}>'
        )

    def to_dict(self) -> Dict[str, Any]:
        return dict(
            chain_identifier=str(self.chain_identifier),
            token_network_address=to_hex(self.token_network_address),
            channel_identifier=str(self.channel_identifier),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CanonicalIdentifier':
        return cls(
            chain_identifier=ChainID(int(data['chain_identifier'])),
            token_network_address=TokenNetworkAddress(
                to_bytes(hexstr=data['token_network_address']),
            ),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
        )
