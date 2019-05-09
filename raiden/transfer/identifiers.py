from eth_utils import to_bytes, to_canonical_address, to_checksum_address

from raiden import constants
from raiden.utils import pex
from raiden.utils.typing import (
    Address,
    Any,
    ChainID,
    ChannelID,
    Dict,
    T_Address,
    T_ChainID,
    T_ChannelID,
    TokenNetworkAddress,
    TokenNetworkID,
    Union,
)


class QueueIdentifier:
    def __init__(self, recipient: Address, channel_identifier: ChannelID) -> None:
        self.recipient = recipient
        self.channel_identifier = channel_identifier

    def __repr__(self) -> str:
        return "<QueueIdentifier recipient:{} channel_identifier:{}>".format(
            pex(self.recipient), self.channel_identifier
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, QueueIdentifier)
            and self.recipient == other.recipient
            and self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.recipient, self.channel_identifier))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipient": to_checksum_address(self.recipient),
            "channel_identifier": self.channel_identifier,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueueIdentifier":
        restored = cls(
            recipient=to_canonical_address(data["recipient"]),
            channel_identifier=data["channel_identifier"],
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

    def __repr__(self) -> str:
        return (
            f"<CanonicalIdentifier "
            f"chain_id:{self.chain_identifier} "
            f"token_network_address:{pex(self.token_network_address)} "
            f"channel_id:{self.channel_identifier}>"
        )

    def validate(self) -> None:
        if not isinstance(self.token_network_address, T_Address):
            raise ValueError("token_network_identifier must be an address instance")

        if not isinstance(self.channel_identifier, T_ChannelID):
            raise ValueError("channel_identifier must be an ChannelID instance")

        if not isinstance(self.chain_identifier, T_ChainID):
            raise ValueError("chain_id must be a ChainID instance")

        if self.channel_identifier < 0 or self.channel_identifier > constants.UINT256_MAX:
            raise ValueError("channel id is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return dict(
            chain_identifier=str(self.chain_identifier),
            token_network_address=to_checksum_address(self.token_network_address),
            channel_identifier=str(self.channel_identifier),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalIdentifier":
        return cls(
            chain_identifier=ChainID(int(data["chain_identifier"])),
            token_network_address=TokenNetworkAddress(
                to_bytes(hexstr=data["token_network_address"])
            ),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CanonicalIdentifier):
            return NotImplemented
        return (
            self.chain_identifier == other.chain_identifier
            and self.token_network_address == other.token_network_address
            and self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, CanonicalIdentifier):
            return True
        return not self.__eq__(other)
