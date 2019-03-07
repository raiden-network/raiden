from eth_utils import to_canonical_address, to_checksum_address

from raiden.utils import pex
from raiden.utils.typing import Address, Any, ChannelID, Dict


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
