from eth_utils import to_canonical_address, to_checksum_address

from raiden.utils import pex, typing


class QueueIdentifier:
    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
    ):
        self.recipient = recipient
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<QueueIdentifier recipient:{} channel_identifier:{}>'.format(
            pex(self.recipient),
            self.channel_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, QueueIdentifier) and
            self.recipient == other.recipient and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.recipient, self.channel_identifier))

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'recipient': to_checksum_address(self.recipient),
            'channel_identifier': self.channel_identifier,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'QueueIdentifier':
        restored = cls(
            recipient=to_canonical_address(data['recipient']),
            channel_identifier=data['channel_identifier'],
        )

        return restored
