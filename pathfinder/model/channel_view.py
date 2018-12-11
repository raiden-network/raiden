from enum import Enum

from eth_utils import is_checksum_address

from pathfinder.config import DEFAULT_PERCENTAGE_FEE
from raiden_libs.types import Address, ChannelIdentifier


class ChannelView:
    """
    Unidirectional view of a bidirectional channel.
    """
    class State(Enum):
        OPEN = 1
        SETTLING = 2
        SETTLED = 3

    def __init__(
        self,
        channel_id: ChannelIdentifier,
        participant1: Address,
        participant2: Address,
        deposit: int = 0,
    ) -> None:
        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.self = participant1
        self.partner = participant2

        self._deposit = deposit
        self._transferred_amount = 0
        self._received_amount = 0
        self._locked_amount = 0
        self._capacity = deposit
        self.state = ChannelView.State.OPEN
        self.channel_id = channel_id

    def update_capacity(
        self,
        nonce: int = None,
        deposit: int = None,
        transferred_amount: int = None,
        received_amount: int = None,
        locked_amount: int = None,
    ):
        if deposit is not None:
            self._deposit = deposit

        self._capacity = self.deposit - (
            self.transferred_amount + self.locked_amount
        ) + self.received_amount

    @property
    def deposit(self) -> int:
        return self._deposit

    @property
    def transferred_amount(self) -> int:
        return self._transferred_amount

    @property
    def received_amount(self) -> int:
        return self._received_amount

    @property
    def locked_amount(self) -> int:
        return self._locked_amount

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def relative_fee(self) -> int:
        return DEFAULT_PERCENTAGE_FEE

    def __repr__(self):
        return '<ChannelView from={} to={} capacity={}>'.format(
            self.self,
            self.partner,
            self.capacity,
        )
