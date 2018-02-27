from enum import Enum
from typing import Tuple

from eth_utils import is_checksum_address

from pathfinder.utils.types import ChannelId, Address


class ChannelView:
    """
    Unidirectional view of a bidirectional channel.
    """
    class State(Enum):
        OPEN = 1,
        SETTLING = 2,
        SETTLED = 3

    @staticmethod
    def from_id(
        channel_id: ChannelId
    ) -> Tuple['ChannelView', 'ChannelView']:
        # TODO: recover on-chain channel information from channel ID
        participant1 = ''
        participant2 = ''
        token = ''
        deposit1 = 0
        deposit2 = 0
        return (
            ChannelView(participant1, participant2, token, deposit1),
            ChannelView(participant2, participant1, token, deposit2)
        )

    def __init__(
        self,
        participant1: Address,
        participant2: Address,
        token: Address,
        deposit: int = 0
    ):
        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.self = participant1
        self.partner = participant2
        self.token = token

        self._deposit = deposit
        self._transferred_amount = 0
        self._locked_amount = 0
        self._capacity = deposit
        self.state = ChannelView.State.OPEN

    def update_capacity(
        self,
        deposit: int = None,
        transferred_amount: int = None,
        locked_amount: int = None
    ):
        if deposit is not None:
            self._deposit = deposit
        if transferred_amount is not None:
            self._transferred_amount = transferred_amount
        if locked_amount is not None:
            self._locked_amount = locked_amount

        self._capacity = self.deposit - self.transferred_amount - self.locked_amount

    @property
    def deposit(self):
        return self._deposit

    @property
    def transferred_amount(self):
        return self._transferred_amount

    @property
    def locked_amount(self):
        return self._locked_amount
