from enum import Enum

from eth_utils import is_checksum_address

from pathfinder.config import DEFAULT_FEE
from pathfinder.utils.types import Address, ChannelId


class ChannelView:
    """
    Unidirectional view of a bidirectional channel.
    """
    class State(Enum):
        OPEN = 1,
        SETTLING = 2,
        SETTLED = 3

    def __init__(
        self,
        channel_id: ChannelId,
        participant1: Address,
        participant2: Address,
        deposit: int = 0
    ):
        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.self = participant1
        self.partner = participant2

        self._deposit = deposit
        self._transferred_amount = 0
        self._received_amount = 0
        self._locked_amount = 0
        self.fee = DEFAULT_FEE
        self._capacity = deposit
        self.state = ChannelView.State.OPEN
        self.channel_id = channel_id
        self.balance_proof_nonce = -1

    def update_capacity(
        self,
        nonce: int = None,
        deposit: int = None,
        transferred_amount: int = None,
        received_amount: int = None,
        locked_amount: int = None
    ):
        if nonce is not None:
            assert nonce > self.balance_proof_nonce, 'Balance proof nonce must increase.'
            self.balance_proof_nonce = nonce

        if deposit is not None:
            self._deposit = deposit
        if transferred_amount is not None:
            self._transferred_amount = transferred_amount
        if received_amount is not None:
            self._received_amount = received_amount
        if locked_amount is not None:
            self._locked_amount = locked_amount

        self._capacity = self.deposit - (
            self.transferred_amount + self.locked_amount
        ) + self.received_amount

    @property
    def deposit(self):
        return self._deposit

    @property
    def transferred_amount(self):
        return self._transferred_amount

    @property
    def received_amount(self):
        return self._received_amount

    @property
    def locked_amount(self):
        return self._locked_amount

    @property
    def capacity(self):
        return self._capacity
