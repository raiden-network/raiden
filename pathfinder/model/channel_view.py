from enum import Enum

from eth_utils import is_checksum_address

from pathfinder.config import DEFAULT_PERCENTAGE_FEE
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
    ) -> None:
        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.self = participant1
        self.partner = participant2

        self._deposit = deposit
        self._transferred_amount = 0
        self._received_amount = 0
        self._locked_amount = 0
        self._percentage_fee = DEFAULT_PERCENTAGE_FEE
        self._capacity = deposit
        self.state = ChannelView.State.OPEN
        self.channel_id = channel_id
        self.balance_proof_nonce = 0
        self.fee_info_nonce = 0

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

    def update_fee(self, nonce: int = None, percentage_fee: float = None):
        if nonce is not None:
            assert nonce > self.fee_info_nonce, 'Fee nonce must increase.'
            self.fee_info_nonce = nonce

        if percentage_fee is not None:
            self._percentage_fee = percentage_fee

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
    def percentage_fee(self) -> float:
        return self._percentage_fee

    def __repr__(self):
        return '<ChannelView from={} to={} capacity={}>'.format(
            self.self,
            self.partner,
            self.capacity
        )
