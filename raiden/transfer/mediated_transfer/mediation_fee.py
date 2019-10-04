from bisect import bisect_right
from dataclasses import dataclass, field, replace
from typing import List, Optional, Sequence, Tuple, TypeVar

from raiden.exceptions import UndefinedMediationFee
from raiden.transfer.architecture import State
from raiden.utils.typing import (
    Balance,
    FeeAmount,
    PaymentWithFeeAmount,
    ProportionalFeeAmount,
    TokenAmount,
)

NUM_DISCRETISATION_POINTS = 21


class Interpolate:  # pylint: disable=too-few-public-methods
    """ Linear interpolation of a function with given points

    Based on https://stackoverflow.com/a/7345691/114926
    """

    def __init__(self, x_list: Sequence, y_list: Sequence):
        if any(y - x <= 0 for x, y in zip(x_list, x_list[1:])):
            raise ValueError("x_list must be in strictly ascending order!")
        self.x_list = x_list
        self.y_list = y_list
        intervals = zip(x_list, x_list[1:], y_list, y_list[1:])
        self.slopes = [(y2 - y1) / (x2 - x1) for x1, x2, y1, y2 in intervals]

    def __call__(self, x: float) -> float:
        if not self.x_list[0] <= x <= self.x_list[-1]:
            raise ValueError("x out of bounds!")
        if x == self.x_list[-1]:
            return self.y_list[-1]
        i = bisect_right(self.x_list, x) - 1
        return self.y_list[i] + self.slopes[i] * (x - self.x_list[i])


T = TypeVar("T", bound="FeeScheduleState")


@dataclass
class FeeScheduleState(State):
    # pylint: disable=not-an-iterable
    flat: FeeAmount = FeeAmount(0)
    proportional: ProportionalFeeAmount = ProportionalFeeAmount(0)  # as micros, e.g. 1% = 0.01e6
    imbalance_penalty: Optional[List[Tuple[TokenAmount, FeeAmount]]] = None
    _penalty_func: Optional[Interpolate] = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        self._update_penalty_func()

    def _update_penalty_func(self) -> None:
        if self.imbalance_penalty:
            assert isinstance(self.imbalance_penalty, list)
            x_list, y_list = tuple(zip(*self.imbalance_penalty))
            self._penalty_func = Interpolate(x_list, y_list)

    def imbalance_fee(self, amount: PaymentWithFeeAmount, balance: Balance) -> FeeAmount:
        if self._penalty_func:
            # Total channel balance - node balance = balance (used as x-axis for the penalty)
            balance = self._penalty_func.x_list[-1] - balance
            try:
                return FeeAmount(
                    round(self._penalty_func(balance + amount) - self._penalty_func(balance))
                )
            except ValueError:
                raise UndefinedMediationFee()

        return FeeAmount(0)

    def fee_payer(self, amount: PaymentWithFeeAmount, balance: Balance) -> FeeAmount:
        imbalance_fee = self.imbalance_fee(amount=PaymentWithFeeAmount(-amount), balance=balance)

        flat_fee = self.flat
        prop_fee = int(round(amount * self.proportional / 1e6))
        return FeeAmount(flat_fee + prop_fee + imbalance_fee)

    def fee_payee(
        self, amount: PaymentWithFeeAmount, balance: Balance, iterations: int = 2
    ) -> FeeAmount:
        def fee_out(imbalance_fee: FeeAmount) -> FeeAmount:
            return FeeAmount(
                round(
                    amount - ((amount - self.flat - imbalance_fee) / (1 + self.proportional / 1e6))
                )
            )

        imbalance_fee = FeeAmount(0)
        for _ in range(iterations):
            imbalance_fee = self.imbalance_fee(
                amount=PaymentWithFeeAmount(amount - fee_out(imbalance_fee)), balance=balance
            )

        return fee_out(imbalance_fee)

    def reversed(self: T) -> T:
        if not self.imbalance_penalty:
            return replace(self)
        max_penalty = max(penalty for x, penalty in self.imbalance_penalty)
        reversed_instance = replace(
            self,
            imbalance_penalty=[
                (x, FeeAmount(max_penalty - penalty)) for x, penalty in self.imbalance_penalty
            ],
        )
        self._update_penalty_func()
        return reversed_instance


def linspace(start: TokenAmount, stop: TokenAmount, num: int) -> List[TokenAmount]:
    """ Returns a list of num numbers from start to stop (inclusive). """
    assert num > 1
    assert start <= stop

    step = (stop - start) / (num - 1)

    result = []
    for i in range(num):
        result.append(TokenAmount(start + round(i * step)))

    return result


def calculate_imbalance_fees(
    channel_capacity: TokenAmount, proportional_imbalance_fee: ProportionalFeeAmount
) -> Optional[List[Tuple[TokenAmount, FeeAmount]]]:
    """ Calculates a U-shaped imbalance curve

    The penalty term takes the following value at the extrema:
    channel_capacity * (proportional_imbalance_fee / 1_000_000)
    """
    assert channel_capacity >= 0
    assert proportional_imbalance_fee >= 0

    if proportional_imbalance_fee == 0:
        return None

    if channel_capacity == 0:
        return None

    MAXIMUM_SLOPE = 0.1
    max_imbalance_fee = channel_capacity * proportional_imbalance_fee / 1e6

    assert proportional_imbalance_fee / 1e6 <= MAXIMUM_SLOPE / 2, "Too high imbalance fee"

    # calculate function parameters
    s = MAXIMUM_SLOPE
    c = max_imbalance_fee
    o = channel_capacity / 2
    b = s * o / c
    b = min(b, 10)  # limit exponent to keep numerical stability
    a = c / o ** b

    def f(x: TokenAmount) -> FeeAmount:
        return FeeAmount(int(round(a * abs(x - o) ** b)))

    # calculate discrete function points
    num_base_points = min(NUM_DISCRETISATION_POINTS, channel_capacity + 1)
    x_values = linspace(TokenAmount(0), channel_capacity, num_base_points)
    y_values = [f(x) for x in x_values]

    return list(zip(x_values, y_values))
