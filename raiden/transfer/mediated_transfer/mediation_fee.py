from bisect import bisect, bisect_right
from copy import copy
from dataclasses import dataclass, field
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

    def __repr__(self) -> str:
        return f"Interpolate({self.x_list}, {self.y_list})"


def sign(x: float) -> int:
    """ Sign of input, returns zero on zero input
    """
    if x == 0:
        return 0
    else:
        return 1 if x > 0 else -1


def _merge_x_values(
    schedule_in: "FeeScheduleState",
    schedule_out: "FeeScheduleState",
    balance_in: Balance,
    balance_out: Balance,
    max_x: int,
) -> List[float]:
    """ Collect all relevant x values (edges of piece wise linear sections) """
    assert schedule_in._penalty_func
    assert schedule_out._penalty_func
    all_x_vals = [x - balance_in for x in schedule_in._penalty_func.x_list] + [
        balance_out - x for x in schedule_out._penalty_func.x_list
    ]
    limited_x_vals = (max(min(x, balance_out, max_x), 0) for x in all_x_vals)
    return sorted(set(limited_x_vals))


def _cap_fees(x_list: List[float], y_list: List[float]) -> Tuple[List[float], List[float]]:
    """ Insert extra points for intersections with x-axis, see `test_fee_capping` """
    x_list = copy(x_list)
    y_list = copy(y_list)

    for i in range(len(x_list) - 1):
        y1, y2 = y_list[i : i + 2]
        if sign(y1) * sign(y2) == -1:
            x1, x2 = x_list[i : i + 2]
            new_x = abs(y1) / abs(y2 - y1) * (x2 - x1)
            new_index = bisect(x_list, new_x)
            x_list.insert(new_index, new_x)
            y_list.insert(new_index, 0)

    # Cap points that are below zero
    y_list = [max(y, 0) for y in y_list]
    return x_list, y_list


T = TypeVar("T", bound="FeeScheduleState")


@dataclass
class FeeScheduleState(State):
    # pylint: disable=not-an-iterable
    cap_fees: bool = True
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

    def _fee(self, balance: Balance, amount: float) -> float:
        assert self._penalty_func
        return (
            self.flat
            + self.proportional / 1e6 * abs(amount)
            + self._penalty_func(balance + amount)
            - self._penalty_func(balance)
        )

    @staticmethod
    def mediation_fee_func(
        schedule_in: "FeeScheduleState",
        schedule_out: "FeeScheduleState",
        balance_in: Balance,
        balance_out: Balance,
        capacity_in: TokenAmount,  # TODO: rename
        amount_with_fees: PaymentWithFeeAmount,
        cap_fees: bool,
    ) -> Interpolate:
        if amount_with_fees > capacity_in:
            raise UndefinedMediationFee()
        if balance_out == 0:
            raise UndefinedMediationFee()

        # Add dummy penalty funcs if none are set
        if not schedule_in._penalty_func:
            schedule_in = copy(schedule_in)
            schedule_in._penalty_func = Interpolate([0, balance_in + capacity_in], [0, 0])
        if not schedule_out._penalty_func:
            schedule_out = copy(schedule_out)
            schedule_out._penalty_func = Interpolate([0, balance_out], [0, 0])

        x_list = _merge_x_values(
            schedule_in, schedule_out, balance_in, balance_out, max_x=capacity_in
        )

        # Sum up fees where amount_with_fees is fixed and x is amount without fees
        try:
            y_list = [
                schedule_in._fee(balance_in, amount_with_fees) + schedule_out._fee(balance_out, -x)
                for x in x_list
            ]
        except ValueError:
            raise UndefinedMediationFee()

        if cap_fees:
            x_list, y_list = _cap_fees(x_list, y_list)

        return Interpolate(x_list, y_list)

    @staticmethod
    def mediation_fee_backwards_func(
        schedule_in: "FeeScheduleState",
        schedule_out: "FeeScheduleState",
        balance_in: Balance,
        balance_out: Balance,
        capacity_in: TokenAmount,
        capacity_out: TokenAmount,  # TODO: rename
        amount_after_fees: PaymentWithFeeAmount,
        cap_fees: bool,
    ) -> Interpolate:
        if amount_after_fees > capacity_in:
            raise UndefinedMediationFee()
        if balance_out == 0:
            raise UndefinedMediationFee()

        # Add dummy penalty funcs if none are set
        if not schedule_in._penalty_func:
            schedule_in = copy(schedule_in)
            schedule_in._penalty_func = Interpolate([0, balance_in + capacity_in], [0, 0])
        if not schedule_out._penalty_func:
            schedule_out = copy(schedule_out)
            schedule_out._penalty_func = Interpolate([0, balance_out + capacity_out], [0, 0])

        x_list = _merge_x_values(
            schedule_in, schedule_out, balance_in, balance_out, max_x=capacity_in
        )

        # Sum up fees where amount_after_fees is fixed and x is amount with fees
        try:
            y_list = [
                schedule_in._fee(balance_in, x)
                + schedule_out._fee(balance_out, -amount_after_fees)
                for x in x_list
            ]
        except ValueError:
            raise UndefinedMediationFee()

        if cap_fees:
            x_list, y_list = _cap_fees(x_list, y_list)

        return Interpolate(x_list, y_list)


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
