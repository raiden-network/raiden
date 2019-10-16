from itertools import islice

from raiden.exceptions import UndefinedMediationFee
from raiden.transfer.channel import get_balance
from raiden.transfer.mediated_transfer.initiator import calculate_safe_amount_with_fee
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import (
    Balance,
    FeeAmount,
    Iterable,
    List,
    NamedTuple,
    Optional,
    PaymentAmount,
    PaymentWithFeeAmount,
    Sequence,
    TokenAmount,
)


def window(seq: Sequence, n: int = 2) -> Iterable[tuple]:
    """Returns a sliding window (of width n) over data from the iterable
    s -> (s0,s1,...s[n-1]), (s1,s2,...,sn), ...
    See https://stackoverflow.com/a/6822773/114926
    """
    remaining_elements = iter(seq)
    result = tuple(islice(remaining_elements, n))
    if len(result) == n:
        yield result
    for elem in remaining_elements:
        result = result[1:] + (elem,)
        yield result


def imbalance_fee_receiver(
    fee_schedule: FeeScheduleState, amount: PaymentWithFeeAmount, balance: Balance
) -> FeeAmount:
    if not fee_schedule._penalty_func:
        return FeeAmount(0)

    # Calculate the mediators balance
    balance = fee_schedule._penalty_func.x_list[-1] - balance
    try:
        return FeeAmount(
            # Mediator is gaining balance on his channel side
            round(
                fee_schedule._penalty_func(balance + amount) - fee_schedule._penalty_func(balance)
            )
        )
    except ValueError:
        raise UndefinedMediationFee()


def imbalance_fee_sender(
    fee_schedule: FeeScheduleState, amount: PaymentWithFeeAmount, balance: Balance
) -> FeeAmount:
    if not fee_schedule._penalty_func:
        return FeeAmount(0)

    try:
        return FeeAmount(
            # Mediator is loosing balance on his channel side
            round(
                fee_schedule._penalty_func(balance - amount) - fee_schedule._penalty_func(balance)
            )
        )
    except ValueError:
        raise UndefinedMediationFee()


class FeesCalculation(NamedTuple):
    total_amount: PaymentWithFeeAmount
    mediation_fees: List[FeeAmount]

    @property
    def amount_without_fees(self) -> PaymentAmount:
        return PaymentAmount(self.total_amount - sum(self.mediation_fees))


def get_amount_before_fees(
    final_amount: PaymentWithFeeAmount,
    payer_balance: Balance,
    payee_balance: Balance,
    payer_fee_schedule: FeeScheduleState,
    payee_fee_schedule: FeeScheduleState,
    payer_capacity: TokenAmount,
    payee_capacity: TokenAmount,
) -> Optional[PaymentWithFeeAmount]:
    """ Return the amount the transfer requires before fees are deducted.

    This function is also used by the PFS. Therefore the parameteres should not be Raiden state
    objects.
    """
    assert (
        payer_fee_schedule.cap_fees == payee_fee_schedule.cap_fees
    ), "Both channels must have the same cap_fees setting for the same mediator."
    try:
        fee_func = FeeScheduleState.mediation_fee_backwards_func(
            schedule_in=payer_fee_schedule,
            schedule_out=payee_fee_schedule,
            balance_in=payer_balance,
            balance_out=payee_balance,
            capacity_in=payer_capacity,
            capacity_out=payee_capacity,
            amount_after_fees=final_amount,
            cap_fees=payer_fee_schedule.cap_fees,
        )
    except UndefinedMediationFee:
        return None

    def angle_bisector(i: int) -> float:
        x = fee_func.x_list[i]
        return x - final_amount

    i = 0  # len(fee_func.x_list) - 1
    y = fee_func.y_list[i]
    if y < angle_bisector(i):
        # TODO: can this happen? Should we throw an exception?
        return None
    while y >= angle_bisector(i):
        i += 1
        if i == len(fee_func.x_list):
            # Not enough capacity to send
            return None
        y = fee_func.y_list[i]
    try:
        # We found the linear section where the solution is. Now interpolate!
        x1 = fee_func.x_list[i - 1]
        x2 = fee_func.x_list[i]
        y1 = fee_func.y_list[i - 1]
        y2 = fee_func.y_list[i]
        slope = (y2 - y1) / (x2 - x1)
        amount_with_fees = (y1 - slope * x1 + final_amount) / (1 - slope)
    except UndefinedMediationFee:
        return None

    amount_after_fees = PaymentWithFeeAmount(int(round(amount_with_fees)))

    if amount_after_fees <= 0:
        # The node can't cover its mediations fees from the transferred amount.
        return None

    return amount_after_fees


def get_initial_amount_for_amount_after_fees(
    amount_after_fees: PaymentAmount, channels: List[NettingChannelState]
) -> Optional[FeesCalculation]:
    """ Calculates the payment amount including fees to be supplied to the given
    channel configuration, so that `amount_after_fees` arrives at the target.

    Note: The channels have to be from the view of the mediator, so for the case
        A -> B -> C this should be [B->A, B->C]
    """
    assert len(channels) >= 1, "Need at least one channel"

    # No fees in direct transfer
    if len(channels) == 1:
        return FeesCalculation(
            total_amount=PaymentWithFeeAmount(amount_after_fees), mediation_fees=[]
        )

    # Backpropagate fees in mediation scenario
    total = PaymentWithFeeAmount(amount_after_fees)
    fees: List[FeeAmount] = []
    try:
        for channel_in, channel_out in reversed(list(window(channels, 2))):
            assert isinstance(channel_in, NettingChannelState)
            assert isinstance(channel_out, NettingChannelState)

            payer_balance = get_balance(channel_in.our_state, channel_in.partner_state)
            payee_balance = get_balance(channel_out.our_state, channel_out.partner_state)

            payer_fee_schedule = channel_in.fee_schedule
            payee_fee_schedule = channel_out.fee_schedule

            capacity_in = TokenAmount(
                channel_in.our_total_deposit + channel_in.partner_total_deposit - payer_balance
            )
            capacity_out = TokenAmount(
                channel_out.our_total_deposit + channel_out.partner_total_deposit - payee_balance
            )

            before_fees = get_amount_before_fees(
                final_amount=total,
                payer_balance=payer_balance,
                payee_balance=payee_balance,
                payer_fee_schedule=payer_fee_schedule,
                payee_fee_schedule=payee_fee_schedule,
                payer_capacity=capacity_in,
                payee_capacity=capacity_out,
            )

            if before_fees is None:
                return None

            fee = FeeAmount(before_fees - total)
            total = PaymentWithFeeAmount(total + fee)
            fees.append(fee)
    except UndefinedMediationFee:
        return None

    return FeesCalculation(total_amount=PaymentWithFeeAmount(total), mediation_fees=fees)


class PaymentAmountCalculation(NamedTuple):
    """
    Represents the result of get_amounts_to_drain_channel_with_fees

    Differ from FeesCalculation in the fact that this returns the amount to send
    without any fees or fee estimates.
    """

    amount_to_send: PaymentAmount
    mediation_fees: List[FeeAmount]
    amount_with_fees: PaymentWithFeeAmount


def get_amount_for_sending_before_and_after_fees(
    amount_to_leave_initiator: PaymentAmount, channels: List[NettingChannelState]
) -> Optional[PaymentAmountCalculation]:
    """
    Calculates the amount needed to be sent by the initiator (before fees) in
    order for his balance to be reduced by `amount_to_leave_initiator`.

    Also returns the fees kept by the mediators.
    """
    amount_at_target = amount_to_leave_initiator
    while amount_at_target != 0:
        calculation = get_initial_amount_for_amount_after_fees(
            amount_after_fees=amount_at_target, channels=channels
        )
        if calculation is None:
            amount_at_target = PaymentAmount(amount_at_target - 1)
            continue

        total_amount_with_mediator_fees = calculation.total_amount
        mediation_fees = sum(calculation.mediation_fees)
        estimated_fee = mediation_fees
        estimated_total_amount_at_initiator = calculate_safe_amount_with_fee(
            payment_amount=amount_at_target, estimated_fee=FeeAmount(estimated_fee)
        )

        send_amount = min(
            estimated_total_amount_at_initiator, total_amount_with_mediator_fees - mediation_fees
        )
        send_amount_with_fees = max(
            estimated_total_amount_at_initiator, total_amount_with_mediator_fees
        )

        if send_amount_with_fees <= amount_to_leave_initiator:
            return PaymentAmountCalculation(
                amount_to_send=PaymentAmount(send_amount),
                mediation_fees=calculation.mediation_fees,
                amount_with_fees=send_amount_with_fees,
            )

        amount_at_target = PaymentAmount(amount_at_target - 1)

    return None
