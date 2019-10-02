from itertools import islice

from raiden.exceptions import UndefinedMediationFee
from raiden.settings import INTERNAL_ROUTING_DEFAULT_FEE_PERC
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


def fee_sender(
    fee_schedule: FeeScheduleState, balance: Balance, amount: PaymentWithFeeAmount
) -> FeeAmount:
    """Returns the mediation fee for this channel when transferring the given amount"""
    imbalance_fee = imbalance_fee_sender(fee_schedule=fee_schedule, amount=amount, balance=balance)
    flat_fee = fee_schedule.flat
    prop_fee = int(round(amount * fee_schedule.proportional / 1e6))
    return FeeAmount(flat_fee + prop_fee + imbalance_fee)


def fee_receiver(
    fee_schedule: FeeScheduleState,
    balance: Balance,
    amount: PaymentWithFeeAmount,
    iterations: int = 2,
) -> FeeAmount:
    """Returns the mediation fee for this channel when receiving the given amount"""

    def fee_in(imbalance_fee: FeeAmount) -> FeeAmount:
        return FeeAmount(
            round(
                (
                    (amount + fee_schedule.flat + imbalance_fee)
                    / (1 - fee_schedule.proportional / 1e6)
                )
                - amount
            )
        )

    imbalance_fee = FeeAmount(0)
    for _ in range(iterations):
        imbalance_fee = imbalance_fee_receiver(
            fee_schedule=fee_schedule,
            amount=PaymentWithFeeAmount(amount + fee_in(imbalance_fee=imbalance_fee)),
            balance=balance,
        )

    return fee_in(imbalance_fee=imbalance_fee)


class FeesCalculation(NamedTuple):
    total_amount: PaymentWithFeeAmount
    mediation_fees: List[FeeAmount]


def get_initial_payment_for_final_target_amount(
    final_amount: PaymentAmount, channels: List[NettingChannelState]
) -> Optional[FeesCalculation]:
    """ Calculates the payment amount including fees to be supplied to the given
    channel configuration, so that `final_amount` arrived at the target.

    Note: The channels have to be from the view of the mediator, so for the case
        A -> B -> C this should be [B->A, B->C]
    """
    assert len(channels) >= 1, "Need at least one channel"

    # No fees in direct transfer
    if len(channels) == 1:
        return FeesCalculation(total_amount=PaymentWithFeeAmount(final_amount), mediation_fees=[])

    # Backpropagate fees in mediation scenario
    total = PaymentWithFeeAmount(final_amount)
    fees: List[FeeAmount] = []
    try:
        for channel_in, channel_out in reversed(list(window(channels, 2))):
            assert isinstance(channel_in, NettingChannelState)
            fee_schedule_out = channel_out.fee_schedule
            assert isinstance(channel_out, NettingChannelState)
            fee_schedule_in = channel_in.fee_schedule

            balance_out = get_balance(channel_out.our_state, channel_out.partner_state)
            fee_out = fee_sender(fee_schedule=fee_schedule_out, balance=balance_out, amount=total)

            total += fee_out  # type: ignore

            balance_in = get_balance(channel_in.our_state, channel_in.partner_state)
            fee_in = fee_receiver(fee_schedule=fee_schedule_in, balance=balance_in, amount=total)

            total += fee_in  # type: ignore

            fees.append(FeeAmount(fee_out + fee_in))
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
        calculation = get_initial_payment_for_final_target_amount(
            final_amount=amount_at_target, channels=channels
        )
        if calculation is None:
            amount_at_target = PaymentAmount(amount_at_target - 1)
            continue

        total_amount_with_mediator_fees = calculation.total_amount
        mediation_fees = sum(calculation.mediation_fees)
        estimated_fee = max(
            mediation_fees, round(INTERNAL_ROUTING_DEFAULT_FEE_PERC * amount_at_target)
        )
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
