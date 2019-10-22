from typing import Tuple

from raiden.exceptions import UndefinedMediationFee
from raiden.transfer.channel import get_balance
from raiden.transfer.mediated_transfer.initiator import calculate_safe_amount_with_fee
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.mediated_transfer.mediator import find_intersection
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import (
    Balance,
    FeeAmount,
    List,
    NamedTuple,
    Optional,
    PaymentAmount,
    PaymentWithFeeAmount,
    TokenAmount,
)


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


def get_amount_with_fees(
    amount_without_fees: PaymentWithFeeAmount,
    balance_in: Balance,
    balance_out: Balance,
    schedule_in: FeeScheduleState,
    schedule_out: FeeScheduleState,
    receivable_amount: TokenAmount,
) -> Optional[PaymentWithFeeAmount]:
    """ Return the amount the transfer requires before fees are deducted.

    This function is also used by the PFS. Therefore the parameters should not be Raiden state
    objects.

    Returns `None` when there is no payable amount_with_fees. Potential reasons:
    * not enough capacity
    * amount_without_fees is so low that it does not even cover the mediation fees
    """
    assert (
        schedule_in.cap_fees == schedule_out.cap_fees
    ), "Both channels must have the same cap_fees setting for the same mediator."
    try:
        fee_func = FeeScheduleState.mediation_fee_backwards_func(
            schedule_in=schedule_in,
            schedule_out=schedule_out,
            balance_in=balance_in,
            balance_out=balance_out,
            receivable=receivable_amount,
            amount_without_fees=amount_without_fees,
            cap_fees=schedule_in.cap_fees,
        )
        amount_with_fees = find_intersection(
            fee_func, lambda i: fee_func.x_list[i] - amount_without_fees
        )
    except UndefinedMediationFee:
        return None

    if amount_with_fees is None:
        return None
    if amount_with_fees <= 0:
        # The node can't cover its mediations fees from the transferred amount.
        return None

    return PaymentWithFeeAmount(int(round(amount_with_fees)))


def get_initial_amount_for_amount_after_fees(
    amount_after_fees: PaymentAmount,
    channels: List[Tuple[NettingChannelState, NettingChannelState]],
) -> Optional[FeesCalculation]:
    """ Calculates the payment amount including fees to be supplied to the given
    channel configuration, so that `amount_after_fees` arrives at the target.

    Note: The channels have to be from the view of the mediator, so for the case
        A -> B -> C this should be [(B->A, B->C)]
    """
    assert len(channels) >= 1, "Need at least one channel pair"

    # Backpropagate fees in mediation scenario
    total = PaymentWithFeeAmount(amount_after_fees)
    fees: List[FeeAmount] = []
    try:
        for channel_in, channel_out in reversed(channels):
            assert isinstance(channel_in, NettingChannelState)
            assert isinstance(channel_out, NettingChannelState)

            balance_in = get_balance(channel_in.our_state, channel_in.partner_state)
            balance_out = get_balance(channel_out.our_state, channel_out.partner_state)
            receivable_amount = TokenAmount(
                channel_in.our_total_deposit + channel_in.partner_total_deposit - balance_in
            )

            before_fees = get_amount_with_fees(
                amount_without_fees=total,
                balance_in=balance_in,
                balance_out=balance_out,
                schedule_in=channel_in.fee_schedule,
                schedule_out=channel_out.fee_schedule,
                receivable_amount=receivable_amount,
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
    amount_to_leave_initiator: PaymentAmount,
    channels: List[Tuple[NettingChannelState, NettingChannelState]],
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
