from itertools import islice

from raiden.exceptions import UndefinedMediationFee
from raiden.transfer.channel import get_balance
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import (
    Balance,
    FeeAmount,
    Iterable,
    List,
    Optional,
    PaymentAmount,
    PaymentWithFeeAmount,
    Sequence,
    Tuple,
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


def fee_sender(
    fee_schedule: FeeScheduleState, balance: Balance, amount: PaymentWithFeeAmount
) -> Optional[FeeAmount]:
    """Returns the mediation fee for this channel when transferring the given amount"""
    try:
        imbalance_fee = fee_schedule.imbalance_fee(amount=amount, balance=balance)
    except UndefinedMediationFee:
        return None

    flat_fee = fee_schedule.flat
    prop_fee = int(round(amount * fee_schedule.proportional / 1e6))
    return FeeAmount(flat_fee + prop_fee + imbalance_fee)


def fee_receiver(
    fee_schedule: FeeScheduleState, balance: Balance, amount: PaymentWithFeeAmount
) -> Optional[FeeAmount]:
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

    imbalance_fee = fee_schedule.imbalance_fee(
        amount=PaymentWithFeeAmount(-(amount - fee_in(imbalance_fee=FeeAmount(0)))),
        balance=balance,
    )

    return fee_in(imbalance_fee=imbalance_fee)


def get_initial_payment_for_final_target_amount(
    final_amount: PaymentAmount, channels: List[NettingChannelState]
) -> Optional[Tuple[PaymentWithFeeAmount, List[FeeAmount]]]:
    """ Calculates the payment amount including fees to be supplied to the given
    channel configuration, so that `final_amount` arrived at the target. """

    assert len(channels) >= 1, "Need at least one channel"

    # No fees in direct transfer
    if len(channels) == 1:
        return PaymentWithFeeAmount(final_amount), []

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
            if fee_out is None:
                return None

            total += fee_out  # type: ignore

            balance_in = get_balance(channel_in.our_state, channel_in.partner_state)
            fee_in = fee_receiver(fee_schedule=fee_schedule_in, balance=balance_in, amount=total)
            if fee_in is None:
                return None

            total += fee_in  # type: ignore

            fees.append(FeeAmount(fee_out + fee_in))
    except UndefinedMediationFee:
        return None

    return PaymentWithFeeAmount(total), fees
