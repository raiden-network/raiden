import pytest
from hypothesis import assume, given
from hypothesis.strategies import integers

from raiden.tests.unit.transfer.test_channel import make_hash_time_lock_state
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
)
from raiden.tests.utils.mediation_fees import get_initial_amount_for_amount_after_fees
from raiden.transfer.mediated_transfer.initiator import calculate_safe_amount_with_fee
from raiden.transfer.mediated_transfer.mediation_fee import (
    NUM_DISCRETISATION_POINTS,
    FeeScheduleState,
    Interpolate,
    calculate_imbalance_fees,
    linspace,
)
from raiden.transfer.mediated_transfer.mediator import get_amount_after_fees
from raiden.utils.mediation_fees import ppm_fee_per_channel
from raiden.utils.typing import (
    Balance,
    FeeAmount,
    PaymentAmount,
    PaymentWithFeeAmount,
    ProportionalFeeAmount,
    TokenAmount,
)


def test_interpolation():
    interp = Interpolate((0, 100), (0, 100))
    for i in range(101):
        assert interp(i) == i

    interp = Interpolate((0, 50, 100), (0, 100, 200))
    for i in range(101):
        assert interp(i) == 2 * i

    interp = Interpolate((0, 50, 100), (0, -50, 50))
    assert interp(40) == -40
    assert interp(60) == -30
    assert interp(90) == 30
    assert interp(99) == 48

    interp = Interpolate((0, 100), (12.35, 67.2))
    assert interp(0) == 12.35
    assert interp(50) == pytest.approx((12.35 + 67.2) / 2)
    assert interp(100) == 67.2


@pytest.mark.skip("reenable after refactoring")
def test_basic_fee():
    """
    flat_schedule = FeeScheduleState(flat=FeeAmount(2))
    assert flat_schedule.fee_payer(PaymentWithFeeAmount(10), balance=Balance(0)) == FeeAmount(2)

    prop_schedule = FeeScheduleState(proportional=ProportionalFeeAmount(int(0.01e6)))
    assert prop_schedule.fee_payer(PaymentWithFeeAmount(40), balance=Balance(0)) == FeeAmount(0)
    assert prop_schedule.fee_payer(PaymentWithFeeAmount(60), balance=Balance(0)) == FeeAmount(1)
    assert prop_schedule.fee_payer(PaymentWithFeeAmount(1000), balance=Balance(0)) == FeeAmount(10)

    combined_schedule = FeeScheduleState(
        flat=FeeAmount(2), proportional=ProportionalFeeAmount(int(0.01e6))
    )
    assert combined_schedule.fee_payer(PaymentWithFeeAmount(60), balance=Balance(0)) == FeeAmount(
        3
    )
    """


@pytest.mark.skip("reenable after refactoring")
def test_imbalance_penalty():
    r""" Test an imbalance penalty by moving back and forth

    The imbalance fee looks like

    20 |         /
       |        /
    10 |\.     /
       |  \.  /
     0 |    \/
    ---------------
       0    50  100

    For each input, we first assume the channel is used to forward tokens to a
    payee, which moves the capacity from x1 to x2. The we assume the same
    amount is mediated in the opposite direction (moving from x2 to x1) and
    check that the calculated fee is the same as before just with the opposite
    sign.
    """
    """
    v_schedule = FeeScheduleState(
        imbalance_penalty=[
            (TokenAmount(0), FeeAmount(10)),
            (TokenAmount(50), FeeAmount(0)),
            (TokenAmount(100), FeeAmount(20)),
        ]
    )

    for cap_fees, x1, amount, expected_fee_payee, expected_fee_payer in [
        # Uncapped fees
        (False, 0, 50, -6, 10),
        (False, 50, 50, 12, -20),
        (False, 0, 10, -2, 2),
        (False, 10, 10, -2, 2),
        (False, 0, 20, -5, 4),
        (False, 40, 15, 0, 0),
        # Capped fees
        (True, 0, 50, 0, 10),
        (True, 50, 50, 12, 0),
        (True, 0, 10, 0, 2),
        (True, 10, 10, 0, 2),
        (True, 0, 20, 0, 4),
        (True, 40, 15, 0, 0),
    ]:
        v_schedule.cap_fees = cap_fees
        x2 = x1 + amount
        assert v_schedule.fee_payee(
            balance=Balance(100 - x1), amount=PaymentWithFeeAmount(amount)
        ) == FeeAmount(expected_fee_payee)
        assert v_schedule.fee_payer(
            balance=Balance(100 - x2), amount=PaymentWithFeeAmount(amount)
        ) == FeeAmount(expected_fee_payer)

    with pytest.raises(UndefinedMediationFee):
        v_schedule.fee_payee(balance=Balance(0), amount=PaymentWithFeeAmount(1))
    with pytest.raises(UndefinedMediationFee):
        v_schedule.fee_payer(balance=Balance(100), amount=PaymentWithFeeAmount(1))
    """


def test_fee_capping():
    r""" Test the capping when one section of the fee function crossed from the
    positive into negative fees. Here, our fee curve looks like:

        Fee
        |
      5 +
        |\
        | \
      0 +--+-----+-> incoming_amount
        | 25\   100
        |    \
        |     \
        |      \
        |       \
    -15 +        \
        0

    When capping it, we need to insert the intersection point of (25, 0) into
    our piecewise linear function before capping all y values to zero.
    Otherwise we would just interpolate between (0, 5) and (100, 0).
    """
    schedule = FeeScheduleState(
        imbalance_penalty=[(TokenAmount(0), FeeAmount(0)), (TokenAmount(100), FeeAmount(20))],
        flat=FeeAmount(5),
    )
    fee_func = FeeScheduleState.mediation_fee_func(
        schedule_in=FeeScheduleState(),
        schedule_out=schedule,
        balance_in=Balance(0),
        balance_out=Balance(100),
        capacity_in=TokenAmount(100),
        amount_with_fees=PaymentWithFeeAmount(5),
        cap_fees=True,
    )
    assert fee_func(30) == 0  # 5 - 6, capped
    assert fee_func(20) == 5 - 4


def test_linspace():
    assert linspace(TokenAmount(0), TokenAmount(4), 5) == [0, 1, 2, 3, 4]
    assert linspace(TokenAmount(0), TokenAmount(4), 4) == [0, 1, 3, 4]
    assert linspace(TokenAmount(0), TokenAmount(4), 3) == [0, 2, 4]
    assert linspace(TokenAmount(0), TokenAmount(4), 2) == [0, 4]
    assert linspace(TokenAmount(0), TokenAmount(0), 3) == [0, 0, 0]

    with pytest.raises(AssertionError):
        assert linspace(TokenAmount(0), TokenAmount(4), 1)

    with pytest.raises(AssertionError):
        assert linspace(TokenAmount(4), TokenAmount(0), 2)


def test_rebalancing_fee_calculation():
    sample = calculate_imbalance_fees(TokenAmount(200), ProportionalFeeAmount(50_000))  # 5%
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert all(0 <= x <= 200 for x, _ in sample)
    assert max(x for x, _ in sample) == 200
    assert all(0 <= y <= 10 for _, y in sample)
    assert max(y for _, y in sample) == 10  # 5% of the 200 TokenAmount capacity

    sample = calculate_imbalance_fees(TokenAmount(100), ProportionalFeeAmount(20_000))  # 2%
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert all(0 <= x <= 100 for x, _ in sample)
    assert max(x for x, _ in sample) == 100
    assert all(0 <= y <= 2 for _, y in sample)
    assert max(y for _, y in sample) == 2  # 2% of the 100 TokenAmount capacity

    sample = calculate_imbalance_fees(TokenAmount(15), ProportionalFeeAmount(50_000))  # 5%
    assert sample is not None
    assert len(sample) == 16
    assert all(0 <= x <= 16 for x, _ in sample)
    assert max(x for x, _ in sample) == 15
    assert all(0 <= y <= 1 for _, y in sample)
    assert max(y for _, y in sample) == 1  # 5% of the 5 rounded up

    # test rounding of the max_balance_fee calculation
    sample = calculate_imbalance_fees(TokenAmount(1000), ProportionalFeeAmount(5_490))  # 0.549%
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert all(0 <= x <= 1000 for x, _ in sample)
    assert max(x for x, _ in sample) == 1000
    assert all(0 <= y <= 5 for _, y in sample)
    assert max(y for _, y in sample) == 5  # 5.49 is rounded to 5

    sample = calculate_imbalance_fees(TokenAmount(1000), ProportionalFeeAmount(5_500))  # 0.55%
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert all(0 <= x <= 1000 for x, _ in sample)
    assert max(x for x, _ in sample) == 1000
    assert all(0 <= y <= 6 for _, y in sample)
    assert max(y for _, y in sample) == 6  # 5.5 is rounded to 6

    # test cases where no imbalance fee is created
    assert calculate_imbalance_fees(TokenAmount(0), ProportionalFeeAmount(1)) is None
    assert calculate_imbalance_fees(TokenAmount(10), ProportionalFeeAmount(0)) is None


@pytest.mark.parametrize(
    "flat_fee, prop_fee, initial_amount, expected_amount",
    [
        # pure flat fee
        (50, 0, 1000, 1000 - 50 - 50),
        # proportional fee
        (0, 1_000_000, 2000, 1000),  # 100% per hop mediation fee
        (0, 100_000, 1100, 1000),  # 10% per hop mediation fee
        (0, 50_000, 1050, 1000),  # 5% per hop mediation fee
        (0, 10_000, 1010, 1000),  # 1% per hop mediation fee
        (0, 10_000, 101, 100),  # 1% per hop mediation fee
        (0, 4_990, 100, 100),  # 0,499% per hop mediation fee gets rounded away
        # mixed tests
        (1, 500_000, 1000 + 500 + 2, 1000),
        (10, 500_000, 1000 + 500 + 20, 997),
        (100, 500_000, 1000 + 500 + 200, 967),
        # -
        (1, 100_000, 1000 + 100 + 2, 1000),
        (10, 100_000, 1000 + 100 + 20, 999),
        (100, 100_000, 1000 + 100 + 200, 991),
        # -
        (1, 10_000, 1000 + 10 + 2, 1000),
        (10, 10_000, 1000 + 10 + 20, 1000),
        (100, 10_000, 1000 + 10 + 200, 999),
        # -
        (100, 500_000, 1000 + 750, 1000),
        # - values found in run_test_mediated_transfer_with_fees
        (0, 200_000, 47 + 9, 47),
        (0, 200_000, 39 + 8, 39),
    ],
)
def test_get_lock_amount_after_fees(flat_fee, prop_fee, initial_amount, expected_amount):
    """ Tests mediation fee deduction. """
    prop_fee_per_channel = ppm_fee_per_channel(ProportionalFeeAmount(prop_fee))
    lock = make_hash_time_lock_state(amount=initial_amount)
    payer_channel = factories.create(
        NettingChannelStateProperties(
            partner_state=NettingChannelEndStateProperties(balance=TokenAmount(2000)),
            fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee_per_channel),
        )
    )
    payee_channel = factories.create(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=TokenAmount(2000)),
            fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee_per_channel),
        )
    )

    locked_after_fees = get_amount_after_fees(
        incoming_amount=lock.amount, payer_channel=payer_channel, payee_channel=payee_channel
    )
    assert locked_after_fees == expected_amount


@pytest.mark.parametrize(
    "cap_fees, flat_fee, prop_fee, imbalance_fee, initial_amount, expected_amount",
    [
        # No capping of the mediation fees
        # The higher the imbalance fee, the stronger the impact of the fee iteration
        (False, 0, 0, 10_000, 50_000, 50_000 + 2_000),
        (False, 0, 0, 20_000, 50_000, 50_000 + 3_995),
        (False, 0, 0, 30_000, 50_000, 50_000 + 5_910),
        (False, 0, 0, 40_000, 50_000, 50_000 + 7_613),
        (False, 0, 0, 50_000, 50_000, 50_000 + 9_091),
        # Capping of mediation fees
        (True, 0, 0, 10_000, 50_000, 50_000),
        (True, 0, 0, 20_000, 50_000, 50_000),
        (True, 0, 0, 30_000, 50_000, 50_000),
        (True, 0, 0, 40_000, 50_000, 50_000),
        (True, 0, 0, 50_000, 50_000, 50_000),
    ],
)
def test_get_lock_amount_after_fees_imbalanced_channel(
    cap_fees, flat_fee, prop_fee, imbalance_fee, initial_amount, expected_amount
):
    """ Tests mediation fee deduction. """
    balance = TokenAmount(100_000)
    prop_fee_per_channel = ppm_fee_per_channel(ProportionalFeeAmount(prop_fee))
    imbalance_fee = calculate_imbalance_fees(
        channel_capacity=balance, proportional_imbalance_fee=ProportionalFeeAmount(imbalance_fee)
    )
    lock = make_hash_time_lock_state(amount=initial_amount)
    payer_channel = factories.create(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=TokenAmount(0)),
            partner_state=NettingChannelEndStateProperties(balance=balance),
            fee_schedule=FeeScheduleState(
                cap_fees=cap_fees,
                flat=FeeAmount(flat_fee),
                proportional=prop_fee_per_channel,
                imbalance_penalty=imbalance_fee,
            ),
        )
    )
    payee_channel = factories.create(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=balance),
            partner_state=NettingChannelEndStateProperties(balance=TokenAmount(0)),
            fee_schedule=FeeScheduleState(
                cap_fees=cap_fees,
                flat=FeeAmount(flat_fee),
                proportional=prop_fee_per_channel,
                imbalance_penalty=imbalance_fee,
            ),
        )
    )

    locked_after_fees = get_amount_after_fees(
        incoming_amount=lock.amount, payer_channel=payer_channel, payee_channel=payee_channel
    )
    assert locked_after_fees == expected_amount


@given(
    integers(min_value=0, max_value=100),
    integers(min_value=0, max_value=10_000),
    integers(min_value=0, max_value=50_000),
    integers(min_value=1, max_value=90_000),
    integers(min_value=1, max_value=100_000),
    integers(min_value=1, max_value=100_000),
)
def test_fee_round_trip(flat_fee, prop_fee, imbalance_fee, amount, balance1, balance2):
    """ Tests mediation fee deduction.

    First we're doing a PFS-like calculation going backwards from the target
    amount to get the amount that the initiator has to send. Then we calculate
    the fees from a mediator's point of view and check if `amount_with_fees -
    fees = amount`.
    """
    # Find examples where there is a reasonable chance of succeeding
    amount = int(min(amount, balance1 * 0.95 - 1, balance2 * 0.95 - 1))
    assume(amount > 0)

    total_balance = TokenAmount(100_000)
    prop_fee_per_channel = ppm_fee_per_channel(ProportionalFeeAmount(prop_fee))
    imbalance_fee = calculate_imbalance_fees(
        channel_capacity=total_balance,
        proportional_imbalance_fee=ProportionalFeeAmount(imbalance_fee),
    )
    payer_channel = factories.create(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=total_balance - balance1),
            partner_state=NettingChannelEndStateProperties(balance=balance1),
            fee_schedule=FeeScheduleState(
                cap_fees=False,
                flat=FeeAmount(flat_fee),
                proportional=prop_fee_per_channel,
                imbalance_penalty=imbalance_fee,
            ),
        )
    )
    payee_channel = factories.create(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=balance2),
            partner_state=NettingChannelEndStateProperties(balance=total_balance - balance2),
            fee_schedule=FeeScheduleState(
                cap_fees=False,
                flat=FeeAmount(flat_fee),
                proportional=prop_fee_per_channel,
                imbalance_penalty=imbalance_fee,
            ),
        )
    )

    # How much do we need to send so that the target receives `amount`? PFS-like calculation.
    fee_calculation = get_initial_amount_for_amount_after_fees(
        amount_after_fees=PaymentAmount(amount), channels=[payer_channel, payee_channel]
    )
    assume(fee_calculation)  # There is not enough capacity for the payment in all cases
    assert fee_calculation

    # How much would a mediator send to the target? Ideally exactly `amount`.
    amount_without_margin_after_fees = get_amount_after_fees(
        incoming_amount=fee_calculation.total_amount,
        payer_channel=payer_channel,
        payee_channel=payee_channel,
    )
    assume(amount_without_margin_after_fees)  # We might lack capacity for the payment
    assert abs(amount - amount_without_margin_after_fees) <= 1  # Equal except for rounding errors

    # We don't handle the case where mediation fees cancel each other out exactly to zero, yet.
    # Remove this assume after https://github.com/raiden-network/raiden-services/issues/569.
    assume(fee_calculation.mediation_fees[0] != 0 or imbalance_fee == 0)

    # If we add the fee margin, the mediator must always send at least `amount` to the target!
    amount_with_fee_and_margin = calculate_safe_amount_with_fee(
        fee_calculation.amount_without_fees, FeeAmount(sum(fee_calculation.mediation_fees))
    )
    amount_with_margin_after_fees = get_amount_after_fees(
        incoming_amount=amount_with_fee_and_margin,
        payer_channel=payer_channel,
        payee_channel=payee_channel,
    )
    assume(amount_with_margin_after_fees)  # We might lack capacity to add margins
    assert amount_with_margin_after_fees >= amount
