import pytest

from raiden.exceptions import UndefinedMediationFee
from raiden.tests.unit.transfer.test_channel import make_hash_time_lock_state
from raiden.tests.utils import factories
from raiden.tests.utils.factories import NettingChannelStateProperties
from raiden.transfer.mediated_transfer.mediation_fee import (
    NUM_DISCRETISATION_POINTS,
    FeeScheduleState,
    Interpolate,
    calculate_imbalance_fees,
    linspace,
)
from raiden.transfer.mediated_transfer.mediator import get_lock_amount_after_fees
from raiden.utils.mediation_fees import ppm_fee_per_channel
from raiden.utils.typing import (
    Balance,
    FeeAmount,
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


def test_basic_fee():
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


def test_imbalance_penalty():
    v_schedule = FeeScheduleState(
        imbalance_penalty=[
            (TokenAmount(0), FeeAmount(10)),
            (TokenAmount(50), FeeAmount(0)),
            (TokenAmount(100), FeeAmount(10)),
        ]
    )
    assert v_schedule.fee_payee(
        balance=Balance(100 - 0), amount=PaymentWithFeeAmount(50)
    ) == FeeAmount(-10)
    # The payer channel works in the opposite direction
    assert v_schedule.fee_payer(
        balance=Balance(100 - 0), amount=PaymentWithFeeAmount(-50)
    ) == FeeAmount(-10)
    assert v_schedule.fee_payee(
        balance=Balance(100 - 50), amount=PaymentWithFeeAmount(50)
    ) == FeeAmount(10)
    assert v_schedule.fee_payee(
        balance=Balance(100 - 0), amount=PaymentWithFeeAmount(10)
    ) == FeeAmount(-2)
    assert v_schedule.fee_payee(
        balance=Balance(100 - 10), amount=PaymentWithFeeAmount(10)
    ) == FeeAmount(-2)
    assert v_schedule.fee_payee(
        balance=Balance(100 - 0), amount=PaymentWithFeeAmount(20)
    ) == FeeAmount(-4)
    assert v_schedule.fee_payee(
        balance=Balance(100 - 40), amount=PaymentWithFeeAmount(20)
    ) == FeeAmount(0)

    with pytest.raises(UndefinedMediationFee):
        v_schedule.fee_payee(balance=Balance(0), amount=PaymentWithFeeAmount(1))


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
    sample = calculate_imbalance_fees(TokenAmount(200), ProportionalFeeAmount(500_000))  # 50%
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert all(0 <= x <= 200 for x, _ in sample)
    assert max(x for x, _ in sample) == 200
    assert all(0 <= y <= 100 for _, y in sample)
    assert max(y for _, y in sample) == 100  # 50% of the 200 TokenAmount capacity

    sample = calculate_imbalance_fees(TokenAmount(10), ProportionalFeeAmount(200_000))  # 20%
    assert sample is not None
    assert len(sample) == 11
    assert all(0 <= x <= 10 for x, _ in sample)
    assert max(x for x, _ in sample) == 10
    assert all(0 <= y <= 2 for _, y in sample)
    assert max(y for _, y in sample) == 2  # 20% of the 10 TokenAmount capacity

    sample = calculate_imbalance_fees(TokenAmount(1), ProportionalFeeAmount(1_000_000))  # 100%
    assert sample is not None
    assert len(sample) == 2
    assert all(0 <= x <= 1 for x, _ in sample)
    assert max(x for x, _ in sample) == 1
    assert all(0 <= y <= 1 for _, y in sample)
    assert max(y for _, y in sample) == 1  # 100% of the 1 TokenAmount capacity

    # test rounding of the max_balance_fee calculation
    sample = calculate_imbalance_fees(TokenAmount(10), ProportionalFeeAmount(549_000))  # 54.9%
    assert sample is not None
    assert len(sample) == 11
    assert all(0 <= x <= 10 for x, _ in sample)
    assert max(x for x, _ in sample) == 10
    assert all(0 <= y <= 5 for _, y in sample)
    assert max(y for _, y in sample) == 5  # 5.49 is rounded to 5

    sample = calculate_imbalance_fees(TokenAmount(10), ProportionalFeeAmount(550_000))  # 55%
    assert sample is not None
    assert len(sample) == 11
    assert all(0 <= x <= 10 for x, _ in sample)
    assert max(x for x, _ in sample) == 10
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
        # proprtional fee
        (0, 1_000_000, 2000, 1000),  # 100% per hop mediation fee
        (0, 100_000, 1100, 1000),  # 10% per hop mediation fee
        (0, 50_000, 1050, 1000),  # 5% per hop mediation fee
        (0, 10_000, 1010, 1000),  # 1% per hop mediation fee
        (0, 10_000, 101, 100),  # 1% per hop mediation fee
        (0, 5_000, 101, 101),  # 0,5% per hop mediation fee gets rounded away
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
            fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee_per_channel)
        )
    )
    payee_channel = factories.create(
        NettingChannelStateProperties(
            fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee_per_channel)
        )
    )

    locked_after_fees = get_lock_amount_after_fees(
        lock=lock, payer_channel=payer_channel, payee_channel=payee_channel
    )
    assert locked_after_fees == expected_amount
