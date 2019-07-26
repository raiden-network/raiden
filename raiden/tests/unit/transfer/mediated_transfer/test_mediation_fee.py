import pytest

from raiden.transfer.mediated_transfer.mediation_fee import (
    NUM_DISCRETISATION_POINTS,
    FeeScheduleState,
    Interpolate,
    calculate_imbalance_fees,
    linspace,
)
from raiden.utils.typing import Balance, FeeAmount as FA, PaymentAmount, TokenAmount as TA


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
    flat_schedule = FeeScheduleState(flat=FA(2))
    assert flat_schedule.fee(PaymentAmount(10), channel_balance=Balance(0)) == FA(2)

    prop_schedule = FeeScheduleState(proportional=int(0.01e6))
    assert prop_schedule.fee(PaymentAmount(40), channel_balance=Balance(0)) == FA(0)
    assert prop_schedule.fee(PaymentAmount(60), channel_balance=Balance(0)) == FA(1)
    assert prop_schedule.fee(PaymentAmount(1000), channel_balance=Balance(0)) == FA(10)

    combined_schedule = FeeScheduleState(flat=FA(2), proportional=int(0.01e6))
    assert combined_schedule.fee(PaymentAmount(60), channel_balance=Balance(0)) == FA(3)


def test_imbalance_penalty():
    v_schedule = FeeScheduleState(
        imbalance_penalty=[(TA(0), FA(10)), (TA(50), FA(0)), (TA(100), FA(10))]
    )
    assert v_schedule.fee(channel_balance=Balance(100 - 0), amount=PaymentAmount(50)) == FA(-10)
    assert v_schedule.fee(channel_balance=Balance(100 - 50), amount=PaymentAmount(50)) == FA(10)
    assert v_schedule.fee(channel_balance=Balance(100 - 0), amount=PaymentAmount(10)) == FA(-2)
    assert v_schedule.fee(channel_balance=Balance(100 - 10), amount=PaymentAmount(10)) == FA(-2)
    assert v_schedule.fee(channel_balance=Balance(100 - 0), amount=PaymentAmount(20)) == FA(-4)
    assert v_schedule.fee(channel_balance=Balance(100 - 40), amount=PaymentAmount(20)) == FA(0)


def test_linspace():
    assert linspace(TA(0), TA(4), 5) == [0, 1, 2, 3, 4]
    assert linspace(TA(0), TA(4), 4) == [0, 1, 3, 4]
    assert linspace(TA(0), TA(4), 3) == [0, 2, 4]
    assert linspace(TA(0), TA(4), 2) == [0, 4]
    assert linspace(TA(0), TA(0), 3) == [0, 0, 0]

    with pytest.raises(AssertionError):
        assert linspace(TA(0), TA(4), 1)

    with pytest.raises(AssertionError):
        assert linspace(TA(4), TA(0), 2)


def test_rebalancing_fee_calculation():
    max_imbalance_fee = FA(10 ** 18)
    sample = calculate_imbalance_fees(TA(200), max_imbalance_fee)
    assert sample is not None
    assert len(sample) == NUM_DISCRETISATION_POINTS
    assert max(x for x, _ in sample) == 200
    assert max(y for _, y in sample) == 10 ** 18

    sample = calculate_imbalance_fees(TA(10), max_imbalance_fee)
    assert sample is not None
    assert len(sample) == 11
    assert max(x for x, _ in sample) == 10
    assert max(y for _, y in sample) == 10 ** 18

    sample = calculate_imbalance_fees(TA(1), max_imbalance_fee)
    assert sample is not None
    assert len(sample) == 2
    assert max(x for x, _ in sample) == 1
    assert max(y for _, y in sample) == 10 ** 18

    assert calculate_imbalance_fees(TA(0), max_imbalance_fee) is None
    assert calculate_imbalance_fees(TA(10), max_imbalance_fee=FA(0)) is None
