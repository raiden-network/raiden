import pytest

from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState, Interpolate
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
    assert flat_schedule.fee(PaymentAmount(10), capacity=Balance(0)) == FA(2)

    prop_schedule = FeeScheduleState(proportional=int(0.01e6))
    assert prop_schedule.fee(PaymentAmount(40), capacity=Balance(0)) == FA(0)
    assert prop_schedule.fee(PaymentAmount(60), capacity=Balance(0)) == FA(1)
    assert prop_schedule.fee(PaymentAmount(1000), capacity=Balance(0)) == FA(10)

    combined_schedule = FeeScheduleState(flat=FA(2), proportional=int(0.01e6))
    assert combined_schedule.fee(PaymentAmount(60), capacity=Balance(0)) == FA(3)


def test_imbalance_penalty():
    v_schedule = FeeScheduleState(
        imbalance_penalty=[(TA(0), FA(10)), (TA(50), FA(0)), (TA(100), FA(10))]
    )
    assert v_schedule.fee(capacity=Balance(100 - 0), amount=PaymentAmount(50)) == FA(-10)
    assert v_schedule.fee(capacity=Balance(100 - 50), amount=PaymentAmount(50)) == FA(10)
    assert v_schedule.fee(capacity=Balance(100 - 0), amount=PaymentAmount(10)) == FA(-2)
    assert v_schedule.fee(capacity=Balance(100 - 10), amount=PaymentAmount(10)) == FA(-2)
    assert v_schedule.fee(capacity=Balance(100 - 0), amount=PaymentAmount(20)) == FA(-4)
    assert v_schedule.fee(capacity=Balance(100 - 40), amount=PaymentAmount(20)) == FA(0)
