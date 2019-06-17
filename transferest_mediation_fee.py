import pytest

from raiden.transfer.mediation_fee import FeeScheduleState, Interpolate
from raiden.utils.typing import FeeAmount as FA, TokenAmount as TA


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
    assert flat_schedule.fee(TA(10), capacity=TA(0)) == FA(2)

    prop_schedule = FeeScheduleState(proportional=0.01)
    assert prop_schedule.fee(TA(40), capacity=TA(0)) == FA(0)
    assert prop_schedule.fee(TA(60), capacity=TA(0)) == FA(1)
    assert prop_schedule.fee(TA(1000), capacity=TA(0)) == FA(10)

    combined_schedule = FeeScheduleState(flat=FA(2), proportional=0.01)
    assert combined_schedule.fee(TA(60), capacity=TA(0)) == FA(3)


def test_imbalance_penalty():
    v_schedule = FeeScheduleState(
        imbalance_penalty=[(TA(0), FA(10)), (TA(50), FA(0)), (TA(100), FA(10))]
    )
    assert v_schedule.fee(capacity=TA(100 - 0), amount=TA(50)) == FA(-10)
    assert v_schedule.fee(capacity=TA(100 - 50), amount=TA(50)) == FA(10)
    assert v_schedule.fee(capacity=TA(100 - 0), amount=TA(10)) == FA(-2)
    assert v_schedule.fee(capacity=TA(100 - 10), amount=TA(10)) == FA(-2)
    assert v_schedule.fee(capacity=TA(100 - 0), amount=TA(20)) == FA(-4)
    assert v_schedule.fee(capacity=TA(100 - 40), amount=TA(20)) == FA(0)
