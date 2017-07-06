# -*- coding: utf-8 -*-
from raiden.utils import safe_equal_attributes


class Slotted(object):
    __slots__ = (
        'a',
        'b',
    )

    def __eq__(self, other):
        if isinstance(other, Slotted):
            return (
                safe_equal_attributes('a', self, other) and
                safe_equal_attributes('b', self, other)
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


def test_safe_equal_attributes():
    slotted = Slotted()
    slotted.a = 1
    slotted.b = 2
    equal = Slotted()
    equal.a = 1
    equal.b = 2
    notequal = Slotted()
    notequal.a = 1
    notequal.b = 3
    none = Slotted()
    none.a = 1
    none.b = None
    incomplete = Slotted()
    incomplete.a = 1
    equal_incomplete = Slotted()
    equal_incomplete.a = 1

    assert slotted == equal
    assert slotted != notequal
    assert slotted != incomplete
    assert slotted != none
    assert incomplete == equal_incomplete
