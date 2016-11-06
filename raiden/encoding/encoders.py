# -*- coding: utf-8 -*-
import codecs
import sys

from rlp.utils import int_to_big_endian

PY2 = sys.version_info.major == 2


__all__ = ('integer',)


class integer(object):  # pylint: disable=invalid-name
    ''' Defines the value as an integer and it's valid value range. '''

    def __init__(self, minimum, maximum):
        self.minimum = minimum
        self.maximum = maximum

    def validate(self, value):
        ''' Validates the integer is in the value range. '''
        if not isinstance(value, (int, long)):
            raise ValueError('value is not an integer')

        if self.minimum > value or self.maximum < value:
            msg = (
                '{} is outside the valide range [{},{}]'
            ).format(value, self.minimum, self.maximum)
            raise ValueError(msg)

    if PY2:
        @staticmethod
        def encode(value, length):  # pylint: disable=unused-argument
            return int_to_big_endian(value)

        @staticmethod
        def decode(value):
            return int(codecs.encode(value, 'hex'), 16)
    else:
        @staticmethod
        def encode(value, length):
            return value.to_bytes(length, byteorder='big')

        @staticmethod
        def decode(value):
            return int.from_bytes(value, byteorder='big')  # pylint: disable=no-member


class optional_bytes(object):  # pylint: disable=invalid-name
    ''' This encoder assumes that a byte string full of NULL values is equal to
    the value being absent. If any of the bytes is not \x00 then all full array
    is considered part of the value.

    This is useful for values of fixed length that are optional.
    '''

    def validate(self, value):
        pass

    @staticmethod
    def encode(value, length):  # pylint: disable=unused-argument
        return value

    @staticmethod
    def decode(value):
        if value.lstrip('\x00') == b'':
            return b''
        return value
