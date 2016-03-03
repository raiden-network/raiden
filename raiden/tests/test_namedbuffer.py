# -*- coding: utf8 -*-

from raiden.encoding.format import Field, namedbuffer
from raiden.encoding.encoders import integer

# pylint: disable=invalid-name
byte = Field('byte', 1, 'B', None)
hugeint = Field('huge', 100, '100s', integer(0, 2 ** (8 * 100)))
SingleByte = namedbuffer('SingleByte', [byte])
HugeInt = namedbuffer('HugeInt', [hugeint])


def test_byte():
    data = bytearray(1)  # zero initialized

    packed_data = SingleByte(data)
    assert packed_data.byte == b'\x00'

    packed_data.byte = b'\x01'
    assert packed_data.byte == b'\x01'


def test_decoder_int():
    data = bytearray(100)

    packed_data = HugeInt(data)
    assert packed_data.huge == 0

    packed_data.huge = 1
    assert packed_data.huge == 1


def test_decoder_long():
    data = bytearray(100)

    packed_data = HugeInt(data)
    assert packed_data.huge == 0

    packed_data.huge = 1L
    assert packed_data.huge == 1

    packed_data.huge = 2L ** 32
    assert packed_data.huge == 2 ** 32

    huge = 2 ** (8 * 100) - 1
    packed_data.huge = huge
    assert packed_data.huge == huge
