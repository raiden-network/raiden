__all__ = ('integer',)


class integer:  # pylint: disable=invalid-name
    ''' Defines the value as an integer and it's valid value range. '''

    def __init__(self, minimum: int, maximum: int):
        self.minimum = minimum
        self.maximum = maximum

    def validate(self, value: int):
        ''' Validates the integer is in the value range. '''
        if not isinstance(value, int):
            raise ValueError('value is not an integer')

        if self.minimum > value or self.maximum < value:
            msg = (
                '{} is outside the valide range [{},{}]'
            ).format(value, self.minimum, self.maximum)
            raise ValueError(msg)

    @staticmethod
    def encode(value: int, length: int):
        return value.to_bytes(length, byteorder='big')

    @staticmethod
    def decode(value: bytes):
        return int.from_bytes(value, byteorder='big')  # pylint: disable=no-member


class optional_bytes:  # pylint: disable=invalid-name
    ''' This encoder assumes that a byte string full of NULL values is equal to
    the value being absent. If any of the bytes is not \x00 then all full array
    is considered part of the value.

    This is useful for values of fixed length that are optional.
    '''

    def validate(self, value):
        pass

    @staticmethod
    def encode(value: bytes, length: int):  # pylint: disable=unused-argument
        return value

    @staticmethod
    def decode(value: bytes):
        if value.lstrip(b'\x00') == b'':
            return b''
        return value
