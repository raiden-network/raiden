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
