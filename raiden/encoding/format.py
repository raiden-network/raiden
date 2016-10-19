# -*- coding: utf-8 -*-
from collections import namedtuple, Counter

try:  # py3k
    from functools import lru_cache
except ImportError:
    from repoze.lru import lru_cache


__all__ = ('Field', 'BYTE', 'namedbuffer', 'buffer_for',)


Field = namedtuple(
    'Field',
    ('name', 'size_bytes', 'format_string', 'encoder'),
)

BYTE = 2 ** 8


@lru_cache(10)  # caching so the factory returns the same object
def pad(size_bytes):
    name = 'pad_{}'.format(size_bytes)
    format_string = '{}x'.format(size_bytes)
    return Field(name, size_bytes, format_string, None)


def make_field(name, size_bytes, format_string, encoder=None):
    if size_bytes < 0:
        raise ValueError('negative size_bytes')

    return Field(
        name,
        size_bytes,
        format_string,
        encoder,
    )


def buffer_for(klass):
    ''' Returns a new buffer of the appropriate size for klass. '''
    return bytearray(klass.size)


def namedbuffer(buffer_name, fields_spec):  # noqa (ignore ciclomatic complexity)
    ''' Wraps a buffer instance using the field spec.

    The field spec specifies how many bytes should be used for a field and what
    is the encoding / decoding function.
    '''

    if not len(buffer_name):
        raise ValueError('buffer_name is empty')

    if not len(fields_spec):
        raise ValueError('fields_spec is empty')

    if any(field.size_bytes < 0 for field in fields_spec):
        raise ValueError('negative size_bytes')

    if any(len(field.name) < 0 for field in fields_spec):
        raise ValueError('field missing name')

    if any(count > 1 for count in Counter(field.name for field in fields_spec).values()):
        raise ValueError('repeated field name')

    size = sum(field.size_bytes for field in fields_spec)

    fields = list()
    name_slice = dict()
    name_field = dict()

    start = 0
    for field in fields_spec:
        end = start + field.size_bytes

        # don't create a slices and attributes for paddings
        if not field.name.startswith('pad_'):
            name_slice[field.name] = slice(start, end)
            name_field[field.name] = field
            fields.append(field.name)

        start = end

    # big endian format
    fields_format = '>' + ''.join(field.format_string for field in fields_spec)

    def __init__(self, data):
        if len(data) < size:
            raise ValueError('data buffer is too small')

        # XXX: validate or initialize the buffer?
        self.data = data

    def __getattr__(self, name):
        if name in name_slice:
            slice_ = name_slice[name]
            field = name_field[name]

            value = self.data[slice_]

            if field.encoder:
                value = field.encoder.decode(value)

            return value

        raise AttributeError

    def __setattr__(self, name, value):
        if name in name_slice:
            slice_ = name_slice[name]
            field = name_field[name]

            if field.encoder:
                field.encoder.validate(value)
                value = field.encoder.encode(value, field.size_bytes)

            length = len(value)
            if length > field.size_bytes:
                msg = 'value with length {length} for {attr} is too big'.format(
                    length=length,
                    attr=name,
                )
                raise ValueError(msg)
            elif length < field.size_bytes:
                pad_size = field.size_bytes - length
                pad_value = b'\x00' * pad_size
                value = pad_value + value

            self.data[slice_] = value
        else:
            super(self.__class__, self).__setattr__(name, value)

    attributes = {
        '__init__': __init__,
        '__slots__': ('data',),
        '__getattr__': __getattr__,
        '__setattr__': __setattr__,

        'fields': fields,
        'fields_spec': fields_spec,
        'name': buffer_name,
        'format': fields_format,
        'size': size,
    }

    return type(buffer_name, (), attributes)
