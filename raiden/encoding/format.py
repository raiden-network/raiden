from collections import namedtuple, Counter

__all__ = ('Field', 'namedbuffer', 'buffer_for')


Field = namedtuple(
    'Field',
    ('name', 'size_bytes', 'format_string', 'encoder'),
)

Pad = namedtuple(
    'Pad',
    ('size_bytes', 'format_string'),
)


def make_field(name, size_bytes, format_string, encoder=None):
    if size_bytes < 0:
        raise ValueError('negative size_bytes')

    return Field(
        name,
        size_bytes,
        format_string,
        encoder,
    )


def pad(bytes):
    return Pad(
        bytes,
        '{}x'.format(bytes),
    )


def buffer_for(klass):
    """ Returns a new buffer of the appropriate size for klass. """
    return bytearray(klass.size)


def compute_slices(fields_spec):
    name_to_slice = dict()
    start = 0

    for field in fields_spec:
        end = start + field.size_bytes

        if not isinstance(field, Pad):  # do not create slices for paddings
            name_to_slice[field.name] = slice(start, end)

        start = end

    return name_to_slice


def namedbuffer(buffer_name, fields_spec):  # noqa (ignore ciclomatic complexity)
    """ Class factory, returns a class to wrap a buffer instance and expose the
    data as fields.

    The field spec specifies how many bytes should be used for a field and what
    is the encoding / decoding function.
    """
    # pylint: disable=protected-access,unused-argument

    if not len(buffer_name):
        raise ValueError('buffer_name is empty')

    if not len(fields_spec):
        raise ValueError('fields_spec is empty')

    fields = [
        field
        for field in fields_spec
        if not isinstance(field, Pad)
    ]

    if any(field.size_bytes < 0 for field in fields):
        raise ValueError('negative size_bytes')

    if any(len(field.name) < 0 for field in fields):
        raise ValueError('field missing name')

    names_fields = {
        field.name: field
        for field in fields
    }

    if 'data' in names_fields:
        raise ValueError('data field shadowing underlying buffer')

    if any(count > 1 for count in Counter(field.name for field in fields).values()):
        raise ValueError('repeated field name')

    # big endian format
    fields_format = '>' + ''.join(field.format_string for field in fields_spec)
    size = sum(field.size_bytes for field in fields_spec)
    names_slices = compute_slices(fields_spec)
    sorted_names = sorted(names_fields.keys())

    @staticmethod
    def get_bytes_from(buffer_, name):
        slice_ = names_slices[name]
        return buffer_[slice_]

    def __init__(self, data):
        if len(data) != size:
            raise ValueError('data buffer has the wrong size, expected {}'.format(size))

        object.__setattr__(self, 'data', data)

    # Intentionally exposing only the attributes from the spec, since the idea
    # is for the instance to expose the underlying buffer as attributes
    def __getattribute__(self, name):
        if name in names_slices:
            slice_ = names_slices[name]
            field = names_fields[name]

            data = object.__getattribute__(self, 'data')
            value = data[slice_]

            if field.encoder:
                value = field.encoder.decode(value)

            return value

        if name == 'data':
            return object.__getattribute__(self, 'data')

        raise AttributeError

    def __setattr__(self, name, value):
        if name in names_slices:
            slice_ = names_slices[name]
            field = names_fields[name]

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

            data = object.__getattribute__(self, 'data')
            if isinstance(value, str):
                value = value.encode()
            data[slice_] = value
        else:
            super(self.__class__, self).__setattr__(name, value)

    def __repr__(self):
        return '<{} [...]>'.format(buffer_name)

    def __len__(self):
        return size

    def __dir__(self):
        return sorted_names

    attributes = {
        '__init__': __init__,
        '__slots__': ('data',),
        '__getattribute__': __getattribute__,
        '__setattr__': __setattr__,
        '__repr__': __repr__,
        '__len__': __len__,
        '__dir__': __dir__,

        # These are class attributes hidden from instance, i.e. must be
        # accessed through the class instance.
        'fields_spec': fields_spec,
        'format': fields_format,
        'size': size,
        'get_bytes_from': get_bytes_from,
    }

    return type(buffer_name, (), attributes)
