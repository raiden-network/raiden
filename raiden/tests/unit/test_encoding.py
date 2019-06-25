import pytest

from raiden.encoding.encoders import integer
from raiden.encoding.format import Field, make_field, namedbuffer


def test_integer_encoder():
    encoder = integer(minimum=10, maximum=100)
    for value in (10, 11, 50, 100):
        encoder.validate(value)
        assert encoder.decode(encoder.encode(value, 8)) == value
    for value in (9, 101, 1000):
        with pytest.raises(ValueError):
            encoder.validate(value)


def test_make_field_invalid_input():
    with pytest.raises(ValueError):
        make_field(name="name", size_bytes=-5, format_string="{}")


def test_named_buffer_invalid_input():
    valid_field = make_field("valid", 4, "{}")
    invalid_field1 = Field("invalid", -5, "{}", None)
    invalid_field2 = Field("", 4, "{}", None)
    field_named_data = make_field("data", 4, "{}")
    with pytest.raises(ValueError):
        namedbuffer("", [valid_field])
    with pytest.raises(ValueError):
        namedbuffer("has_a_name_but_no_fields", [])
    with pytest.raises(ValueError):
        namedbuffer("has_invalid_field", [valid_field, invalid_field1])
    with pytest.raises(ValueError):
        namedbuffer("has_nameless_field", [valid_field, invalid_field2])
    with pytest.raises(ValueError):
        namedbuffer("field_named_data", [field_named_data, valid_field])
    with pytest.raises(ValueError):
        namedbuffer("repeated_field_name", [valid_field, valid_field])
