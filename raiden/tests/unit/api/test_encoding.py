import datetime

import pytest
from marshmallow.fields import DateTime
from werkzeug.routing import Map

from raiden.api.v1.encoding import AddressField, BaseSchema, HexAddressConverter
from raiden.utils.typing import Address


class SchemaTest(BaseSchema):
    timestamp = DateTime()

    class Meta:
        fields = ("timestamp",)
        strict = True


def test_timestamp_field():
    now = datetime.datetime.now()
    assert (
        SchemaTest().dump({}) == {}
    ), "timestamp fields should only be serialized when the date is provided"
    assert SchemaTest().dump({"timestamp": now}) == {
        "timestamp": now.isoformat()
    }, "timestamp fields should be formatted as ISO8601"


def test_hex_converter():
    converter = HexAddressConverter(map=Map())

    # invalid hex data
    with pytest.raises(Exception):
        converter.to_python("-")

    # invalid address, too short
    with pytest.raises(Exception):
        converter.to_python("0x1234")

    # missing prefix 0x
    with pytest.raises(Exception):
        converter.to_python("414d72a6f6e28f4950117696081450d63d56c354")

    address = Address(b"AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T")
    assert converter.to_python("0x414D72a6f6E28F4950117696081450d63D56C354") == address


def test_address_field():
    # pylint: disable=protected-access
    field = AddressField()
    attr = "test"
    data = object()

    # invalid hex data
    with pytest.raises(Exception):
        field._deserialize("-", attr, data)

    # invalid address, too short
    with pytest.raises(Exception):
        field._deserialize("0x1234", attr, data)

    # missing prefix 0x
    with pytest.raises(Exception):
        field._deserialize("414d72a6f6e28f4950117696081450d63d56c354", attr, data)

    address = b"AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T"
    assert field._deserialize("0x414D72a6f6E28F4950117696081450d63D56C354", attr, data) == address
