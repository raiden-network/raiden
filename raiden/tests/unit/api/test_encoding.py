import datetime

from raiden.api.v1.encoding import BaseSchema, TimeStampField


class TestSchema(BaseSchema):
    timestamp = TimeStampField()

    class Meta:
        fields = ("timestamp",)
        strict = True
        decoding_class = dict


def test_timestamp_field():
    now = datetime.datetime.now()
    assert (
        TestSchema().dump({}) == {}
    ), "timestamp fields should only be serialized when the date is provided"
    assert TestSchema().dump({"timestamp": now}) == {
        "timestamp": now.isoformat()
    }, "timestamp fields should be formatted as ISO8601"
