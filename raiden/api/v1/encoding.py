from werkzeug.routing import BaseConverter
from marshmallow import Schema, SchemaOpts, post_load, post_dump, pre_load
from marshmallow_polyfield import PolyField
from webargs import validate
from marshmallow import fields

from pyethapp.jsonrpc import address_encoder, address_decoder, data_encoder, data_decoder

from raiden.utils import camel_to_snake_case, snake_to_camel_case
from raiden.api.objects import (
    Channel,
    ChannelList,
    EventsList,
    TokenAdded,
    ChannelClosed,
    ChannelSettled,
    ChannelNew,
    ChannelNewBalance,
    ChannelSecretRevealed,
    TransferReceived
)
from raiden.settings import DEFAULT_SETTLE_TIMEOUT


def serialize_schema_selector(list_element, list_obj):
    schema = None
    try:
        schema = event_class_name_to_schema[list_element.__class__.__name__]()

    except Exception as e:
        raise e
    return schema


def deserialize_schema_selector(element_dict, base_dict):
    event_type = element_dict['event_type']
    event_class_name = snake_to_camel_case(event_type)
    schema = None
    try:
        schema = event_class_name_to_schema[event_class_name]()

    except Exception as e:
        raise e
    return schema


# type converter for the flask route
class HexAddressConverter(BaseConverter):

    def to_python(self, value):
        value = address_decoder(value)
        return value

    def to_url(self, value):
        value = address_encoder(value)

        return BaseConverter.to_url(value)


class AddressField(fields.Field):

    def _serialize(self, value, attr, obj):
        return address_encoder(value)

    def _deserialize(self, value, attr, obj):
        return address_decoder(value)


class DataField(fields.Field):

    def _serialize(self, value, attr, obj):
        return data_encoder(value)

    def _deserialize(self, value, attr, obj):
        return data_decoder(value)


class BaseOpts(SchemaOpts):
    """
    This allows for having the Object the Schema encodes to inside of the class Meta
    """
    def __init__(self, meta):
        SchemaOpts.__init__(self, meta)
        self.decoding_class = getattr(meta, 'decoding_class', None)


class BaseSchema(Schema):
    OPTIONS_CLASS = BaseOpts

    @post_load
    def make_object(self, data):
        # this will depend on the Schema used, which has its object class in the class Meta attributes
        decoding_class = self.opts.decoding_class
        return decoding_class(**data)


class BaseListSchema(Schema):
    OPTIONS_CLASS = BaseOpts

    @pre_load
    def wrap_data_envelope(self, data):
        # because the EventListSchema and ChannelListSchema ojects need to have some field ('data'),
        # the data has to be enveloped in the internal representation to comply with the Schema
        data = dict(data=data)
        return data

    @post_dump
    def unwrap_data_envelope(self, data):
        return data['data']

    @post_load
    def make_object(self, data):
        decoding_class = self.opts.decoding_class
        list_ = data['data']
        return decoding_class(list_)


class EventSchema(BaseSchema):

    @pre_load
    def unwrap_envelope(self, data):
        # exclude the event_type from the dict, since this is irrelevant internally
        data = {key:data[key] for key in data if key !='event_type'}
        return data

    @post_dump
    def wrap_with_envelope(self, data):
        event_type = camel_to_snake_case(self.opts.decoding_class.__name__)
        data['event_type'] = event_type
        return data


class EventsListSchema(BaseListSchema):
    data = PolyField(serialization_schema_selector=serialize_schema_selector, deserialization_schema_selector=deserialize_schema_selector, many=True)

    class Meta:
        strict = True
        decoding_class = EventsList


class ChannelSchema(BaseSchema):
    channel_address = AddressField()
    token_address = AddressField()
    partner_address = AddressField()
    settle_timeout = fields.Integer()
    reveal_timeout = fields.Integer()
    balance = fields.Integer()
    status = fields.String(validate=validate.OneOf(['closed', 'open', 'settled']))

    class Meta:
        strict= True
        decoding_class = Channel


class ChannelRequestSchema(BaseSchema):
    channel_address = AddressField(missing=None)
    token_address = AddressField(required=True)
    partner_address = AddressField(required=True)
    settle_timeout = fields.Integer(missing=DEFAULT_SETTLE_TIMEOUT)
    balance = fields.Integer(default=None, missing=None)
    status = fields.String(default=None, missing=None, validate=validate.OneOf(['closed', 'open', 'settled']))

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
        decoding_class = dict


class ChannelListSchema(BaseListSchema):
    data = fields.Nested(ChannelSchema, many=True)

    class Meta:
        strict= True
        decoding_class = ChannelList


class ChannelNewSchema(EventSchema):
    netting_channel_address = AddressField()
    participant1 = AddressField()
    participant2 = AddressField()
    settle_timeout = fields.Integer()

    class Meta:
        strict = True
        decoding_class = ChannelNew


class TokenAddedSchema(EventSchema):
    registry_address = AddressField()
    token_address = AddressField()
    channel_manager_address = AddressField()

    class Meta:
        strict = True
        decoding_class = TokenAdded


class ChannelNewBalanceSchema(EventSchema):
    netting_channel_address = AddressField()
    token_address = AddressField()
    participant_address = AddressField()
    new_balance = fields.Integer()
    block_number = fields.Integer()

    class Meta:
        strict = True
        decoding_class = ChannelNewBalance


class ChannelClosedSchema(EventSchema):
    netting_channel_address = AddressField()
    closing_address = AddressField()
    block_number = fields.Integer()

    class Meta:
        strict = True
        decoding_class = ChannelClosed


class ChannelSettledSchema(EventSchema):
    netting_channel_address = AddressField()
    block_number = fields.Integer()

    class Meta:
        strict = True
        decoding_class = ChannelSettled


class ChannelSecretRevealedSchema(EventSchema):
    netting_channel_address = AddressField()
    secret = DataField()

    class Meta:
        strict = True
        decoding_class = ChannelSecretRevealed


class TransferReceivedSchema(EventSchema):
    token_address = AddressField()
    initiator_address = AddressField()
    recipient_address = AddressField()
    transferred_amount = AddressField()
    identifier = fields.Integer()
    hashlock = DataField()

    class Meta:
        strict = True
        decoding_class = TransferReceived


event_class_name_to_schema = dict(
    TokenAdded=TokenAddedSchema,
    ChannelNew=ChannelNewSchema,
    ChannelClosed=ChannelClosedSchema,
    ChannelSettled=ChannelSettledSchema,
    ChannelSecretRevealed=ChannelSecretRevealedSchema,
    ChannelNewBalance=ChannelNewBalanceSchema,
    TransferReceived=TransferReceivedSchema,
)
