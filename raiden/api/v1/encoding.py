# -*- coding: utf-8 -*-
import binascii
from binascii import unhexlify

from marshmallow import (
    fields,
    post_dump,
    post_load,
    pre_load,
    Schema,
    SchemaOpts,
)
from webargs import validate
from werkzeug.routing import (
    BaseConverter,
    ValidationError,
)

from raiden.api.objects import (
    Address,
    AddressList,
    Channel,
    ChannelList,
    PartnersPerToken,
    PartnersPerTokenList
)
from raiden.settings import (
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_JOINABLE_FUNDS_TARGET,
    DEFAULT_INITIAL_CHANNEL_TARGET,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.utils import (
    address_encoder,
    data_encoder,
    data_decoder,
)


class HexAddressConverter(BaseConverter):
    def to_python(self, value):
        if value[:2] != '0x':
            raise ValidationError()

        try:
            value = unhexlify(value[2:])
        except TypeError:
            raise ValidationError()

        if len(value) != 20:
            raise ValidationError()

        return value

    def to_url(self, value):
        return address_encoder(value)


class AddressField(fields.Field):
    default_error_messages = {
        'missing_prefix': 'Not a valid hex encoded address, must be 0x prefixed.',
        'invalid_data': 'Not a valid hex encoded address, contains invalid characters.',
        'invalid_size': 'Not a valid hex encoded address, decoded address is not 20 bytes long.',
    }

    def _serialize(self, value, attr, obj):
        return address_encoder(value)

    def _deserialize(self, value, attr, data):
        if value[:2] != '0x':
            self.fail('missing_prefix')

        try:
            value = unhexlify(value[2:])
        except binascii.Error:
            self.fail('invalid_data')

        if len(value) != 20:
            self.fail('invalid_size')

        return value


class DataField(fields.Field):
    def _serialize(self, value, attr, obj):
        return data_encoder(value)

    def _deserialize(self, value, attr, data):
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
        # this will depend on the Schema used, which has its object class in
        # the class Meta attributes
        decoding_class = self.opts.decoding_class  # pylint: disable=no-member
        return decoding_class(**data)


class BaseListSchema(Schema):
    OPTIONS_CLASS = BaseOpts

    @pre_load
    def wrap_data_envelope(self, data):  # pylint: disable=no-self-use
        # because the EventListSchema and ChannelListSchema objects need to
        # have some field ('data'), the data has to be enveloped in the
        # internal representation to comply with the Schema
        data = dict(data=data)
        return data

    @post_dump
    def unwrap_data_envelope(self, data):  # pylint: disable=no-self-use
        return data['data']

    @post_load
    def make_object(self, data):
        decoding_class = self.opts.decoding_class  # pylint: disable=no-member
        list_ = data['data']
        return decoding_class(list_)


class EventRequestSchema(BaseSchema):
    from_block = fields.Integer(missing=None)
    to_block = fields.Integer(missing=None)

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs
        decoding_class = dict


class AddressSchema(BaseSchema):
    address = AddressField()

    class Meta:
        strict = True
        decoding_class = Address


class AddressListSchema(BaseListSchema):
    data = fields.List(AddressField())

    class Meta:
        strict = True
        decoding_class = AddressList


class PartnersPerTokenSchema(BaseSchema):
    partner_address = AddressField()
    channel = fields.String()

    class Meta:
        strict = True
        decoding_class = PartnersPerToken


class PartnersPerTokenListSchema(BaseListSchema):
    data = fields.Nested(PartnersPerTokenSchema, many=True)

    class Meta:
        strict = True
        decoding_class = PartnersPerTokenList


class ChannelSchema(BaseSchema):
    channel_address = AddressField()
    token_address = AddressField()
    partner_address = AddressField()
    settle_timeout = fields.Integer()
    reveal_timeout = fields.Integer()
    balance = fields.Integer()
    state = fields.String(validate=validate.OneOf([
        CHANNEL_STATE_CLOSED,
        CHANNEL_STATE_OPENED,
        CHANNEL_STATE_SETTLED,
    ]))

    class Meta:
        strict = True
        decoding_class = Channel


class ChannelRequestSchema(BaseSchema):
    channel_address = AddressField(missing=None)
    token_address = AddressField(required=True)
    partner_address = AddressField(required=True)
    settle_timeout = fields.Integer(missing=DEFAULT_SETTLE_TIMEOUT)
    reveal_timeout = fields.Integer(missing=DEFAULT_REVEAL_TIMEOUT)
    balance = fields.Integer(default=None, missing=None)
    state = fields.String(
        default=None,
        missing=None,
        validate=validate.OneOf([
            CHANNEL_STATE_CLOSED,
            CHANNEL_STATE_OPENED,
            CHANNEL_STATE_SETTLED,
        ])
    )

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
        decoding_class = dict


class ChannelListSchema(BaseListSchema):
    data = fields.Nested(ChannelSchema, many=True)

    class Meta:
        strict = True
        decoding_class = ChannelList


class TokenSwapsSchema(BaseSchema):
    # The identifier is actually returned properly without this, but if this
    # is included we get a "missing" error.
    # XXX: Lef does not like this. Find out why flask behaves like that.
    # identifier = fields.Integer(required=True)

    role = fields.String(
        required=True,
        validate=validate.OneOf(['maker', 'taker']),
    )
    sending_amount = fields.Integer(required=True)
    sending_token = AddressField(required=True)
    receiving_amount = fields.Integer(required=True)
    receiving_token = AddressField(required=True)

    class Meta:
        strict = True
        decoding_class = dict


class TransferSchema(BaseSchema):
    initiator_address = AddressField(missing=None)
    target_address = AddressField(missing=None)
    token_address = AddressField(missing=None)
    amount = fields.Integer(required=True)
    identifier = fields.Integer(missing=None)

    class Meta:
        strict = True
        decoding_class = dict


class ConnectionsConnectSchema(BaseSchema):
    funds = fields.Integer(required=True)
    initial_channel_target = fields.Integer(
        missing=DEFAULT_INITIAL_CHANNEL_TARGET,
    )
    joinable_funds_target = fields.Decimal(missing=DEFAULT_JOINABLE_FUNDS_TARGET)

    class Meta:
        strict = True
        decoding_class = dict


class ConnectionsLeaveSchema(BaseSchema):
    only_receiving_channels = fields.Boolean(
        required=False,
        default=True,
        missing=True,
    )

    class Meta:
        strict = True
        decoding_class = dict
