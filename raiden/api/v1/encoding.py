from binascii import Error as DecodeError

from marshmallow import (
    fields,
    post_dump,
    post_load,
    pre_load,
    Schema,
    SchemaOpts,
)
from webargs import validate
from werkzeug.exceptions import NotFound
from werkzeug.routing import (
    BaseConverter,
    ValidationError,
)
from eth_utils import (
    is_checksum_address,
    to_checksum_address,
    to_canonical_address,
    decode_hex,
    encode_hex,
)

from raiden.api.objects import (
    Address,
    AddressList,
    PartnersPerToken,
    PartnersPerTokenList,
)
from raiden.settings import (
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_JOINABLE_FUNDS_TARGET,
    DEFAULT_INITIAL_CHANNEL_TARGET,
)
from raiden.transfer import channel
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
)
from raiden.utils import data_encoder, data_decoder


class InvalidEndpoint(NotFound):
    """
    Exception to be raised instead of ValidationError if we want to skip the remaining
    endpoint matching rules and give a reason why the endpoint is invalid.
    """


class HexAddressConverter(BaseConverter):
    def to_python(self, value):
        if value[:2] != '0x':
            raise InvalidEndpoint('Not a valid hex address, 0x prefix missing.')

        if not is_checksum_address(value):
            raise InvalidEndpoint('Not a valid EIP55 encoded address.')

        try:
            value = to_canonical_address(value)
        except ValueError:
            raise InvalidEndpoint('Could not decode hex.')

        return value

    def to_url(self, value):
        return to_checksum_address(value)


# do this to make testing easier
def decode_keccak(value: str) -> bytes:
    if value[:2] != '0x':
        raise ValidationError("Channel Id is missing the '0x' prefix")

    try:
        value = decode_hex(value)
    except DecodeError:
        raise ValidationError('Channel Id is not a valid hexadecimal value')

    if len(value) != 32:
        raise ValidationError('Channel Id is not valid')

    return value


class KeccakConverter(BaseConverter):
    def to_python(self, value: str):
        return decode_keccak(value)

    def to_url(self, value):
        return encode_hex(value)


class AddressField(fields.Field):
    default_error_messages = {
        'missing_prefix': 'Not a valid hex encoded address, must be 0x prefixed.',
        'invalid_checksum': 'Not a valid EIP55 encoded address',
        'invalid_data': 'Not a valid hex encoded address, contains invalid characters.',
        'invalid_size': 'Not a valid hex encoded address, decoded address is not 20 bytes long.',
    }

    def _serialize(self, value, attr, obj):
        return to_checksum_address(value)

    def _deserialize(self, value, attr, data):
        if value[:2] != '0x':
            self.fail('missing_prefix')

        if not is_checksum_address(value):
            self.fail('invalid_checksum')

        try:
            value = to_canonical_address(value)
        except ValueError:
            self.fail('invalid_data')

        if len(value) != 20:
            self.fail('invalid_size')

        return value


class KeccakField(fields.Field):
    default_error_messages = {
        'missing_prefix': 'Not a valid hex encoded, must be 0x prefixed.',
        'invalid_data': 'Not a valid hex encoded hash, contains invalid characters.',
        'invalid_size': 'Not a valid hex encoded hash, decoded has is not 20 bytes long.',
    }

    def _serialize(self, value, attr, obj):
        return encode_hex(value)

    def _deserialize(self, value, attr, data):
        if value[:2] != '0x':
            self.fail('missing_prefix')

        try:
            value = decode_hex(value)
        except DecodeError:
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


class ChannelStateSchema(BaseSchema):
    channel_identifier = KeccakField(attribute='identifier')
    token_network_identifier = AddressField()
    token_address = AddressField()
    partner_address = fields.Method('get_partner_address')
    settle_timeout = fields.Integer()
    reveal_timeout = fields.Integer()
    balance = fields.Method('get_balance')
    state = fields.Method('get_state')

    def get_partner_address(self, channel_state):  # pylint: disable=no-self-use
        return to_checksum_address(channel_state.partner_state.address)

    def get_balance(self, channel_state):  # pylint: disable=no-self-use
        return channel.get_balance(
            channel_state.our_state,
            channel_state.partner_state,
        )

    def get_state(self, channel_state):
        return channel.get_status(channel_state)

    class Meta:
        strict = True
        decoding_class = dict


class ChannelPutSchema(BaseSchema):
    token_address = AddressField(required=True)
    partner_address = AddressField(required=True)
    settle_timeout = fields.Integer(missing=DEFAULT_SETTLE_TIMEOUT)
    reveal_timeout = fields.Integer(missing=DEFAULT_REVEAL_TIMEOUT)
    balance = fields.Integer(default=None, missing=None)

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
        decoding_class = dict


class ChannelPatchSchema(BaseSchema):
    total_deposit = fields.Integer(default=None, missing=None)
    state = fields.String(
        default=None,
        missing=None,
        validate=validate.OneOf([
            CHANNEL_STATE_CLOSED,
            CHANNEL_STATE_OPENED,
            CHANNEL_STATE_SETTLED,
        ]),
    )

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
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
    class Meta:
        strict = True
        decoding_class = dict
