import binascii
import datetime
from typing import Any, Optional

from eth_utils import (
    is_0x_prefixed,
    is_checksum_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_hex,
)
from marshmallow import Schema, SchemaOpts, fields, post_dump, post_load, pre_load
from webargs import validate
from werkzeug.exceptions import NotFound
from werkzeug.routing import BaseConverter

from raiden.api.objects import Address, AddressList, PartnersPerToken, PartnersPerTokenList
from raiden.constants import (
    NULL_ADDRESS_BYTES,
    NULL_ADDRESS_HEX,
    SECRET_LENGTH,
    SECRETHASH_LENGTH,
    UINT256_MAX,
)
from raiden.settings import DEFAULT_INITIAL_CHANNEL_TARGET, DEFAULT_JOINABLE_FUNDS_TARGET
from raiden.transfer import channel
from raiden.transfer.state import ChannelState, NettingChannelState
from raiden.utils.typing import AddressHex


class InvalidEndpoint(NotFound):
    """
    Exception to be raised instead of ValidationError if we want to skip the remaining
    endpoint matching rules and give a reason why the endpoint is invalid.
    """


class HexAddressConverter(BaseConverter):
    @staticmethod
    def to_python(value: Any) -> Address:
        if not is_0x_prefixed(value):
            raise InvalidEndpoint("Not a valid hex address, 0x prefix missing.")

        if not is_checksum_address(value):
            raise InvalidEndpoint("Not a valid EIP55 encoded address.")

        try:
            value = to_canonical_address(value)
        except ValueError:
            raise InvalidEndpoint("Could not decode hex.")

        return value

    @staticmethod
    def to_url(value: Any) -> AddressHex:
        return to_checksum_address(value)


class AddressField(fields.Field):
    default_error_messages = {
        "missing_prefix": "Not a valid hex encoded address, must be 0x prefixed.",
        "invalid_checksum": "Not a valid EIP55 encoded address",
        "invalid_data": "Not a valid hex encoded address, contains invalid characters.",
        "invalid_size": "Not a valid hex encoded address, decoded address is not 20 bytes long.",
        "null_address": f"The {NULL_ADDRESS_HEX} address is not accepted",
    }

    @staticmethod
    def _serialize(value, attr, obj, **kwargs):  # pylint: disable=unused-argument
        return to_checksum_address(value)

    def _deserialize(self, value, attr, data, **kwargs):  # pylint: disable=unused-argument
        if not is_0x_prefixed(value):
            self.fail("missing_prefix")

        if not is_checksum_address(value):
            self.fail("invalid_checksum")

        try:
            value = to_canonical_address(value)
        except ValueError:
            self.fail("invalid_data")

        if len(value) != 20:
            self.fail("invalid_size")

        if value == NULL_ADDRESS_BYTES:
            self.fail("null_address")

        return value


class TimeStampField(fields.DateTime):
    def _serialize(
        self, value: Optional[datetime.datetime], attr: Any, obj: Any, **kwargs
    ) -> Optional[str]:
        if value is not None:
            return value.isoformat()
        return None

    def _deserialize(self, value, attr, data, **kwargs) -> Optional[datetime.datetime]:
        if value is not None:
            return datetime.datetime.fromisoformat(value)
        return None


class SecretField(fields.Field):
    default_error_messages = {
        "missing_prefix": "Not a valid hex encoded value, must be 0x prefixed.",
        "invalid_data": "Not a valid hex formated string, contains invalid characters.",
        "invalid_size": (
            f"Not a valid hex encoded secret, it is not {SECRET_LENGTH} characters long."
        ),
    }

    @staticmethod
    def _serialize(value, attr, obj, **kwargs):  # pylint: disable=unused-argument
        return to_hex(value)

    def _deserialize(self, value, attr, data, **kwargs):  # pylint: disable=unused-argument
        if not is_0x_prefixed(value):
            self.fail("missing_prefix")

        try:
            value = to_bytes(hexstr=value)
        except binascii.Error:
            self.fail("invalid_data")

        if len(value) != SECRET_LENGTH:
            self.fail("invalid_size")

        return value


class SecretHashField(fields.Field):
    default_error_messages = {
        "missing_prefix": "Not a valid hex encoded value, must be 0x prefixed.",
        "invalid_data": "Not a valid hex formated string, contains invalid characters.",
        "invalid_size": (
            f"Not a valid secrethash, decoded value is not {SECRETHASH_LENGTH} bytes long."
        ),
    }

    @staticmethod
    def _serialize(value, attr, obj, **kwargs):  # pylint: disable=unused-argument
        return to_hex(value)

    def _deserialize(self, value, attr, data, **kwargs):  # pylint: disable=unused-argument
        if not is_0x_prefixed(value):
            self.fail("missing_prefix")

        try:
            value = to_bytes(hexstr=value)
        except binascii.Error:
            self.fail("invalid_data")

        if len(value) != SECRETHASH_LENGTH:
            self.fail("invalid_size")

        return value


class BaseOpts(SchemaOpts):
    """
    This allows for having the Object the Schema encodes to inside of the class Meta
    """

    def __init__(self, meta, ordered):
        SchemaOpts.__init__(self, meta, ordered=ordered)
        self.decoding_class = getattr(meta, "decoding_class", None)


class BaseSchema(Schema):
    OPTIONS_CLASS = BaseOpts

    @post_load
    def make_object(self, data, **kwargs):  # pylint: disable=unused-argument
        # this will depend on the Schema used, which has its object class in
        # the class Meta attributes
        decoding_class = self.opts.decoding_class  # pylint: disable=no-member
        return decoding_class(**data)


class BaseListSchema(Schema):
    OPTIONS_CLASS = BaseOpts

    @pre_load
    def wrap_data_envelope(self, data, **kwargs):  # pylint: disable=no-self-use,unused-argument
        # because the EventListSchema and ChannelListSchema objects need to
        # have some field ('data'), the data has to be enveloped in the
        # internal representation to comply with the Schema
        data = dict(data=data)
        return data

    @post_dump
    def unwrap_data_envelope(self, data, **kwargs):  # pylint: disable=no-self-use,unused-argument
        return data["data"]

    @post_load
    def make_object(self, data, **kwargs):  # pylint: disable=unused-argument
        decoding_class = self.opts.decoding_class  # pylint: disable=no-member
        list_ = data["data"]
        return decoding_class(list_)


class BlockchainEventsRequestSchema(BaseSchema):
    from_block = fields.Integer(missing=None)
    to_block = fields.Integer(missing=None)

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs
        decoding_class = dict


class RaidenEventsRequestSchema(BaseSchema):
    limit = fields.Integer(missing=None)
    offset = fields.Integer(missing=None)

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


class MintTokenSchema(BaseSchema):
    to = AddressField(required=True)
    value = fields.Integer(required=True, validate=validate.Range(min=1, max=UINT256_MAX))
    contract_method = fields.String(
        validate=validate.OneOf(choices=("increaseSupply", "mint", "mintFor"))
    )

    class Meta:
        strict = True
        decoding_class = dict


class ChannelStateSchema(BaseSchema):
    channel_identifier = fields.Integer(attribute="identifier")
    token_network_address = AddressField()
    token_address = AddressField()
    partner_address = fields.Method("get_partner_address")
    settle_timeout = fields.Integer()
    reveal_timeout = fields.Integer()
    balance = fields.Method("get_balance")
    state = fields.Method("get_state")
    total_deposit = fields.Method("get_total_deposit")
    total_withdraw = fields.Method("get_total_withdraw")

    @staticmethod
    def get_partner_address(channel_state: NettingChannelState) -> str:
        return to_checksum_address(channel_state.partner_state.address)

    @staticmethod
    def get_balance(channel_state: NettingChannelState) -> int:
        return channel.get_balance(channel_state.our_state, channel_state.partner_state)

    @staticmethod
    def get_state(channel_state: NettingChannelState) -> str:
        return channel.get_status(channel_state).value

    @staticmethod
    def get_total_deposit(channel_state: NettingChannelState) -> int:
        """Return our total deposit in the contract for this channel"""
        return channel_state.our_total_deposit

    @staticmethod
    def get_total_withdraw(channel_state: NettingChannelState) -> int:
        """Return our total withdraw from this channel"""
        return channel_state.our_total_withdraw

    class Meta:
        strict = True
        decoding_class = dict


class ChannelPutSchema(BaseSchema):
    token_address = AddressField(required=True)
    partner_address = AddressField(required=True)
    reveal_timeout = fields.Integer(missing=None)
    settle_timeout = fields.Integer(missing=None)
    total_deposit = fields.Integer(default=None, missing=None)

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
        decoding_class = dict


class ChannelPatchSchema(BaseSchema):
    total_deposit = fields.Integer(default=None, missing=None)
    total_withdraw = fields.Integer(default=None, missing=None)
    reveal_timeout = fields.Integer(default=None, missing=None)
    state = fields.String(
        default=None,
        missing=None,
        validate=validate.OneOf(
            [
                ChannelState.STATE_CLOSED.value,
                ChannelState.STATE_OPENED.value,
                ChannelState.STATE_SETTLED.value,
            ]
        ),
    )

    class Meta:
        strict = True
        # decoding to a dict is required by the @use_kwargs decorator from webargs:
        decoding_class = dict


class PaymentSchema(BaseSchema):
    initiator_address = AddressField(missing=None)
    target_address = AddressField(missing=None)
    token_address = AddressField(missing=None)
    amount = fields.Integer(required=True)
    identifier = fields.Integer(missing=None)
    secret = SecretField(missing=None)
    secret_hash = SecretHashField(missing=None)
    lock_timeout = fields.Integer(missing=None)

    class Meta:
        strict = True
        decoding_class = dict


class ConnectionsConnectSchema(BaseSchema):
    funds = fields.Integer(required=True)
    initial_channel_target = fields.Integer(missing=DEFAULT_INITIAL_CHANNEL_TARGET)
    joinable_funds_target = fields.Decimal(missing=DEFAULT_JOINABLE_FUNDS_TARGET)

    class Meta:
        strict = True
        decoding_class = dict


class ConnectionsLeaveSchema(BaseSchema):
    class Meta:
        strict = True
        decoding_class = dict


class EventPaymentSentFailedSchema(BaseSchema):
    block_number = fields.Integer()
    identifier = fields.Integer()
    event = fields.Constant("EventPaymentSentFailed")
    reason = fields.Str()
    target = AddressField()
    log_time = TimeStampField()

    class Meta:
        fields = ("block_number", "event", "reason", "target", "log_time")
        strict = True
        decoding_class = dict


class EventPaymentSentSuccessSchema(BaseSchema):
    block_number = fields.Integer()
    identifier = fields.Integer()
    event = fields.Constant("EventPaymentSentSuccess")
    amount = fields.Integer()
    target = AddressField()
    log_time = TimeStampField()

    class Meta:
        fields = ("block_number", "event", "amount", "target", "identifier", "log_time")
        strict = True
        decoding_class = dict


class EventPaymentReceivedSuccessSchema(BaseSchema):
    block_number = fields.Integer()
    identifier = fields.Integer()
    event = fields.Constant("EventPaymentReceivedSuccess")
    amount = fields.Integer()
    initiator = AddressField()
    log_time = TimeStampField()

    class Meta:
        fields = ("block_number", "event", "amount", "initiator", "identifier", "log_time")
        strict = True
        decoding_class = dict
