import binascii
from typing import Any, Dict
from urllib.parse import parse_qs

from eth_utils import (
    is_0x_prefixed,
    is_checksum_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_hex,
)
from marshmallow import (
    INCLUDE,
    Schema,
    SchemaOpts,
    fields,
    post_dump,
    post_load,
    pre_load,
    validate,
)
from werkzeug.exceptions import NotFound
from werkzeug.routing import BaseConverter
from werkzeug.urls import url_encode, url_parse

from raiden.api.objects import Address, AddressList, PartnersPerToken, PartnersPerTokenList
from raiden.constants import (
    NULL_ADDRESS_BYTES,
    NULL_ADDRESS_HEX,
    SECRET_LENGTH,
    SECRETHASH_LENGTH,
    UINT256_MAX,
)
from raiden.settings import DEFAULT_INITIAL_CHANNEL_TARGET, DEFAULT_JOINABLE_FUNDS_TARGET
from raiden.storage.serialization.schemas import IntegerToStringField
from raiden.storage.utils import TimestampedEvent
from raiden.transfer import channel
from raiden.transfer.state import ChainState, ChannelState, NettingChannelState
from raiden.transfer.views import get_token_network_by_address
from raiden.utils.capabilities import _bool_to_binary, int_bool
from raiden.utils.typing import Address as AddressBytes, AddressHex


class InvalidEndpoint(NotFound):
    """
    Exception to be raised instead of ValidationError if we want to skip the remaining
    endpoint matching rules and give a reason why the endpoint is invalid.
    """


class HexAddressConverter(BaseConverter):
    @staticmethod
    def to_python(value: Any) -> AddressBytes:
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
            raise self.make_error("missing_prefix")

        if not is_checksum_address(value):
            raise self.make_error("invalid_checksum")

        try:
            value = to_canonical_address(value)
        except ValueError:
            raise self.make_error("invalid_data")

        if len(value) != 20:
            raise self.make_error("invalid_size")

        if value == NULL_ADDRESS_BYTES:
            raise self.make_error("null_address")

        return value


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
            raise self.make_error("missing_prefix")

        try:
            value = to_bytes(hexstr=value)
        except binascii.Error:
            raise self.make_error("invalid_data")

        if len(value) != SECRET_LENGTH:
            raise self.make_error("invalid_size")

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
            raise self.make_error("missing_prefix")

        try:
            value = to_bytes(hexstr=value)
        except binascii.Error:
            raise self.make_error("invalid_data")

        if len(value) != SECRETHASH_LENGTH:
            raise self.make_error("invalid_size")

        return value


class CapabilitiesField(fields.Field):
    @staticmethod
    def _serialize(value, attr, obj, **kwargs):  # pylint: disable=unused-argument
        capdict = value or {}
        for key in capdict:
            capdict[key] = _bool_to_binary(capdict[key])
        return f"mxc://raiden.network/cap?{url_encode(capdict)}"

    def _deserialize(self, value, attr, data, **kwargs):  # pylint: disable=unused-argument
        capstring = url_parse(value)
        capdict = parse_qs(capstring.query)
        capabilities: Dict[str, Any] = {}
        for key, value in capdict.items():
            # reduce lists with one entry to just their element
            if len(value) == 1:
                capabilities[key] = int_bool(value.pop())
            else:
                capabilities[key] = value
        return capabilities


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
        decoding_class = self.opts.decoding_class  # type: ignore # pylint: disable=no-member
        if decoding_class is None:
            return data
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
        decoding_class = self.opts.decoding_class  # type: ignore # pylint: disable=no-member
        list_ = data["data"]
        return decoding_class(list_)


class RaidenEventsRequestSchema(BaseSchema):
    limit = IntegerToStringField(missing=None)
    offset = IntegerToStringField(missing=None)


class AddressSchema(BaseSchema):
    address = AddressField()

    class Meta:
        decoding_class = Address


class AddressListSchema(BaseListSchema):
    data = fields.List(AddressField())

    class Meta:
        decoding_class = AddressList


class PartnersPerTokenSchema(BaseSchema):
    partner_address = AddressField()
    channel = fields.String()

    class Meta:
        decoding_class = PartnersPerToken


class PartnersPerTokenListSchema(BaseListSchema):
    data = fields.Nested(PartnersPerTokenSchema, many=True)

    class Meta:
        decoding_class = PartnersPerTokenList


class MintTokenSchema(BaseSchema):
    to = AddressField(required=True)
    value = IntegerToStringField(required=True, validate=validate.Range(min=1, max=UINT256_MAX))


class ChannelStateSchema(BaseSchema):
    channel_identifier = IntegerToStringField(attribute="identifier")
    token_network_address = AddressField()
    token_address = AddressField()
    partner_address = fields.Method("get_partner_address")
    settle_timeout = IntegerToStringField()
    reveal_timeout = IntegerToStringField()
    balance = fields.Method("get_balance")
    state = fields.Method("get_state")
    total_deposit = fields.Method("get_total_deposit")
    total_withdraw = fields.Method("get_total_withdraw")

    @staticmethod
    def get_partner_address(channel_state: NettingChannelState) -> str:
        return to_checksum_address(channel_state.partner_state.address)

    @staticmethod
    def get_balance(channel_state: NettingChannelState) -> str:
        return str(channel.get_balance(channel_state.our_state, channel_state.partner_state))

    @staticmethod
    def get_state(channel_state: NettingChannelState) -> str:
        return channel.get_status(channel_state).value

    @staticmethod
    def get_total_deposit(channel_state: NettingChannelState) -> str:
        """Return our total deposit in the contract for this channel"""
        return str(channel_state.our_total_deposit)

    @staticmethod
    def get_total_withdraw(channel_state: NettingChannelState) -> str:
        """Return our total withdraw from this channel"""
        return str(channel_state.our_total_withdraw)


class ChannelPutSchema(BaseSchema):
    token_address = AddressField(required=True)
    partner_address = AddressField(required=True)
    reveal_timeout = IntegerToStringField(missing=None)
    settle_timeout = IntegerToStringField(missing=None)
    total_deposit = IntegerToStringField(default=None, missing=None)


class ChannelPatchSchema(BaseSchema):
    total_deposit = IntegerToStringField(default=None, missing=None)
    total_withdraw = IntegerToStringField(default=None, missing=None)
    reveal_timeout = IntegerToStringField(default=None, missing=None)
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


class PaymentSchema(BaseSchema):
    initiator_address = AddressField(missing=None)
    target_address = AddressField(missing=None)
    token_address = AddressField(missing=None)
    amount = IntegerToStringField(required=True)
    identifier = IntegerToStringField(missing=None)
    secret = SecretField(missing=None)
    secret_hash = SecretHashField(missing=None)
    lock_timeout = IntegerToStringField(missing=None)


class ConnectionsConnectSchema(BaseSchema):
    funds = IntegerToStringField(required=True)
    initial_channel_target = IntegerToStringField(missing=DEFAULT_INITIAL_CHANNEL_TARGET)
    joinable_funds_target = fields.Decimal(missing=DEFAULT_JOINABLE_FUNDS_TARGET)


class EventPaymentSchema(BaseSchema):
    block_number = IntegerToStringField()
    identifier = IntegerToStringField()
    log_time = fields.DateTime()
    token_address = AddressField(missing=None)

    def serialize(self, chain_state: ChainState, event: TimestampedEvent) -> Dict[str, Any]:
        serialized_event = self.dump(event)
        token_network = get_token_network_by_address(
            chain_state=chain_state,
            token_network_address=event.event.token_network_address,  # type: ignore
        )
        assert token_network, "Token network object should be registered if we got events with it"
        serialized_event["token_address"] = to_checksum_address(token_network.token_address)
        return serialized_event


class EventPaymentSentFailedSchema(EventPaymentSchema):
    event = fields.Constant("EventPaymentSentFailed")
    reason = fields.Str()
    target = AddressField()

    class Meta:
        fields = ("block_number", "event", "reason", "target", "log_time", "token_address")


class EventPaymentSentSuccessSchema(EventPaymentSchema):
    event = fields.Constant("EventPaymentSentSuccess")
    amount = IntegerToStringField()
    target = AddressField()

    class Meta:
        fields = (
            "block_number",
            "event",
            "amount",
            "target",
            "identifier",
            "log_time",
            "token_address",
        )


class EventPaymentReceivedSuccessSchema(EventPaymentSchema):
    event = fields.Constant("EventPaymentReceivedSuccess")
    amount = IntegerToStringField()
    initiator = AddressField()

    class Meta:
        fields = (
            "block_number",
            "event",
            "amount",
            "initiator",
            "identifier",
            "log_time",
            "token_address",
        )


class UserDepositPostSchema(BaseSchema):
    total_deposit = IntegerToStringField(default=None, missing=None)
    planned_withdraw_amount = IntegerToStringField(default=None, missing=None)
    withdraw_amount = IntegerToStringField(default=None, missing=None)


class NotificationSchema(BaseSchema):
    id = fields.String()
    summary = fields.String()
    body = fields.String()
    urgency = fields.String(
        default=None, missing=None, validate=validate.OneOf(["normal", "low", "critical"])
    )


class CapabilitiesSchema(BaseSchema):
    class Meta:
        unknown = INCLUDE

    capabilities = CapabilitiesField(missing="mxc://")
