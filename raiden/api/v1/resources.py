from typing import Dict

import marshmallow
from flask import Blueprint, Response, abort, jsonify, make_response, request
from flask_restful import Resource

from raiden.api.rest_utils import if_api_available
from raiden.api.v1.encoding import (
    ChannelPatchSchema,
    ChannelPutSchema,
    ConnectionsConnectSchema,
    MintTokenSchema,
    PaymentSchema,
    RaidenEventsRequestSchema,
    UserDepositPostSchema,
)
from raiden.utils.typing import TYPE_CHECKING, Address, Any, TargetAddress, TokenAddress

if TYPE_CHECKING:
    from raiden.api.rest import RestAPI


def _validate(  # pylint: disable=inconsistent-return-statements
    schema: marshmallow.Schema, data: Dict[str, Any]
) -> Dict[str, Any]:
    try:
        return schema.load(data)
    except marshmallow.ValidationError as ex:
        abort(make_response(jsonify(errors=ex.normalized_messages()), 400))


def validate_json(schema: marshmallow.Schema) -> Dict[str, Any]:
    json_data = request.get_json()
    if not json_data:
        abort(make_response(jsonify(errors="JSON payload expected"), 400))
    return _validate(schema, json_data)


def validate_query_params(schema: marshmallow.Schema) -> Dict[str, Any]:
    return _validate(schema, request.args)


def create_blueprint() -> Blueprint:
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:
    # http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
    return Blueprint("v1_resources", __name__)


class BaseResource(Resource):
    def __init__(self, rest_api_object: "RestAPI", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rest_api = rest_api_object


class AddressResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_our_address()


class VersionResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_raiden_version()


class NodeSettingsResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_node_settings()


class ContractsResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_contract_versions()


class ChannelsResource(BaseResource):

    put_schema = ChannelPutSchema()

    @if_api_available
    def get(self) -> Response:
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list(
            self.rest_api.raiden_api.raiden.default_registry.address
        )

    @if_api_available
    def put(self, **kwargs: Any) -> Response:
        kwargs.update(validate_json(self.put_schema))
        return self.rest_api.open(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class ChannelsResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, **kwargs: Any) -> Response:
        """
        this translates to 'get all channels the node is connected to for the given token address'
        """
        return self.rest_api.get_channel_list(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class ChannelsResourceByTokenAndPartnerAddress(BaseResource):

    patch_schema = ChannelPatchSchema()

    @if_api_available
    def patch(self, **kwargs: Any) -> Response:
        kwargs.update(validate_json(self.patch_schema))
        return self.rest_api.patch_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )

    @if_api_available
    def get(self, **kwargs: Any) -> Response:
        return self.rest_api.get_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class TokensResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        """
        this translates to 'get all token addresses we have channels open for'
        """
        return self.rest_api.get_tokens_list(
            self.rest_api.raiden_api.raiden.default_registry.address
        )


class PartnersResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_partners_by_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )


class RaidenInternalEventsResource(BaseResource):

    get_schema = RaidenEventsRequestSchema()

    @if_api_available
    def get(self) -> Response:
        kwargs = validate_query_params(self.get_schema)
        return self.rest_api.get_raiden_internal_events_with_timestamps(**kwargs)


class RegisterTokenResource(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_token_network_for_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )

    @if_api_available
    def put(self, token_address: TokenAddress) -> Response:
        return self.rest_api.register_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )


class MintTokenResource(BaseResource):
    post_schema = MintTokenSchema()

    @if_api_available
    def post(self, token_address: TokenAddress) -> Response:
        kwargs = validate_json(self.post_schema)
        return self.rest_api.mint_token_for(token_address=token_address, **kwargs)


class ConnectionsResource(BaseResource):

    put_schema = ConnectionsConnectSchema()

    @if_api_available
    def delete(self, token_address: TokenAddress) -> Response:
        return self.rest_api.leave(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
        )


class ConnectionsInfoResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_connection_managers_info(
            self.rest_api.raiden_api.raiden.default_registry.address
        )


class PaymentEventsResource(BaseResource):
    get_schema = RaidenEventsRequestSchema()

    @if_api_available
    def get(self, token_address: TokenAddress = None) -> Response:
        kwargs = validate_query_params(self.get_schema)
        return self.rest_api.get_raiden_events_payment_history_with_timestamps(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            **kwargs,
        )


class PaymentResource(BaseResource):
    post_schema = PaymentSchema(
        only=("amount", "identifier", "secret", "secret_hash", "lock_timeout", "paths")
    )
    get_schema = RaidenEventsRequestSchema()

    @if_api_available
    def get(self, token_address: TokenAddress, target_address: Address) -> Response:
        kwargs = validate_query_params(self.get_schema)
        return self.rest_api.get_raiden_events_payment_history_with_timestamps(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            target_address=target_address,
            **kwargs,
        )

    @if_api_available
    def post(self, token_address: TokenAddress, target_address: TargetAddress) -> Response:
        kwargs = validate_json(self.post_schema)
        route_states = kwargs.pop("paths", None)

        return self.rest_api.initiate_payment(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            target_address=target_address,
            route_states=route_states,
            **kwargs,
        )


class PendingTransfersResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_pending_transfers()


class PendingTransfersResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_pending_transfers(token_address)


class PendingTransfersResourceByTokenAndPartnerAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress, partner_address: Address) -> Response:
        return self.rest_api.get_pending_transfers(token_address, partner_address)


class UserDepositResource(BaseResource):
    post_schema = UserDepositPostSchema()

    @if_api_available
    def post(self) -> Response:
        kwargs = validate_json(self.post_schema)
        return self.rest_api.send_udc_transaction(**kwargs)


class StatusResource(BaseResource):
    def get(self) -> Response:
        return self.rest_api.get_status()


class ShutdownResource(BaseResource):
    @if_api_available
    def post(self) -> Response:
        return self.rest_api.shutdown()


class NotificationsResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_new_notifications()
