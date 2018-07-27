from webargs.flaskparser import use_kwargs
from flask_restful import Resource
from flask import Blueprint
from raiden.api.v1.encoding import (
    ChannelPutSchema,
    ChannelPatchSchema,
    EventRequestSchema,
    TransferSchema,
    ConnectionsConnectSchema,
    ConnectionsLeaveSchema,
)

import structlog

log = structlog.get_logger(__name__)


def create_blueprint():
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:
    # http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
    return Blueprint('v1_resources', __name__)


class BaseResource(Resource):
    def __init__(self, rest_api_object, **kwargs):
        super().__init__(**kwargs)
        self.rest_api = rest_api_object


class AddressResource(BaseResource):

    def get(self):
        return self.rest_api.get_our_address()


class ChannelsResource(BaseResource):

    put_schema = ChannelPutSchema

    def get(self):
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list(
            self.rest_api.raiden_api.raiden.default_registry.address,
        )

    @use_kwargs(put_schema, locations=('json',))
    def put(self, **kwargs):
        return self.rest_api.open(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            **kwargs,
        )


class ChannelsResourceByTokenAndPartnerAddress(BaseResource):

    patch_schema = ChannelPatchSchema

    @use_kwargs(patch_schema, locations=('json',))
    def patch(self, **kwargs):
        return self.rest_api.patch_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            **kwargs,
        )

    def get(self, **kwargs):
        return self.rest_api.get_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            **kwargs,
        )


class TokensResource(BaseResource):

    def get(self):
        """
        this translates to 'get all token addresses we have channels open for'
        """
        return self.rest_api.get_tokens_list(
            self.rest_api.raiden_api.raiden.default_registry.address,
        )


class PartnersResourceByTokenAddress(BaseResource):

    def get(self, token_address):
        return self.rest_api.get_partners_by_token(
            self.rest_api.raiden_api.raiden.default_registry.address,
            token_address,
        )


class NetworkEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, from_block, to_block):
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or 'latest'
        return self.rest_api.get_network_events(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            from_block=from_block,
            to_block=to_block,
        )


class TokenEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, token_address, from_block, to_block):
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or 'latest'
        return self.rest_api.get_token_network_events(
            token_address=token_address,
            from_block=from_block,
            to_block=to_block,
        )


class ChannelEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, token_address, partner_address=None, from_block=None, to_block=None):
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or 'latest'
        return self.rest_api.get_channel_events(
            token_address=token_address,
            partner_address=partner_address,
            from_block=from_block,
            to_block=to_block,
        )


class RegisterTokenResource(BaseResource):

    def put(self, token_address):
        return self.rest_api.register_token(
            self.rest_api.raiden_api.raiden.default_registry.address,
            token_address,
        )


class TransferToTargetResource(BaseResource):

    post_schema = TransferSchema(
        only=('amount', 'identifier'),
    )

    @use_kwargs(post_schema, locations=('json',))
    def post(self, token_address, target_address, amount, identifier):
        return self.rest_api.initiate_transfer(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            target_address=target_address,
            amount=amount,
            identifier=identifier,
        )


class ConnectionsResource(BaseResource):

    put_schema = ConnectionsConnectSchema()
    delete_schema = ConnectionsLeaveSchema()

    @use_kwargs(put_schema)
    def put(
            self,
            token_address,
            funds,
            initial_channel_target,
            joinable_funds_target,
    ):
        return self.rest_api.connect(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    @use_kwargs(delete_schema, locations=('json',))
    def delete(self, token_address):
        return self.rest_api.leave(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
        )


class ConnectionsInfoResource(BaseResource):

    def get(self):
        return self.rest_api.get_connection_managers_info(
            self.rest_api.raiden_api.raiden.default_registry.address,
        )
