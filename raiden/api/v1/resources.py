# -*- coding: utf-8 -*-

from webargs.flaskparser import use_kwargs
from flask_restful import Resource
from flask import Blueprint
from raiden.api.v1.encoding import (
    ChannelRequestSchema,
    EventRequestSchema,
    TokenSwapsSchema,
    TransferSchema,
    ConnectionsConnectSchema,
    ConnectionsLeaveSchema,
)


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

    put_schema = ChannelRequestSchema(
        exclude=('channel_address', 'state'),
    )

    def get(self):
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list()

    @use_kwargs(put_schema, locations=('json',))
    def put(self, **kwargs):
        return self.rest_api.open(**kwargs)


class ChannelsResourceByChannelAddress(BaseResource):

    patch_schema = ChannelRequestSchema(
        only=('balance', 'state'),
    )

    @use_kwargs(patch_schema, locations=('json',))
    def patch(self, **kwargs):
        return self.rest_api.patch_channel(**kwargs)

    def get(self, **kwargs):
        return self.rest_api.get_channel(**kwargs)


class TokensResource(BaseResource):

    def get(self):
        """
        this translates to 'get all token addresses we have channels open for'
        """
        return self.rest_api.get_tokens_list()


class PartnersResourceByTokenAddress(BaseResource):

    def get(self, **kwargs):
        return self.rest_api.get_partners_by_token(**kwargs)


class NetworkEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, from_block, to_block):
        return self.rest_api.get_network_events(
            from_block=from_block,
            to_block=to_block,
        )


class TokenEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, token_address, from_block, to_block):
        return self.rest_api.get_token_network_events(
            token_address=token_address,
            from_block=from_block,
            to_block=to_block,
        )


class ChannelEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    @use_kwargs(get_schema, locations=('query',))
    def get(self, channel_address, from_block, to_block):
        return self.rest_api.get_channel_events(
            channel_address=channel_address,
            from_block=from_block,
            to_block=to_block,
        )


class RegisterTokenResource(BaseResource):

    def put(self, token_address):
        return self.rest_api.register_token(token_address)


class TokenSwapsResource(BaseResource):

    put_schema = TokenSwapsSchema()

    @use_kwargs(put_schema)
    def put(
            self,
            target_address,
            identifier,
            role,
            sending_token,
            sending_amount,
            receiving_token,
            receiving_amount):
        return self.rest_api.token_swap(
            target_address=target_address,
            identifier=identifier,
            role=role,
            sending_token=sending_token,
            sending_amount=sending_amount,
            receiving_token=receiving_token,
            receiving_amount=receiving_amount
        )


class TransferToTargetResource(BaseResource):

    post_schema = TransferSchema(
        only=('amount', 'identifier'),
    )

    @use_kwargs(post_schema, locations=('json',))
    def post(self, token_address, target_address, amount, identifier):
        return self.rest_api.initiate_transfer(
            token_address=token_address,
            target_address=target_address,
            amount=amount,
            identifier=identifier,
        )


class ConnectionsResource(BaseResource):

    put_schema = ConnectionsConnectSchema()
    delete_schema = ConnectionsLeaveSchema()

    @use_kwargs(put_schema)
    def put(self, token_address, funds, initial_channel_target, joinable_funds_target):
        return self.rest_api.connect(
            token_address=token_address,
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    @use_kwargs(delete_schema, locations=('json',))
    def delete(self, token_address, only_receiving_channels):
        return self.rest_api.leave(
            token_address=token_address,
            only_receiving=only_receiving_channels
        )


class ConnectionManagersResource(BaseResource):

    def get(self):
        return self.rest_api.get_connection_managers_info()
