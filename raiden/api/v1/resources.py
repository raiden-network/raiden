# -*- coding: utf-8 -*-

from webargs.flaskparser import use_kwargs
from flask_restful import Resource
from flask import Blueprint
from raiden.api.v1.encoding import (
    ChannelRequestSchema,
    EventRequestSchema,
    TokenSwapsSchema,
    TransferSchema,
)


def create_blueprint():
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:
    # http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
    return Blueprint('v1_resources', __name__)


class BaseResource(Resource):
    def __init__(self, **kwargs):
        super(BaseResource, self).__init__()
        self.rest_api = kwargs['rest_api_object']


class ChannelsResource(BaseResource):

    put_schema = ChannelRequestSchema(
        exclude=('channel_address', 'state'),
    )

    def __init__(self, **kwargs):
        super(ChannelsResource, self).__init__(**kwargs)

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
        exclude=('token_address', 'partner_address', 'settle_timeout', 'channel_address'),
    )

    def __init__(self, **kwargs):
        super(ChannelsResourceByChannelAddress, self).__init__(**kwargs)

    @use_kwargs(patch_schema, locations=('json',))
    def patch(self, **kwargs):
        return self.rest_api.patch_channel(**kwargs)

    def get(self, **kwargs):
        return self.rest_api.get_channel(**kwargs)


class TokensResource(BaseResource):

    def __init__(self, **kwargs):
        super(TokensResource, self).__init__(**kwargs)

    def get(self):
        """
        this translates to 'get all token addresses we have channels open for'
        """
        return self.rest_api.get_tokens_list()


class PartnersResourceByTokenAddress(BaseResource):

    def __init__(self, **kwargs):
        super(PartnersResourceByTokenAddress, self).__init__(**kwargs)

    def get(self, **kwargs):
        return self.rest_api.get_partners_by_token(**kwargs)


class NetworkEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    def __init__(self, **kwargs):
        super(NetworkEventsResource, self).__init__(**kwargs)

    @use_kwargs(get_schema, locations=('query',))
    def get(self, **kwargs):
        return self.rest_api.get_network_events(kwargs['from_block'], kwargs['to_block'])


class TokenEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    def __init__(self, **kwargs):
        super(TokenEventsResource, self).__init__(**kwargs)

    @use_kwargs(get_schema, locations=('query',))
    def get(self, **kwargs):
        return self.rest_api.get_token_network_events(
            kwargs['token_address'],
            kwargs['from_block'],
            kwargs['to_block']
        )


class ChannelEventsResource(BaseResource):

    get_schema = EventRequestSchema()

    def __init__(self, **kwargs):
        super(ChannelEventsResource, self).__init__(**kwargs)

    @use_kwargs(get_schema, locations=('query',))
    def get(self, **kwargs):
        return self.rest_api.get_channel_events(
            kwargs['channel_address'],
            kwargs['from_block'],
            kwargs['to_block']
        )


class TokenSwapsResource(BaseResource):

    put_schema = TokenSwapsSchema()

    def __init__(self, **kwargs):
        super(TokenSwapsResource, self).__init__(**kwargs)

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
        exclude=('initiator_address', 'target_address', 'token_address')
    )

    def __init__(self, **kwargs):
        super(TransferToTargetResource, self).__init__(**kwargs)

    @use_kwargs(post_schema, locations=('json',))
    def post(self, token_address, target_address, amount, identifier):
        return self.rest_api.initiate_transfer(
            token_address=token_address,
            target_address=target_address,
            amount=amount,
            identifier=identifier,
        )
