# -*- coding: utf-8 -*-

from webargs.flaskparser import use_kwargs, parser
from flask_restful import Resource
from flask import Blueprint
from pyethapp.jsonrpc import address_encoder
from raiden.api.v1.encoding import ChannelRequestSchema


def create_blueprint():
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:  http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
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


class EventsResoure(BaseResource):
    """no args, since we are filtering in the client for now"""

    _route = '/api/events'

    def __init__(self, **kwargs):
        super(EventsResoure, self).__init__(**kwargs)

    def get(self):
        return self.rest_api.get_new_events()
