from webargs.flaskparser import use_args, use_kwargs, parser
from flask_restful import Resource
from flask import Blueprint
from pyethapp.jsonrpc import address_encoder
from raiden.api.v1.encoding import ChannelRequestSchema, AddressField


def create_blueprint():
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:  http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
    return Blueprint('v1_resources', __name__)


class BaseResource(Resource):
    def __init__(self, **kwargs):
        return


@parser.location_handler('query')
def parse_query_data(request, name, field):
    if 'channel_address' in request.view_args:
        # TODO: channel address gets encoded into the view_args from inside
        # the flask/webargs core code as bytes and now we encode the bytes
        # to hex again. Feels like a waste. Find a way to fix?
        #
        #   Option 1: Figure out how to properly add it as an argument when appearing
        #             as a placeholder in the variable endpoint and use it from inside
        #             the various put/patch functions.
        #
        #   Option 2: Remove the hexaddress part of <hexaddress:channel_address>.
        #             With this the conversion to bytes should not be performed,
        #             but also we would probably need to extract the channel address
        #             in this function here by parsing the URL string.
        return address_encoder(request.view_args['channel_address'])


class ChannelsResource(BaseResource):

    # define the route of the resource here:
    _route = '/channels'

    # has to be set externally via dependency injection
    rest_api = None
    put_schema = ChannelRequestSchema(
        exclude=('channel_address', 'state'),
    )

    def get(self):
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list()

    # e.g. this endpoint will accept the args from all locations:
    # as JSON object, via form data. or as query string
    # change according to what is desired here
    @use_kwargs(put_schema, locations=('form',))
    def put(self, **kwargs):
        return self.rest_api.open(**kwargs)


class ChannelsResourceByChannelAddress(Resource):
    _route = '/channels/<hexaddress:channel_address>'
    rest_api = None

    patch_schema = ChannelRequestSchema(
        exclude=('token_address', 'partner_address', 'settle_timeout'),
    )

    @use_args(patch_schema, locations=('form',))
    @use_kwargs({'channel_address': AddressField()}, locations=('query',))
    def patch(self, *args, **kwargs):
        # TODO: Perhaps use a different schema here for patching so that the
        #      channel address does not appear twice and we don't need to combine
        #      dictionaries like this.
        args = args[0]
        args.update(kwargs)
        return self.rest_api.patch_channel(**args)


class TokensResource(BaseResource):
    _route = '/tokens'
    rest_api = None

    patch_schema = ChannelRequestSchema(
        exclude=('channel_address', 'token_address', 'partner_address'),
    )

    def get(self):
        """
        this translates to 'get all token addresses we have channels open for
        """
        # TODO
        pass


class Partner(BaseResource):
    pass


class EventsResoure(BaseResource):
    """
    no args, since we are filtering in the client for now
    """

    _route = '/api/events'
    rest_api = None

    def get(self):
        return self.rest_api.get_new_events()
