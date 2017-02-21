from webargs.flaskparser import use_kwargs
from flask_restful import Resource

from raiden.api.encoding import AddressField, ChannelRequestSchema


class BaseResource(Resource):
    def __init__(self, **kwargs):
        return


class ChannelsResource(BaseResource):

    # define the route of the resource here:
    _route = 'channels'

    # has to be set externally via dependency injection
    rest_api = None
    put_schema = ChannelRequestSchema(
        exclude=('channel_address', 'status'),
    )

    delete_schema = dict(

    )

    update_schema = dict(

    )

    def get(self):
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list()

    # e.g. this endpoint will accept the args from all locations:
    # as JSON object, via form data. or as query string
    # change according to what is desired here
    @use_kwargs(put_schema, locations=('json', 'form', 'query'))
    def put(self, **kwargs):
        return self.rest_api.open(**kwargs)

    @use_kwargs(delete_schema)
    def delete(self, **kwargs):
        return self.rest_api.close(**kwargs)

    @use_kwargs(update_schema)
    def update(self, **kwargs):
        return self.rest_api.deposit(**kwargs)


class ChannelsResourceByChannelAddress(Resource):
    _route = 'channels/<hexaddress:channel_address>'
    rest_api = None

    patch_schema = ChannelRequestSchema(
        exclude=('channel_address', 'token_address', 'partner_address'),
    )

    @use_kwargs(patch_schema)
    def patch(self, **kwargs):
        # the channel_address kwarg is automatically included in the kwargs,
        # because there is an argument placeholder in the route!
        return self.rest_api.patch_channel(**kwargs)


class ChannelsByPartner(BaseResource):
    """
    this translates to 'All channel the node is connected with and have the specified asset
    """
    _route = '/api/partner/<hexaddress:partner_address>/channels'
    rest_api = None

    @use_kwargs({'asset_address': AddressField()})
    def get(self, partner_address, args):
        channel_list = self.rest_api.get_channel_list(
            asset_address=None,
            partner_address=partner_address
        )

        return channel_list


class Partner(BaseResource):
    pass


class Asset(BaseResource):
    pass


class EventsResoure(BaseResource):
    """
    no args, since we are filtering in the client for now
    """

    _route = '/api/events'
    rest_api = None

    def get(self):
        return self.rest_api.get_new_events()
