from flask import Flask
from flask_restful import Api, abort

from webargs.flaskparser import parser

from raiden.api.v1.encoding import (
    EventsListSchema,
    ChannelSchema,
    ChannelListSchema,
    HexAddressConverter
)
from raiden.api.v1.resources import (
    v1_resources_blueprint,
    ChannelsResource,
    ChannelsResourceByChannelAddress,
    TokensResource
)
from raiden.api.objects import EventsList, ChannelList


app = Flask(__name__)


class APIServer(object):
    """
    Runs the API-server that routes the endpoint to the resources.
    The API is wrapped in multiple layers, and the Server should be invoked this way:

    ```
    # instance of the raiden-api
    raiden_api = RaidenAPI(...)

    # wrap the raiden-api with rest-logic and encoding
    rest_api = RestAPI(raiden_api)

    # create the server and link the api-endpoints with flask / flask-restful middleware
    api_server = APIServer(rest_api)

    # run the server
    api_server.run(5001, debug=True)
    ```
    """

    # flask TypeConverter
    # links argument-placeholder in route (e.g. '/<hexaddress: channel_address>') to the Converter
    _type_converter_mapping = {
        'hexaddress': HexAddressConverter
    }

    # default resource classes will be added to the routes on initialisation
    # and will be exposed once the RestfulAPI is running
    _default_resource_classes = [
        ChannelsResource,
        ChannelsResourceByChannelAddress,
        TokensResource
    ]

    def __init__(self, rest_api):
        self.rest_api = rest_api
        if self.rest_api.version == 1:
            self.flask_api_middleware = Api(
                v1_resources_blueprint,
                prefix="/api/1"
            )
            blueprint = v1_resources_blueprint
        else:
            raise ValueError('Inalid api version: {}'.format(self.rest_api.version))

        self._add_default_resources()
        self._register_type_converters()
        app.register_blueprint(blueprint)

    def _add_default_resources(self):
        for klass in self._default_resource_classes:
            self.add_resource(klass)

    def _register_type_converters(self, additional_mapping=None):
        # an additional mapping concats to class-mapping and will overwrite existing keys
        if additional_mapping:
            mapping = dict(self._type_converter_mapping, **additional_mapping)
        else:
            mapping = self._type_converter_mapping

        for key, value in mapping.items():
            app.url_map.converters[key] = value

    def add_resource(self, resource_cls):
        # inject rest_api
        resource_cls.rest_api = self.rest_api

        self.flask_api_middleware.add_resource(
            resource_cls,
            resource_cls._route
        )

    def run(self, port, debug=False):
        app.run(port=port, debug=debug)


class RestAPI(object):
    """
    This wraps around the actual RaidenAPI in raiden_service.
    It will provide the additional, neccessary RESTful logic and
    the proper JSON-encoding of the Objects provided by the RaidenAPI
    """
    version = 1

    def __init__(self, raiden_api):
        self.raiden_api = raiden_api
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.events_list_schema = EventsListSchema()

    def open(self, partner_address, token_address, settle_timeout, deposit=None):
        api_result = self.raiden_api.open(
            token_address,
            partner_address,
            settle_timeout
        )

        if deposit:
            # make initial deposit
            api_result = self.raiden_api.deposit(
                token_address,
                partner_address,
                deposit
            )

        result = self.channel_schema.dumps(api_result)
        return result

    def deposit(self, token_address, partner_address, amount):

        api_result = self.raiden_api.deposit(
            token_address,
            partner_address,
            amount
        )

        result = self.channel_schema.dumps(api_result)
        return result

    def close(self, token_address, partner_address):

        api_result = self.raiden_api.close(
            token_address,
            partner_address
        )

        result = self.channel_schema.dumps(api_result)
        return result

    def get_channel_list(self, token_address=None, partner_address=None):
        api_result = self.raiden_api.get_channel_list(token_address, partner_address)
        assert isinstance(api_result, list)

        # wrap in ChannelList:
        channel_list = ChannelList(api_result)
        result = self.channel_list_schema.dumps(channel_list)
        return result

    def get_new_events(self):
        api_result = self.get_new_events()
        assert isinstance(api_result, list)

        # wrap in EventsList:
        events_list = EventsList(api_result)
        result = self.events_list_schema.dumps(events_list)
        return result

    def patch_channel(self, channel_address, deposit=None, status=None):

        if deposit is not None and status is None:
            api_result = self.raiden_api.deposit(deposit)
            return self.channel_schema.dumps(api_result)

        elif status is not None and deposit is None:

            if status == 'closed':
                api_result = self.raiden_api.close(channel_address)
                return self.channel_schema.dumps(api_result)

            if status == 'settled':
                api_result = self.raiden_api.close(channel_address)
                return self.channel_schema.dumps(api_result)

            if status == 'open':
                raise Exception('nothing to do here')
        raise Exception()


@parser.error_handler
def handle_request_parsing_error(err):
    abort(422, errors=err.messages)
