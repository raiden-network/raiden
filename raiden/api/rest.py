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
    create_blueprint,
    ChannelsResource,
    ChannelsResourceByChannelAddress,
    TokensResource
)
from raiden.api.objects import EventsList, ChannelList


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
        self.blueprint = create_blueprint()
        if self.rest_api.version == 1:
            self.flask_api_middleware = Api(
                self.blueprint,
                prefix="/api/1"
            )
        else:
            raise ValueError('Invalid api version: {}'.format(self.rest_api.version))

        self.flask_app = Flask(__name__)
        self._add_default_resources()
        self._register_type_converters()
        self.flask_app.register_blueprint(self.blueprint)

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
            self.flask_app.url_map.converters[key] = value

    def add_resource(self, resource_cls):
        # inject rest_api
        resource_cls.rest_api = self.rest_api

        self.flask_api_middleware.add_resource(
            resource_cls,
            resource_cls._route
        )

    def run(self, port, **kwargs):
        self.flask_app.run(port=port, **kwargs)


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

    def open(self, partner_address, token_address, settle_timeout, balance=None):
        raiden_service_result = self.raiden_api.open(
            token_address,
            partner_address,
            settle_timeout
        )

        if balance:
            # make initial deposit
            raiden_service_result = self.raiden_api.deposit(
                token_address,
                partner_address,
                balance
            )

        result = self.channel_schema.dumps(raiden_service_result)
        return result

    def deposit(self, token_address, partner_address, amount):

        raiden_service_result = self.raiden_api.deposit(
            token_address,
            partner_address,
            amount
        )

        result = self.channel_schema.dumps(raiden_service_result)
        return result

    def close(self, token_address, partner_address):

        raiden_service_result = self.raiden_api.close(
            token_address,
            partner_address
        )

        result = self.channel_schema.dumps(raiden_service_result)
        return result

    def get_channel_list(self, token_address=None, partner_address=None):
        raiden_service_result = self.raiden_api.get_channel_list(token_address, partner_address)
        assert isinstance(raiden_service_result, list)

        # wrap in ChannelList:
        channel_list = ChannelList(raiden_service_result)
        result = self.channel_list_schema.dumps(channel_list)
        return result

    def get_new_events(self):
        raiden_service_result = self.get_new_events()
        assert isinstance(raiden_service_result, list)

        # wrap in EventsList:
        events_list = EventsList(raiden_service_result)
        result = self.events_list_schema.dumps(events_list)
        return result

    def patch_channel(self, channel_address, balance=None, state=None):
        # find the channel
        channel = self.raiden_api.get_channel(channel_address)

        # if we patch with `balance` it's a deposit
        if balance is not None and state is None:
            raiden_service_result = self.raiden_api.deposit(
                channel.token_address,
                channel.partner_address,
                balance
            )
            return self.channel_schema.dumps(raiden_service_result)

        elif state is not None and balance is None:

            if state == 'closed':
                raiden_service_result = self.raiden_api.close(channel_address)
                return self.channel_schema.dumps(raiden_service_result)
            elif state == 'settled':
                raiden_service_result = self.raiden_api.close(channel_address)
                return self.channel_schema.dumps(raiden_service_result)
            elif state == 'open':
                raise Exception('nothing to do here')

        raise Exception()


@parser.error_handler
def handle_request_parsing_error(err):
    abort(422, errors=err.messages)
