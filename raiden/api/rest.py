from flask import Flask, jsonify, redirect, url_for, request
from flask_restful import Resource, Api, abort

from webargs.flaskparser import parser, abort

from raiden.api.encoding import EventsListSchema, ChannelSchema, ChannelListSchema, HexAddressConverter
from raiden.api.resources import ChannelsResource, ChannelsByPartner
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

    # default resource classes will be added to the routes on initialisation and will be exposed
    # once the RestfulAPI is running
    _default_resource_classes = [
        ChannelsResource,
        ChannelsByPartner
    ]

    def __init__(self, rest_api):
        self.rest_api = rest_api
        self.flask_api_middleware = Api(app)

        self._register_type_converters()
        self._add_default_resources()

    def _add_default_resources(self):
        for klass in self._default_resource_classes:
            self.add_resource(klass)

    def _inject_api(self, klass):
        klass.api = self.rest_api

    def _register_type_converters(self, additional_mapping=None):
        # an additional mapping concats to class-mapping and will overwrite existing keys
        if additional_mapping:
            mapping = dict(self._type_converter_mapping, **additional_mapping)
        else:
            mapping = self._type_converter_mapping

        for key, value in mapping.items():
            app.url_map.converters[key] = value

    def add_resource(self, resource_cls):
        self._inject_api(resource_cls)

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

    def __init__(self, raiden_api):
        self.raiden_api = raiden_api

    def open(self, partner_address, asset_address, settle_timeout=None, reveal_timeout=None, amount=None):

        api_result = self.raiden_api.open(
            asset_address,
            partner_address,
            settle_timeout,
            reveal_timeout
        )

        if amount:
            # make initial deposit
            api_result = self.raiden_api.deposit(
                asset_address,
                partner_address,
                amount
            )

        schema = ChannelSchema()
        result = schema.dumps(api_result)
        return result

    def deposit(self, asset_address, partner_address, amount):

        api_result = self.raiden_api.deposit(
            asset_address,
            partner_address,
            amount
        )

        schema = ChannelSchema()
        result = schema.dumps(api_result)
        return result

    def close(self, asset_address, partner_address):

        api_result = self.raiden_api.close(
            asset_address,
            partner_address
        )

        schema = ChannelSchema()
        result = schema.dumps(api_result)
        return result

    def get_channel_list(self, asset_address=None, partner_address=None):
        api_result = self.raiden_api.get_channel_list(asset_address, partner_address)
        assert isinstance(api_result, list)

        # wrap in ChannelList:
        channel_list = ChannelList(api_result)

        schema = ChannelListSchema()
        result = schema.dumps(channel_list)
        return result

    def get_new_events(self):
        api_result = self.get_new_events()
        assert isinstance(api_result, list)

        #wrap in EventsList:
        events_list = EventsList(api_result)

        schema = EventsListSchema()
        result = schema.dumps(events_list)
        return result


@parser.error_handler
def handle_request_parsing_error(err):
    abort(422, errors=err.messages)

