from flask import Flask, jsonify, redirect, url_for, request
from flask_restful import Resource, Api, abort

from webargs.flaskparser import parser, abort

from raiden.api.encoding import EventsListSchema, ChannelSchema, ChannelListSchema
from raiden.api.objects import Events
from raiden.api.encoding import HexAddressConverter


app = Flask(__name__)


class RestfulAPI(object):

    _type_converter_mapping = {
        'hexaddress': HexAddressConverter
    }


    def __init__(self, api):
        self.api = api
        self.rest_api = Api(app)

    def add_resource(self, resource_cls, endpoint):
        # HACK:  set api manually
        resource_cls.api = self.api

        self.rest_api.add_resource(
            resource_cls,
            endpoint
        )

    @classmethod
    def register_type_converters(cls, additional_mapping=None):
        # an additional mapping concats to class-mapping and will overwrite existing keys
        if additional_mapping:
            mapping = dict(cls._type_converter_mapping, **additional_mapping)
        else:
            mapping = cls._type_converter_mapping

        for key, value in mapping.items():
            app.url_map.converters[key] = value

    def run(self, port, debug=False):
        app.run(port=port, debug=debug)


class APIWrapper(object):
    """
    This wraps around the actual RaidenAPI in raiden_service.
    It will provide additional, neccessary RESTful and
    the proper JSON-encoding of the Python-Objects provided by the RaidenAPI
    """

    def __init__(self, raiden_api):
        self.api = raiden_api

    def open(self, partner_address, asset_address, settle_timeout=None, reveal_timeout=None, amount=None):

        api_result = self.api.open(
            asset_address,
            partner_address,
            settle_timeout,
            reveal_timeout
        )

        if amount:
            # make initial deposit
            api_result = self.api.deposit(
                asset_address,
                partner_address,
                amount
            )

        # assert isinstance(api_result, Result)

        schema = None  # TODO ResultSchema()
        result = schema.dumps(api_result)
        return result

    def deposit(self, asset_address, partner_address, amount):

        api_result = self.api.deposit(
            asset_address,
            partner_address,
            amount
        )

        schema = ChannelSchema()
        result = schema.dumps(api_result)
        return result

    def close(self, asset_address, partner_address):

        api_result = self.api.close(
            asset_address,
            partner_address
        )

        schema = ChannelSchema()
        result = schema.dumps(api_result)
        return result

    def get_channel_list(self, asset_address=None, partner_address=None):
        api_result = self.api.get_channel_list(asset_address, partner_address)

        schema = ChannelListSchema()
        result = schema.dumps(api_result)
        return result

    def get_new_events(self):
        api_result = self.get_new_events()
        assert isinstance(api_result, Events)

        schema = EventsListSchema()
        result = schema.dumps(api_result)
        return result


@parser.error_handler
def handle_request_parsing_error(err):
    abort(422, errors=err.messages)


