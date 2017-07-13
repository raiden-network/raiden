# -*- coding: utf-8 -*-

import httplib
import json
from flask import Flask, make_response, url_for
from flask.json import jsonify
from flask_restful import Api, abort
from flask_cors import CORS
from webargs.flaskparser import parser

from pyethapp.jsonrpc import address_encoder
from raiden.exceptions import (
    InvalidAddress,
    InvalidAmount,
    NoPathError,
)
from raiden.api.v1.encoding import (
    ChannelSchema,
    ChannelListSchema,
    TokensListSchema,
    PartnersPerTokenListSchema,
    HexAddressConverter,
    TransferSchema,
)
from raiden.api.v1.resources import (
    create_blueprint,
    AddressResource,
    ChannelsResource,
    ChannelsResourceByChannelAddress,
    TokensResource,
    PartnersResourceByTokenAddress,
    NetworkEventsResource,
    RegisterTokenResource,
    TokenEventsResource,
    ChannelEventsResource,
    TokenSwapsResource,
    TransferToTargetResource,
    ConnectionsResource,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.raiden_service import (
    create_default_identifier,
)
from raiden.api.objects import ChannelList, TokensList, PartnersPerTokenList
from raiden.utils import channel_to_api_dict


def normalize_events_list(old_list):
    """Internally the `event_type` key is prefixed with underscore but the API
    returns an object without that prefix"""
    new_list = []
    for _event in old_list:
        new_event = dict(_event)
        new_event['event_type'] = new_event.pop('_event_type')
        new_list.append(new_event)
    return new_list


def jsonify_with_response(data, status_code):
    response = make_response((
        json.dumps(data),
        status_code,
        {'mimetype': 'application/json', 'Content-Type': 'application/json'}
    ))
    return response


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
    api_server.run('127.0.0.1', 5001, debug=True)
    ```
    """

    # flask TypeConverter
    # links argument-placeholder in route (e.g. '/<hexaddress: channel_address>') to the Converter
    _type_converter_mapping = {
        'hexaddress': HexAddressConverter
    }

    def __init__(self, rest_api, cors_domain_list=None):
        self.rest_api = rest_api
        self.blueprint = create_blueprint()
        if self.rest_api.version == 1:
            self.flask_api_context = Api(
                self.blueprint,
                prefix="/api/1",
            )
        else:
            raise ValueError('Invalid api version: {}'.format(self.rest_api.version))

        self.flask_app = Flask(__name__)
        if cors_domain_list:
            CORS(self.flask_app, origins=cors_domain_list)
        self._add_default_resources()
        self._register_type_converters()
        self.flask_app.register_blueprint(self.blueprint)

    def _add_default_resources(self):
        self.add_resource(AddressResource, '/address')
        self.add_resource(ChannelsResource, '/channels')
        self.add_resource(
            ChannelsResourceByChannelAddress,
            '/channels/<hexaddress:channel_address>'
        )
        self.add_resource(TokensResource, '/tokens')
        self.add_resource(
            PartnersResourceByTokenAddress,
            '/tokens/<hexaddress:token_address>/partners'
        )
        self.add_resource(
            RegisterTokenResource,
            '/tokens/<hexaddress:token_address>'
        )
        self.add_resource(NetworkEventsResource, '/events/network')
        self.add_resource(
            TokenEventsResource,
            '/events/tokens/<hexaddress:token_address>'
        )
        self.add_resource(
            ChannelEventsResource,
            '/events/channels/<hexaddress:channel_address>'
        )
        self.add_resource(
            TokenSwapsResource,
            '/token_swaps/<hexaddress:target_address>/<int:identifier>'
        )
        self.add_resource(
            TransferToTargetResource,
            '/transfers/<hexaddress:token_address>/<hexaddress:target_address>'
        )
        self.add_resource(
            ConnectionsResource,
            '/connection/<hexaddress:token_address>'
        )

    def _register_type_converters(self, additional_mapping=None):
        # an additional mapping concats to class-mapping and will overwrite existing keys
        if additional_mapping:
            mapping = dict(self._type_converter_mapping, **additional_mapping)
        else:
            mapping = self._type_converter_mapping

        for key, value in mapping.items():
            self.flask_app.url_map.converters[key] = value

    def add_resource(self, resource_cls, route):
        self.flask_api_context.add_resource(
            resource_cls,
            route,
            resource_class_kwargs={'rest_api_object': self.rest_api}
        )

    def run(self, host='127.0.0.1', port=5001, **kwargs):
        self.flask_app.run(host=host, port=port, **kwargs)


class RestAPI(object):
    """
    This wraps around the actual RaidenAPI in api/python.
    It will provide the additional, neccessary RESTful logic and
    the proper JSON-encoding of the Objects provided by the RaidenAPI
    """
    version = 1

    def __init__(self, raiden_api):
        self.raiden_api = raiden_api
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.tokens_list_schema = TokensListSchema()
        self.partner_per_token_list_schema = PartnersPerTokenListSchema()
        self.transfer_schema = TransferSchema()

    def get_our_address(self):
        return {'our_address': address_encoder(self.raiden_api.address)}

    def register_token(self, token_address):
        manager_address = self.raiden_api.manager_address_if_token_registered(token_address)

        if manager_address is not None:
            return make_response('Token is already registered', httplib.CONFLICT)

        if manager_address is None:
            manager_address = self.raiden_api.register_token(token_address)

        return jsonify_with_response(
            data=dict(channel_manager_address=address_encoder(manager_address)),
            status_code=httplib.CREATED
        )

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

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return jsonify_with_response(data=result.data, status_code=httplib.CREATED)

    def deposit(self, token_address, partner_address, amount):

        raiden_service_result = self.raiden_api.deposit(
            token_address,
            partner_address,
            amount
        )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return jsonify(result.data)

    def close(self, token_address, partner_address):

        raiden_service_result = self.raiden_api.close(
            token_address,
            partner_address
        )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return jsonify(result.data)

    def connect(
            self,
            token_address,
            funds,
            initial_channel_target=None,
            joinable_funds_target=None):

        self.raiden_api.connect_token_network(
            token_address,
            funds,
            initial_channel_target,
            joinable_funds_target
        )

    def leave(self, token_address, wait_for_settle=None, timeout=None):

        self.raiden_api.leave_token_network(
            token_address,
            wait_for_settle,
            timeout
        )

    def get_channel_list(self, token_address=None, partner_address=None):
        raiden_service_result = self.raiden_api.get_channel_list(token_address, partner_address)
        assert isinstance(raiden_service_result, list)

        channel_list = ChannelList(raiden_service_result)
        result = self.channel_list_schema.dump(channel_list)
        return jsonify(result.data)

    def get_tokens_list(self):
        raiden_service_result = self.raiden_api.get_tokens_list()
        assert isinstance(raiden_service_result, list)

        new_list = []
        for result in raiden_service_result:
            new_list.append({'address': result})

        tokens_list = TokensList(new_list)
        result = self.tokens_list_schema.dump(tokens_list)
        return jsonify(result.data)

    def get_network_events(self, from_block, to_block):
        raiden_service_result = self.raiden_api.get_network_events(
            from_block, to_block
        )
        return normalize_events_list(raiden_service_result)

    def get_token_network_events(self, token_address, from_block, to_block):
        raiden_service_result = self.raiden_api.get_token_network_events(
            token_address, from_block, to_block
        )
        return normalize_events_list(raiden_service_result)

    def get_channel_events(self, channel_address, from_block, to_block):
        raiden_service_result = self.raiden_api.get_channel_events(
            channel_address, from_block, to_block
        )
        return normalize_events_list(raiden_service_result)

    def get_channel(self, channel_address):
        channel = self.raiden_api.get_channel(channel_address)
        result = self.channel_schema.dump(channel_to_api_dict(channel))
        return jsonify(result.data)

    def get_partners_by_token(self, token_address):
        return_list = []
        raiden_service_result = self.raiden_api.get_channel_list(token_address)
        for result in raiden_service_result:
            return_list.append({
                'partner_address': result.partner_address,
                'channel': url_for(
                    # TODO: Somehow nicely parameterize this for future versions
                    'v1_resources.channelsresourcebychanneladdress',
                    channel_address=result.channel_address
                ),
            })

        schema_list = PartnersPerTokenList(return_list)
        result = self.partner_per_token_list_schema.dump(schema_list)
        return jsonify(result.data)

    def initiate_transfer(self, token_address, target_address, amount, identifier):

        if identifier is None:
            identifier = create_default_identifier()

        try:
            self.raiden_api.transfer(
                token_address=token_address,
                target=target_address,
                amount=amount,
                identifier=identifier
            )
        except (InvalidAmount, InvalidAddress, NoPathError) as e:
            return make_response(str(e), httplib.CONFLICT)

        transfer = {
            'initiator_address': self.raiden_api.raiden.address,
            'token_address': token_address,
            'target_address': target_address,
            'amount': amount,
            'identifier': identifier,
        }
        result = self.transfer_schema.dump(transfer)
        return jsonify(result.data)

    def patch_channel(self, channel_address, balance=None, state=None):
        if balance is not None and state is not None:
            return make_response(
                'Can not update balance and change channel state at the same time',
                httplib.CONFLICT,
            )
        elif balance is None and state is None:
            return make_response(
                'Nothing to do. Should either provide \'balance\' or \'state\' argument',
                httplib.BAD_REQUEST,
            )

        # find the channel
        channel = self.raiden_api.get_channel(channel_address)
        current_state = channel.state

        # if we patch with `balance` it's a deposit
        if balance is not None:
            if current_state != CHANNEL_STATE_OPENED:
                return make_response(
                    "Can't deposit on a closed channel",
                    httplib.CONFLICT,
                )
            raiden_service_result = self.raiden_api.deposit(
                channel.token_address,
                channel.partner_address,
                balance
            )
            result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
            return jsonify(result.data)

        if state == CHANNEL_STATE_CLOSED:
            if current_state != CHANNEL_STATE_OPENED:
                return make_response(
                    httplib.CONFLICT,
                    'Attempted to close an already closed channel'
                )
            raiden_service_result = self.raiden_api.close(
                channel.token_address,
                channel.partner_address
            )
            result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
            return jsonify(result.data)

        if state == CHANNEL_STATE_SETTLED:
            if current_state == CHANNEL_STATE_SETTLED or current_state == CHANNEL_STATE_OPENED:
                return make_response(
                    'Attempted to settle a channel at its {} state'.format(current_state),
                    httplib.CONFLICT,
                )
            raiden_service_result = self.raiden_api.settle(
                channel.token_address,
                channel.partner_address
            )
            result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
            return jsonify(result.data)

        # should never happen, channel_state is validated in the schema
        return make_response(
            'Provided invalid channel state {}'.format(state),
            httplib.BAD_REQUEST,
        )

    def token_swap(
            self,
            target_address,
            identifier,
            role,
            sending_token,
            sending_amount,
            receiving_token,
            receiving_amount):

        if role == 'maker':
            self.raiden_api.token_swap(
                from_token=sending_token,
                from_amount=sending_amount,
                to_token=receiving_token,
                to_amount=receiving_amount,
                target_address=target_address,
            )
        elif role == 'taker':
            self.raiden_api.expect_token_swap(
                identifier=identifier,
                from_token=sending_token,
                from_amount=sending_amount,
                to_token=receiving_token,
                to_amount=receiving_amount,
                target_address=target_address,
            )
        else:
            # should never happen, role is validated in the schema
            return make_response(
                'Provided invalid token swap role {}'.format(role),
                httplib.BAD_REQUEST,
            )

        return jsonify_with_response(dict(), httplib.CREATED)


@parser.error_handler
def handle_request_parsing_error(err):
    """ This handles request parsing errors generated for example by schema
    field validation failing."""
    abort(httplib.BAD_REQUEST, errors=err.messages)
