# -*- coding: utf-8 -*-

from http import HTTPStatus
import json
import sys

from flask import Flask, make_response, url_for, send_from_directory, request
from flask.json import jsonify
from flask_restful import Api, abort
from flask_cors import CORS
from webargs.flaskparser import parser
from werkzeug.exceptions import NotFound
from gevent.wsgi import WSGIServer

from ethereum import slogging

from raiden.exceptions import (
    EthNodeCommunicationError,
    InvalidAddress,
    InvalidAmount,
    InvalidState,
    InvalidSettleTimeout,
    InsufficientFunds,
    NoPathError,
    SamePeerAddress,
    NoTokenManager,
    AddressWithoutCode,
    DuplicatedChannelError,
    ChannelNotFound,
    UnknownTokenAddress,
)
from raiden.api.v1.encoding import (
    ChannelSchema,
    ChannelListSchema,
    AddressListSchema,
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
    ConnectionManagersResource,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.raiden_service import (
    create_default_identifier,
)
from raiden.api.objects import ChannelList, PartnersPerTokenList, AddressList
from raiden.utils import address_encoder, channel_to_api_dict, split_endpoint, is_frozen

log = slogging.get_logger(__name__)

ERROR_STATUS_CODES = [
    HTTPStatus.CONFLICT,
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.PAYMENT_REQUIRED,
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.NOT_FOUND,
]

URLS_V1 = [
    ('/address', AddressResource),
    ('/channels', ChannelsResource),
    ('/channels/<hexaddress:channel_address>', ChannelsResourceByChannelAddress),
    ('/tokens', TokensResource),
    ('/tokens/<hexaddress:token_address>/partners', PartnersResourceByTokenAddress),
    ('/tokens/<hexaddress:token_address>', RegisterTokenResource),
    ('/events/network', NetworkEventsResource),
    ('/events/tokens/<hexaddress:token_address>', TokenEventsResource),
    ('/events/channels/<hexaddress:channel_address>', ChannelEventsResource),
    ('/token_swaps/<hexaddress:target_address>/<int:identifier>', TokenSwapsResource),
    (
        '/transfers/<hexaddress:token_address>/<hexaddress:target_address>',
        TransferToTargetResource,
    ),
    ('/connections/<hexaddress:token_address>', ConnectionsResource),
    ('/connections', ConnectionManagersResource),
]


def api_response(result, status_code=HTTPStatus.OK):
    if status_code == HTTPStatus.NO_CONTENT:
        assert not result, 'Provided 204 response with non-zero length response'
        data = ''
    else:
        data = json.dumps(result)

    response = make_response((
        data,
        status_code,
        {'mimetype': 'application/json', 'Content-Type': 'application/json'}
    ))
    return response


def api_error(errors, status_code):
    assert status_code in ERROR_STATUS_CODES, 'Programming error, unexpected error status code'
    response = make_response((
        json.dumps(dict(errors=errors)),
        status_code,
        {'mimetype': 'application/json', 'Content-Type': 'application/json'}
    ))
    return response


@parser.error_handler
def handle_request_parsing_error(err):
    """ This handles request parsing errors generated for example by schema
    field validation failing."""
    abort(HTTPStatus.BAD_REQUEST, errors=err.messages)


def endpoint_not_found(e):
    return api_error('invalid endpoint', HTTPStatus.NOT_FOUND)


def normalize_events_list(old_list):
    """Internally the `event_type` key is prefixed with underscore but the API
    returns an object without that prefix"""
    new_list = []
    for _event in old_list:
        new_event = dict(_event)
        new_event['event_type'] = new_event.pop('_event_type').decode()
        # Some of the raiden events contain accounts and as such need to
        # be exported in hex to the outside world
        if new_event['event_type'] == 'EventTransferReceivedSuccess':
            new_event['initiator'] = address_encoder(new_event['initiator'])[2:]
        if new_event['event_type'] == 'EventTransferSentSuccess':
            new_event['target'] = address_encoder(new_event['target'])[2:]
        new_list.append(new_event)
    return new_list


def restapi_setup_urls(flask_api_context, rest_api, urls):
    for route, resource_cls in urls:
        flask_api_context.add_resource(
            resource_cls,
            route,
            resource_class_kwargs={'rest_api_object': rest_api}
        )


def restapi_setup_type_converters(flask_app, names_to_converters):
    for key, value in names_to_converters.items():
        flask_app.url_map.converters[key] = value


class APIServer:
    """
    Runs the API-server that routes the endpoint to the resources.
    The API is wrapped in multiple layers, and the Server should be invoked this way::

        # instance of the raiden-api
        raiden_api = RaidenAPI(...)

        # wrap the raiden-api with rest-logic and encoding
        rest_api = RestAPI(raiden_api)

        # create the server and link the api-endpoints with flask / flask-restful middleware
        api_server = APIServer(rest_api)

        # run the server
        api_server.run('127.0.0.1', 5001, debug=True)

    """

    _api_prefix = '/api/1'

    def __init__(self, rest_api, cors_domain_list=None, web_ui=False, eth_rpc_endpoint=None):
        if rest_api.version != 1:
            raise ValueError(
                'Invalid api version: {}'.format(rest_api.version)
            )

        flask_app = Flask(__name__)
        if cors_domain_list:
            CORS(flask_app, origins=cors_domain_list)

        if eth_rpc_endpoint:
            if not eth_rpc_endpoint.startswith('http'):
                eth_rpc_endpoint = 'http://{}'.format(eth_rpc_endpoint)
            flask_app.config['WEB3_ENDPOINT'] = eth_rpc_endpoint

        blueprint = create_blueprint()
        flask_api_context = Api(blueprint, prefix=self._api_prefix)

        restapi_setup_type_converters(
            flask_app,
            {'hexaddress': HexAddressConverter},
        )

        restapi_setup_urls(
            flask_api_context,
            rest_api,
            URLS_V1,
        )

        self.rest_api = rest_api
        self.flask_app = flask_app
        self.blueprint = blueprint
        self.flask_api_context = flask_api_context

        self.wsgiserver = None
        self.flask_app.register_blueprint(self.blueprint)
        self.flask_app.config['WEBUI_PATH'] = '../ui/web/dist/'
        if is_frozen():
            # Inside frozen pyinstaller image
            self.flask_app.config['WEBUI_PATH'] = '{}/raiden/ui/web/dist/'.format(sys.prefix)

        self.flask_app.errorhandler(HTTPStatus.NOT_FOUND)(endpoint_not_found)

        if web_ui:
            for route in ('/ui/<path:file_name>', '/ui', '/ui/', '/index.html', '/'):
                self.flask_app.add_url_rule(
                    route,
                    route,
                    view_func=self._serve_webui,
                    methods=('GET', ),
                )

    def _serve_webui(self, file_name='index.html'):  # pylint: disable=redefined-builtin
        try:
            assert file_name
            web3 = self.flask_app.config.get('WEB3_ENDPOINT')
            if web3 and 'config.' in file_name and file_name.endswith('.json'):
                host = request.headers.get('Host')
                if any(h in web3 for h in ('localhost', '127.0.0.1')) and host:
                    _, _port = split_endpoint(web3)
                    _host, _ = split_endpoint(host)
                    web3 = 'http://{}:{}'.format(_host, _port)
                response = jsonify({'raiden': self._api_prefix, 'web3': web3})
            else:
                response = send_from_directory(self.flask_app.config['WEBUI_PATH'], file_name)
        except (NotFound, AssertionError):
            response = send_from_directory(self.flask_app.config['WEBUI_PATH'], 'index.html')
        return response

    def run(self, host='127.0.0.1', port=5001, **kwargs):
        self.flask_app.run(host=host, port=port, **kwargs)

    def start(self, host='127.0.0.1', port=5001):
        self.wsgiserver = WSGIServer((host, port), self.flask_app, log=log, error_log=log)
        self.wsgiserver.start()

    def stop(self, timeout=5):
        if getattr(self, 'wsgiserver', None):
            self.wsgiserver.stop(timeout)
            self.wsgiserver = None


class RestAPI:
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
        self.address_list_schema = AddressListSchema()
        self.partner_per_token_list_schema = PartnersPerTokenListSchema()
        self.transfer_schema = TransferSchema()

    def get_our_address(self):
        return api_response(result=dict(our_address=address_encoder(self.raiden_api.address)))

    def register_token(self, token_address):
        manager_address = self.raiden_api.manager_address_if_token_registered(token_address)

        if manager_address is not None:
            return api_error(
                errors='Token is already registered',
                status_code=HTTPStatus.CONFLICT
            )

        if manager_address is None:
            manager_address = self.raiden_api.register_token(token_address)

        return api_response(
            result=dict(channel_manager_address=address_encoder(manager_address)),
            status_code=HTTPStatus.CREATED
        )

    def open(
            self,
            partner_address,
            token_address,
            settle_timeout=None,
            reveal_timeout=None,
            balance=None):
        try:
            raiden_service_result = self.raiden_api.open(
                token_address,
                partner_address,
                settle_timeout,
                reveal_timeout,
            )
        except (InvalidAddress, InvalidSettleTimeout, SamePeerAddress,
                AddressWithoutCode, NoTokenManager, DuplicatedChannelError) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT
            )

        if balance:
            # make initial deposit
            try:
                raiden_service_result = self.raiden_api.deposit(
                    token_address,
                    partner_address,
                    balance
                )
            except EthNodeCommunicationError as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.REQUEST_TIMEOUT
                )
            except InsufficientFunds as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.PAYMENT_REQUIRED
                )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(
            result=result.data,
            status_code=HTTPStatus.CREATED
        )

    def deposit(self, token_address, partner_address, amount):
        try:
            raiden_service_result = self.raiden_api.deposit(
                token_address,
                partner_address,
                amount
            )
        except EthNodeCommunicationError as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.REQUEST_TIMEOUT
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED
            )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(result=result.data)

    def close(self, token_address, partner_address):

        raiden_service_result = self.raiden_api.close(
            token_address,
            partner_address
        )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(result=result.data)

    def connect(
            self,
            token_address,
            funds,
            initial_channel_target=None,
            joinable_funds_target=None):

        try:
            self.raiden_api.connect_token_network(
                token_address,
                funds,
                initial_channel_target,
                joinable_funds_target
            )
        except EthNodeCommunicationError as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.REQUEST_TIMEOUT
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED
            )

        return api_response(
            result=dict(),
            status_code=HTTPStatus.NO_CONTENT
        )

    def leave(self, token_address, only_receiving):
        closed_channels = self.raiden_api.leave_token_network(token_address, only_receiving)
        closed_channels = [channel.channel_address for channel in closed_channels]
        channel_addresses_list = AddressList(closed_channels)
        result = self.address_list_schema.dump(channel_addresses_list)
        return api_response(result=result.data)

    def get_connection_managers_info(self):
        raiden_service_result = self.raiden_api.get_connection_managers_info()
        assert isinstance(raiden_service_result, dict)
        # encode token addresses indexes
        result = {
            address_encoder(token_address): info
            for token_address, info in raiden_service_result.items()
        }
        return api_response(result=result)

    def get_channel_list(self, token_address=None, partner_address=None):
        raiden_service_result = self.raiden_api.get_channel_list(token_address, partner_address)
        assert isinstance(raiden_service_result, list)

        channel_list = ChannelList(raiden_service_result)
        result = self.channel_list_schema.dump(channel_list)
        return api_response(result=result.data)

    def get_tokens_list(self):
        raiden_service_result = self.raiden_api.get_tokens_list()
        assert isinstance(raiden_service_result, list)
        tokens_list = AddressList(raiden_service_result)
        result = self.address_list_schema.dump(tokens_list)
        return api_response(result=result.data)

    def get_network_events(self, from_block, to_block):
        raiden_service_result = self.raiden_api.get_network_events(
            from_block, to_block
        )
        return api_response(result=normalize_events_list(raiden_service_result))

    def get_token_network_events(self, token_address, from_block, to_block):
        try:
            raiden_service_result = self.raiden_api.get_token_network_events(
                token_address, from_block, to_block
            )
            return api_response(result=normalize_events_list(raiden_service_result))
        except UnknownTokenAddress as e:
            return api_error(str(e), status_code=HTTPStatus.NOT_FOUND)

    def get_channel_events(self, channel_address, from_block, to_block):
        raiden_service_result = self.raiden_api.get_channel_events(
            channel_address, from_block, to_block
        )
        return api_response(result=normalize_events_list(raiden_service_result))

    def get_channel(self, channel_address):
        channel = self.raiden_api.get_channel(channel_address)
        result = self.channel_schema.dump(channel_to_api_dict(channel))
        return api_response(result=result.data)

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
        return api_response(result=result.data)

    def initiate_transfer(self, token_address, target_address, amount, identifier):

        if identifier is None:
            identifier = create_default_identifier()

        try:
            transfer_result = self.raiden_api.transfer(
                token_address=token_address,
                target=target_address,
                amount=amount,
                identifier=identifier
            )
        except (InvalidAmount, InvalidAddress, NoPathError) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED
            )

        if transfer_result is False:
            return api_error(
                errors="Payment couldn't be completed "
                "(insufficient funds or no route to target).",
                status_code=HTTPStatus.CONFLICT
            )

        transfer = {
            'initiator_address': self.raiden_api.raiden.address,
            'token_address': token_address,
            'target_address': target_address,
            'amount': amount,
            'identifier': identifier,
        }
        result = self.transfer_schema.dump(transfer)
        return api_response(result=result.data)

    def _deposit(self, channel, balance):
        if channel.state != CHANNEL_STATE_OPENED:
            return api_error(
                errors="Can't deposit on a closed channel",
                status_code=HTTPStatus.CONFLICT,
            )

        try:
            raiden_service_result = self.raiden_api.deposit(
                channel.token_address,
                channel.partner_address,
                balance
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED
            )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(result=result.data)

    def _close(self, channel):
        if channel.state != CHANNEL_STATE_OPENED:
            return api_error(
                errors='Attempted to close an already closed channel',
                status_code=HTTPStatus.CONFLICT,
            )

        raiden_service_result = self.raiden_api.close(
            channel.token_address,
            channel.partner_address
        )
        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(result=result.data)

    def _settle(self, channel):
        if channel.state != CHANNEL_STATE_CLOSED:
            return api_error(
                errors='Attempted to settle a channel at its {} state'.format(
                    channel.state,
                ),
                status_code=HTTPStatus.CONFLICT,
            )

        try:
            raiden_service_result = self.raiden_api.settle(
                channel.token_address,
                channel.partner_address
            )
        except InvalidState:
            return api_error(
                errors='Settlement period is not yet over',
                status_code=HTTPStatus.CONFLICT,
            )

        result = self.channel_schema.dump(channel_to_api_dict(raiden_service_result))
        return api_response(result=result.data)

    def patch_channel(self, channel_address, balance=None, state=None):
        if balance is not None and state is not None:
            return api_error(
                errors='Can not update balance and change channel state at the same time',
                status_code=HTTPStatus.CONFLICT,
            )

        if balance is None and state is None:
            return api_error(
                errors="Nothing to do. Should either provide 'balance' or 'state' argument",
                status_code=HTTPStatus.BAD_REQUEST,
            )

        try:
            channel = self.raiden_api.get_channel(channel_address)
        except ChannelNotFound:
            return api_error(
                errors='Requested channel {} not found'.format(address_encoder(channel_address)),
                status_code=HTTPStatus.CONFLICT,
            )

        if balance is not None:
            result = self._deposit(channel, balance)

        elif state == CHANNEL_STATE_CLOSED:
            result = self._close(channel)

        elif state == CHANNEL_STATE_SETTLED:
            result = self._settle(channel)

        else:  # should never happen, channel_state is validated in the schema
            result = api_error(
                errors='Provided invalid channel state {}'.format(state),
                status_code=HTTPStatus.BAD_REQUEST,
            )

        return result

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
                identifier=identifier,
                maker_token=sending_token,
                maker_amount=sending_amount,
                maker_address=self.raiden_api.address,
                taker_token=receiving_token,
                taker_amount=receiving_amount,
                taker_address=target_address,
            )
        elif role == 'taker':
            self.raiden_api.expect_token_swap(
                identifier=identifier,
                maker_token=receiving_token,
                maker_amount=receiving_amount,
                maker_address=target_address,
                taker_token=sending_token,
                taker_amount=sending_amount,
                taker_address=self.raiden_api.address
            )
        else:
            # should never happen, role is validated in the schema
            return api_error(
                errors='Provided invalid token swap role {}'.format(role),
                status_code=HTTPStatus.BAD_REQUEST,
            )

        return api_response(result=dict(), status_code=HTTPStatus.CREATED)
