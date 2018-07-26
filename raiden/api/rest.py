from http import HTTPStatus
import errno
import json
import logging
import socket
import structlog
import sys
from typing import Dict

from flask import Flask, make_response, url_for, send_from_directory, request
from flask.json import jsonify
from flask_restful import Api, abort
from flask_cors import CORS
from webargs.flaskparser import parser
from werkzeug.exceptions import NotFound
from gevent.pywsgi import WSGIServer
from eth_utils import to_checksum_address
from hexbytes import HexBytes
from eth_utils import encode_hex

from raiden.exceptions import (
    AddressWithoutCode,
    AlreadyRegisteredTokenAddress,
    APIServerPortInUseError,
    ChannelNotFound,
    DuplicatedChannelError,
    EthNodeCommunicationError,
    InsufficientFunds,
    InvalidAddress,
    InvalidBlockNumberInput,
    InvalidAmount,
    InvalidSettleTimeout,
    SamePeerAddress,
    TransactionThrew,
    UnknownTokenAddress,
    DepositOverLimit,
    DepositMismatch,
    TokenNotRegistered,
)
from raiden.api.v1.encoding import (
    AddressListSchema,
    ChannelStateSchema,
    HexAddressConverter,
    KeccakConverter,
    PartnersPerTokenListSchema,
    TransferSchema,
    InvalidEndpoint,
)
from raiden.api.v1.resources import (
    create_blueprint,
    AddressResource,
    ChannelsResource,
    ChannelsResourceByTokenAndPartnerAddress,
    TokensResource,
    PartnersResourceByTokenAddress,
    NetworkEventsResource,
    RegisterTokenResource,
    TokenEventsResource,
    ChannelEventsResource,
    TransferToTargetResource,
    ConnectionsResource,
    ConnectionsInfoResource,
)
from raiden.transfer import channel, views
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
)
from raiden.utils import create_default_identifier
from raiden.api.objects import PartnersPerTokenList, AddressList
from raiden.utils import (
    split_endpoint,
    is_frozen,
)

log = structlog.get_logger(__name__)

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
    (
        '/channels/<hexaddress:token_address>/<hexaddress:partner_address>',
        ChannelsResourceByTokenAndPartnerAddress),
    ('/tokens', TokensResource),
    ('/tokens/<hexaddress:token_address>/partners', PartnersResourceByTokenAddress),
    ('/tokens/<hexaddress:token_address>', RegisterTokenResource),
    ('/events/network', NetworkEventsResource),
    ('/events/tokens/<hexaddress:token_address>', TokenEventsResource),
    (
        '/events/channels/<hexaddress:token_address>',
        ChannelEventsResource,
        'tokenchanneleventsresource',
    ),
    (
        '/events/channels/<hexaddress:token_address>/<hexaddress:partner_address>',
        ChannelEventsResource,
    ),
    (
        '/transfers/<hexaddress:token_address>/<hexaddress:target_address>',
        TransferToTargetResource,
    ),
    ('/connections/<hexaddress:token_address>', ConnectionsResource),
    ('/connections', ConnectionsInfoResource),
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
        {'mimetype': 'application/json', 'Content-Type': 'application/json'},
    ))
    return response


def api_error(errors, status_code):
    assert status_code in ERROR_STATUS_CODES, 'Programming error, unexpected error status code'
    response = make_response((
        json.dumps(dict(errors=errors)),
        status_code,
        {'mimetype': 'application/json', 'Content-Type': 'application/json'},
    ))
    return response


@parser.error_handler
def handle_request_parsing_error(err):
    """ This handles request parsing errors generated for example by schema
    field validation failing."""
    abort(HTTPStatus.BAD_REQUEST, errors=err.messages)


def endpoint_not_found(e):
    errors = ['invalid endpoint']
    if isinstance(e, InvalidEndpoint):
        errors.append(e.description)
    return api_error(errors, HTTPStatus.NOT_FOUND)


def hexbytes_to_str(map: Dict):
    """ Converts values that are of type `HexBytes` to strings. """
    for k, v in map.items():
        if isinstance(v, HexBytes):
            map[k] = encode_hex(v)


def encode_byte_values(map: Dict):
    """ Converts values that are of type `bytes` to strings. """
    for k, v in map.items():
        if isinstance(v, bytes):
            map[k] = encode_hex(v)


def normalize_events_list(old_list):
    """Internally the `event_type` key is prefixed with underscore but the API
    returns an object without that prefix"""
    new_list = []
    for _event in old_list:
        new_event = dict(_event)
        if new_event.get('args'):
            new_event['args'] = dict(new_event['args'])
            encode_byte_values(new_event['args'])

        # the events contain HexBytes values, convert those to strings
        hexbytes_to_str(new_event)
        # Some of the raiden events contain accounts and as such need to
        # be exported in hex to the outside world
        if new_event['event'] == 'EventTransferReceivedSuccess':
            new_event['initiator'] = to_checksum_address(new_event['initiator'])
        if new_event['event'] == 'EventTransferSentSuccess':
            new_event['target'] = to_checksum_address(new_event['target'])
        new_list.append(new_event)
    return new_list


def restapi_setup_urls(flask_api_context, rest_api, urls):
    for url_tuple in urls:
        if len(url_tuple) == 2:
            route, resource_cls = url_tuple
            endpoint = resource_cls.__name__.lower()
        elif len(url_tuple) == 3:
            route, resource_cls, endpoint = url_tuple
        else:
            raise ValueError(f'Invalid URL format: {url_tuple!r}')
        flask_api_context.add_resource(
            resource_cls,
            route,
            resource_class_kwargs={'rest_api_object': rest_api},
            endpoint=endpoint,
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
                'Invalid api version: {}'.format(rest_api.version),
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
            {
                'hexaddress': HexAddressConverter,
                'keccak': KeccakConverter,
            },
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
        try:
            # WSGI expects a stdlib logger, with structlog there's conflict of method names
            wsgi_log = logging.getLogger(__name__ + '.pywsgi')
            self.wsgiserver = WSGIServer(
                (host, port),
                self.flask_app,
                log=wsgi_log,
                error_log=wsgi_log,
            )
            self.wsgiserver.start()
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                raise APIServerPortInUseError()
            raise

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
        self.channel_schema = ChannelStateSchema()
        self.address_list_schema = AddressListSchema()
        self.partner_per_token_list_schema = PartnersPerTokenListSchema()
        self.transfer_schema = TransferSchema()

    def get_our_address(self):
        return api_response(
            result=dict(our_address=to_checksum_address(self.raiden_api.address)),
        )

    def register_token(self, registry_address, token_address):
        try:
            token_network_address = self.raiden_api.token_network_register(
                registry_address,
                token_address,
            )
        except EthNodeCommunicationError:
            return api_response(
                result='',
                status_code=HTTPStatus.ACCEPTED,
            )
        except (InvalidAddress, AlreadyRegisteredTokenAddress, TransactionThrew) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )

        return api_response(
            result=dict(token_network_address=to_checksum_address(token_network_address)),
            status_code=HTTPStatus.CREATED,
        )

    def open(
            self,
            registry_address,
            partner_address,
            token_address,
            settle_timeout=None,
            reveal_timeout=None,
            balance=None,
    ):

        try:
            self.raiden_api.channel_open(
                registry_address,
                token_address,
                partner_address,
                settle_timeout,
                reveal_timeout,
            )
        except EthNodeCommunicationError:
            return api_response(
                result='',
                status_code=HTTPStatus.ACCEPTED,
            )
        except (InvalidAddress, InvalidSettleTimeout, SamePeerAddress,
                AddressWithoutCode, DuplicatedChannelError, TokenNotRegistered) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )

        if balance:
            # make initial deposit
            try:
                self.raiden_api.set_total_channel_deposit(
                    registry_address,
                    token_address,
                    partner_address,
                    balance,
                )
            except EthNodeCommunicationError:
                return api_response(
                    result='',
                    status_code=HTTPStatus.ACCEPTED,
                )
            except InsufficientFunds as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.PAYMENT_REQUIRED,
                )
            except DepositOverLimit as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.CONFLICT,
                )
            except DepositMismatch as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.CONFLICT,
                )

        channel_state = views.get_channelstate_for(
            views.state_from_raiden(self.raiden_api.raiden),
            registry_address,
            token_address,
            partner_address,
        )

        result = self.channel_schema.dump(channel_state)

        return api_response(
            result=result.data,
            status_code=HTTPStatus.CREATED,
        )

    def connect(
            self,
            registry_address,
            token_address,
            funds,
            initial_channel_target=None,
            joinable_funds_target=None,
    ):

        try:
            self.raiden_api.token_network_connect(
                registry_address,
                token_address,
                funds,
                initial_channel_target,
                joinable_funds_target,
            )
        except EthNodeCommunicationError:
            return api_response(
                result='',
                status_code=HTTPStatus.ACCEPTED,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )
        except InvalidAmount as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )

        return api_response(
            result=dict(),
            status_code=HTTPStatus.NO_CONTENT,
        )

    def leave(self, registry_address, token_address):
        closed_channels = self.raiden_api.token_network_leave(
            registry_address,
            token_address,
        )
        closed_channels = [
            self.channel_schema.dump(channel_state).data
            for channel_state in closed_channels
        ]
        return api_response(result=closed_channels)

    def get_connection_managers_info(self, registry_address):
        """Get a dict whose keys are token addresses and whose values are
        open channels, funds of last request, sum of deposits and number of channels"""
        connection_managers = dict()

        for token in self.raiden_api.get_tokens_list(registry_address):
            token_network_identifier = views.get_token_network_identifier_by_token_address(
                views.state_from_raiden(self.raiden_api.raiden),
                payment_network_id=registry_address,
                token_address=token,
            )

            try:
                connection_manager = self.raiden_api.raiden.connection_manager_for_token_network(
                    token_network_identifier,
                )
            except InvalidAddress:
                connection_manager = None

            open_channels = views.get_channelstate_open(
                chain_state=views.state_from_raiden(self.raiden_api.raiden),
                payment_network_id=registry_address,
                token_address=token,
            )
            if connection_manager is not None and open_channels:
                connection_managers[to_checksum_address(connection_manager.token_address)] = {
                    'funds': connection_manager.funds,
                    'sum_deposits': views.get_our_capacity_for_token_network(
                        views.state_from_raiden(self.raiden_api.raiden),
                        registry_address,
                        token,
                    ),
                    'channels': len(open_channels),
                }

        return connection_managers

    def get_channel_list(self, registry_address, token_address=None, partner_address=None):
        raiden_service_result = self.raiden_api.get_channel_list(
            registry_address,
            token_address,
            partner_address,
        )
        assert isinstance(raiden_service_result, list)
        result = [
            self.channel_schema.dump(channel_schema).data
            for channel_schema in raiden_service_result
        ]
        return api_response(result=result)

    def get_tokens_list(self, registry_address):
        raiden_service_result = self.raiden_api.get_tokens_list(registry_address)
        assert isinstance(raiden_service_result, list)
        tokens_list = AddressList(raiden_service_result)
        result = self.address_list_schema.dump(tokens_list)
        return api_response(result=result.data)

    def get_network_events(self, registry_address, from_block, to_block):
        try:
            raiden_service_result = self.raiden_api.get_network_events(
                registry_address,
                from_block,
                to_block,
            )
        except InvalidBlockNumberInput as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

        return api_response(result=normalize_events_list(raiden_service_result))

    def get_token_network_events(self, token_address, from_block, to_block):
        try:
            raiden_service_result = self.raiden_api.get_token_network_events(
                token_address,
                from_block,
                to_block,
            )
            return api_response(result=normalize_events_list(raiden_service_result))
        except UnknownTokenAddress as e:
            return api_error(str(e), status_code=HTTPStatus.NOT_FOUND)
        except InvalidBlockNumberInput as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

    def get_channel_events(
            self,
            token_address,
            partner_address=None,
            from_block=None,
            to_block=None,
    ):
        try:
            raiden_service_result = self.raiden_api.get_channel_events(
                token_address,
                partner_address,
                from_block,
                to_block,
            )
        except InvalidBlockNumberInput as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

        return api_response(result=normalize_events_list(raiden_service_result))

    def get_channel(self, registry_address, token_address, partner_address):
        try:
            channel_state = self.raiden_api.get_channel(
                registry_address=registry_address,
                token_address=token_address,
                partner_address=partner_address,
            )
            result = self.channel_schema.dump(channel_state)
            return api_response(result=result.data)
        except ChannelNotFound as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.NOT_FOUND,
            )

    def get_partners_by_token(self, registry_address, token_address):
        return_list = []
        raiden_service_result = self.raiden_api.get_channel_list(
            registry_address,
            token_address,
        )
        for result in raiden_service_result:
            return_list.append({
                'partner_address': result.partner_state.address,
                'channel': url_for(
                    # TODO: Somehow nicely parameterize this for future versions
                    'v1_resources.channelsresourcebytokenandpartneraddress',
                    token_address=token_address,
                    partner_address=result.partner_state.address,
                ),
            })

        schema_list = PartnersPerTokenList(return_list)
        result = self.partner_per_token_list_schema.dump(schema_list)
        return api_response(result=result.data)

    def initiate_transfer(
            self,
            registry_address,
            token_address,
            target_address,
            amount,
            identifier,
    ):

        if identifier is None:
            identifier = create_default_identifier()

        try:
            transfer_result = self.raiden_api.transfer(
                registry_address=registry_address,
                token_address=token_address,
                target=target_address,
                amount=amount,
                identifier=identifier,
            )
        except (InvalidAmount, InvalidAddress) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )

        if transfer_result is False:
            return api_error(
                errors="Payment couldn't be completed "
                "(insufficient funds, no route to target or target offline).",
                status_code=HTTPStatus.CONFLICT,
            )

        transfer = {
            'initiator_address': self.raiden_api.address,
            'registry_address': registry_address,
            'token_address': token_address,
            'target_address': target_address,
            'amount': amount,
            'identifier': identifier,
        }
        result = self.transfer_schema.dump(transfer)
        return api_response(result=result.data)

    def _deposit(self, registry_address, channel_state, total_deposit):
        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            return api_error(
                errors="Can't set total deposit on a closed channel",
                status_code=HTTPStatus.CONFLICT,
            )

        try:
            self.raiden_api.set_total_channel_deposit(
                registry_address,
                channel_state.token_address,
                channel_state.partner_state.address,
                total_deposit,
            )
        except EthNodeCommunicationError:
            return api_response(
                result='',
                status_code=HTTPStatus.ACCEPTED,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )
        except DepositOverLimit as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )
        except DepositMismatch as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )

        updated_channel_state = self.raiden_api.get_channel(
            registry_address,
            channel_state.token_address,
            channel_state.partner_state.address,
        )

        result = self.channel_schema.dump(updated_channel_state)
        return api_response(result=result.data)

    def _close(self, registry_address, channel_state):
        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            return api_error(
                errors='Attempted to close an already closed channel',
                status_code=HTTPStatus.CONFLICT,
            )

        try:
            self.raiden_api.channel_close(
                registry_address,
                channel_state.token_address,
                channel_state.partner_state.address,
            )
        except EthNodeCommunicationError:
            return api_response(
                result='',
                status_code=HTTPStatus.ACCEPTED,
            )
        except InsufficientFunds as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )

        updated_channel_state = self.raiden_api.get_channel(
            registry_address,
            channel_state.token_address,
            channel_state.partner_state.address,
        )

        result = self.channel_schema.dump(updated_channel_state)
        return api_response(result=result.data)

    def patch_channel(
            self,
            registry_address,
            token_address,
            partner_address,
            total_deposit=None,
            state=None,
    ):
        if total_deposit is not None and state is not None:
            return api_error(
                errors="Can not update a channel's total deposit and state at the same time",
                status_code=HTTPStatus.CONFLICT,
            )

        if total_deposit is None and state is None:
            return api_error(
                errors="Nothing to do. Should either provide 'total_deposit' or 'state' argument",
                status_code=HTTPStatus.BAD_REQUEST,
            )

        try:
            channel_state = self.raiden_api.get_channel(
                registry_address=registry_address,
                token_address=token_address,
                partner_address=partner_address,
            )

        except ChannelNotFound:
            return api_error(
                errors='Requested channel for token {} and partner {} not found'.format(
                    to_checksum_address(token_address),
                    to_checksum_address(partner_address),
                ),
                status_code=HTTPStatus.CONFLICT,
            )

        if total_deposit is not None:
            result = self._deposit(registry_address, channel_state, total_deposit)

        elif state == CHANNEL_STATE_CLOSED:
            result = self._close(registry_address, channel_state)

        else:  # should never happen, channel_state is validated in the schema
            result = api_error(
                errors='Provided invalid channel state {}'.format(state),
                status_code=HTTPStatus.BAD_REQUEST,
            )

        return result
