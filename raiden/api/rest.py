import errno
import json
import logging
import socket
import sys
from http import HTTPStatus
from typing import Dict

import gevent
import structlog
from eth_utils import encode_hex, to_checksum_address
from flask import Flask, make_response, request, send_from_directory, url_for
from flask.json import jsonify
from flask_cors import CORS
from flask_restful import Api, abort
from gevent.pywsgi import WSGIServer
from hexbytes import HexBytes
from webargs.flaskparser import parser
from werkzeug.exceptions import NotFound

from raiden.api.objects import AddressList, PartnersPerTokenList
from raiden.api.v1.encoding import (
    AddressListSchema,
    ChannelStateSchema,
    EventPaymentReceivedSuccessSchema,
    EventPaymentSentFailedSchema,
    EventPaymentSentSuccessSchema,
    HexAddressConverter,
    InvalidEndpoint,
    PartnersPerTokenListSchema,
    PaymentSchema,
)
from raiden.api.v1.resources import (
    AddressResource,
    BlockchainEventsNetworkResource,
    BlockchainEventsTokenResource,
    ChannelBlockchainEventsResource,
    ChannelsResource,
    ChannelsResourceByTokenAddress,
    ChannelsResourceByTokenAndPartnerAddress,
    ConnectionsInfoResource,
    ConnectionsResource,
    PartnersResourceByTokenAddress,
    PaymentResource,
    RaidenInternalEventsResource,
    RegisterTokenResource,
    TokensResource,
    create_blueprint,
)
from raiden.constants import GENESIS_BLOCK_NUMBER, Environment
from raiden.exceptions import (
    AddressWithoutCode,
    AlreadyRegisteredTokenAddress,
    APIServerPortInUseError,
    ChannelNotFound,
    DepositMismatch,
    DepositOverLimit,
    DuplicatedChannelError,
    InsufficientFunds,
    InsufficientGasReserve,
    InvalidAddress,
    InvalidAmount,
    InvalidBlockNumberInput,
    InvalidNumberInput,
    InvalidSettleTimeout,
    PaymentConflict,
    SamePeerAddress,
    TokenNotRegistered,
    TransactionThrew,
    UnknownTokenAddress,
)
from raiden.transfer import channel, views
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.transfer.state import CHANNEL_STATE_CLOSED, CHANNEL_STATE_OPENED, NettingChannelState
from raiden.utils import (
    create_default_identifier,
    is_frozen,
    optional_address_to_string,
    pex,
    split_endpoint,
    typing,
)
from raiden.utils.runnable import Runnable

log = structlog.get_logger(__name__)

ERROR_STATUS_CODES = [
    HTTPStatus.CONFLICT,
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.PAYMENT_REQUIRED,
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.NOT_FOUND,
    HTTPStatus.NOT_IMPLEMENTED,
    HTTPStatus.INTERNAL_SERVER_ERROR,
]

URLS_V1 = [
    (
        '/address',
        AddressResource,
    ),
    (
        '/channels',
        ChannelsResource,
    ),
    (
        '/channels/<hexaddress:token_address>',
        ChannelsResourceByTokenAddress,
    ),
    (
        '/channels/<hexaddress:token_address>/<hexaddress:partner_address>',
        ChannelsResourceByTokenAndPartnerAddress,
    ),
    (
        '/connections/<hexaddress:token_address>',
        ConnectionsResource,
    ),
    (
        '/connections',
        ConnectionsInfoResource,
    ),
    (
        '/payments',
        PaymentResource,
    ),
    (
        '/payments/<hexaddress:token_address>',
        PaymentResource,
        'token_paymentresource',
    ),
    (
        '/payments/<hexaddress:token_address>/<hexaddress:target_address>',
        PaymentResource,
        'token_target_paymentresource',
    ),
    (
        '/tokens',
        TokensResource,
    ),
    (
        '/tokens/<hexaddress:token_address>/partners',
        PartnersResourceByTokenAddress,
    ),
    (
        '/tokens/<hexaddress:token_address>',
        RegisterTokenResource,
    ),

    (
        '/_debug/blockchain_events/network',
        BlockchainEventsNetworkResource,
    ),
    (
        '/_debug/blockchain_events/tokens/<hexaddress:token_address>',
        BlockchainEventsTokenResource,
    ),
    (
        '/_debug/blockchain_events/payment_networks/<hexaddress:token_address>/channels',
        ChannelBlockchainEventsResource,
        'tokenchanneleventsresourceblockchain',
    ),
    (
        (
            '/_debug/blockchain_events/payment_networks/'
            '<hexaddress:token_address>/channels/<hexaddress:partner_address>'
        ),
        ChannelBlockchainEventsResource,
    ),
    (
        '/_debug/raiden_events',
        RaidenInternalEventsResource,
    ),
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
def handle_request_parsing_error(err, _req, _schema):
    """ This handles request parsing errors generated for example by schema
    field validation failing."""
    abort(HTTPStatus.BAD_REQUEST, errors=err.messages)


def endpoint_not_found(e):
    errors = ['invalid endpoint']
    if isinstance(e, InvalidEndpoint):
        errors.append(e.description)
    return api_error(errors, HTTPStatus.NOT_FOUND)


def hexbytes_to_str(map_: Dict):
    """ Converts values that are of type `HexBytes` to strings. """
    for k, v in map_.items():
        if isinstance(v, HexBytes):
            map_[k] = encode_hex(v)


def encode_byte_values(map_: Dict):
    """ Converts values that are of type `bytes` to strings. """
    for k, v in map_.items():
        if isinstance(v, bytes):
            map_[k] = encode_hex(v)


def encode_object_to_str(map_: Dict):
    for k, v in map_.items():
        if isinstance(v, int) or k == 'args':
            continue
        if not isinstance(v, str):
            map_[k] = repr(v)


def normalize_events_list(old_list):
    """Internally the `event_type` key is prefixed with underscore but the API
    returns an object without that prefix"""
    new_list = []
    for _event in old_list:
        new_event = dict(_event)
        if new_event.get('args'):
            new_event['args'] = dict(new_event['args'])
            encode_byte_values(new_event['args'])
        # remove the queue identifier
        if new_event.get('queue_identifier'):
            del new_event['queue_identifier']
        # the events contain HexBytes values, convert those to strings
        hexbytes_to_str(new_event)
        # Some of the raiden events contain accounts and as such need to
        # be exported in hex to the outside world
        name = new_event['event']
        if name == 'EventPaymentReceivedSuccess':
            new_event['initiator'] = to_checksum_address(new_event['initiator'])
        if name in ('EventPaymentSentSuccess', 'EventPaymentSentFailed'):
            new_event['target'] = to_checksum_address(new_event['target'])
        encode_byte_values(new_event)
        # encode unserializable objects
        encode_object_to_str(new_event)
        new_list.append(new_event)
    return new_list


def convert_to_serializable(event_list):
    returned_events = []
    for event in event_list:
        new_event = {
            'event': type(event).__name__,
        }
        new_event.update(event.__dict__)
        returned_events.append(new_event)
    return returned_events


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


class APIServer(Runnable):
    """
    Runs the API-server that routes the endpoint to the resources.
    The API is wrapped in multiple layers, and the Server should be invoked this way::

        # instance of the raiden-api
        raiden_api = RaidenAPI(...)

        # wrap the raiden-api with rest-logic and encoding
        rest_api = RestAPI(raiden_api)

        # create the server and link the api-endpoints with flask / flask-restful middleware
        api_server = APIServer(rest_api)

        # run the server greenlet
        api_server.start('127.0.0.1', 5001)
    """

    _api_prefix = '/api/1'
    kwargs = {'host': '127.0.0.1', 'port': 5001}

    def __init__(self, rest_api, cors_domain_list=None, web_ui=False, eth_rpc_endpoint=None):
        super().__init__()
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

        self.flask_app.register_error_handler(HTTPStatus.NOT_FOUND, endpoint_not_found)
        self.flask_app.register_error_handler(Exception, self.unhandled_exception)
        self.flask_app.before_request(self._is_raiden_running)

        # needed so flask_restful propagates the exception to our error handler above
        # or else, it'll replace it with a E500 response
        self.flask_app.config['PROPAGATE_EXCEPTIONS'] = True

        if web_ui:
            for route in ('/ui/<path:file_name>', '/ui', '/ui/', '/index.html', '/'):
                self.flask_app.add_url_rule(
                    route,
                    route,
                    view_func=self._serve_webui,
                    methods=('GET', ),
                )

        self._is_raiden_running()

    def _is_raiden_running(self):
        # We cannot accept requests before the node has synchronized with the
        # blockchain, which is done during the call to RaidenService.start.
        # Otherwise there is no guarantee that the node is in a valid state and
        # that the actions are valid, e.g. deposit in a channel that has closed
        # while the node was offline.
        if not self.rest_api.raiden_api.raiden:
            raise RuntimeError(
                'The RaidenService must be started before the API can be used',
            )

    def _serve_webui(self, file_name='index.html'):  # pylint: disable=redefined-builtin
        try:
            if not file_name:
                raise NotFound

            web3 = self.flask_app.config.get('WEB3_ENDPOINT')
            if 'config.' in file_name and file_name.endswith('.json'):
                environment_type = self.rest_api.raiden_api.raiden.config[
                    'environment_type'
                ].name.lower()
                config = {
                    'raiden': self._api_prefix,
                    'web3': web3,
                    'settle_timeout': self.rest_api.raiden_api.raiden.config['settle_timeout'],
                    'reveal_timeout': self.rest_api.raiden_api.raiden.config['reveal_timeout'],
                    'environment_type': environment_type,
                }

                # if raiden sees eth rpc endpoint as localhost, replace it by Host header,
                # which is the hostname by which the client/browser sees/access the raiden node
                host = request.headers.get('Host')
                if web3 and host:
                    web3_host, web3_port = split_endpoint(web3)
                    if web3_host in ('localhost', '127.0.0.1'):
                        host, _ = split_endpoint(host)
                        web3 = f'http://{host}:{web3_port}'
                        config['web3'] = web3

                response = jsonify(config)
            else:
                response = send_from_directory(self.flask_app.config['WEBUI_PATH'], file_name)
        except (NotFound, AssertionError):
            response = send_from_directory(self.flask_app.config['WEBUI_PATH'], 'index.html')
        return response

    def _run(self):
        try:
            self.wsgiserver.serve_forever()
        except gevent.GreenletExit:  # pylint: disable=try-except-raise
            raise
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def serve_forever(self, host='127.0.0.1', port=5001):
        self.start(host, port)
        return self.get()  # block here

    def start(self, host='127.0.0.1', port=5001):
        # WSGI expects an stdlib logger. With structlog there's conflict of
        # method names. Rest unhandled exception will be re-raised here:
        wsgi_log = logging.getLogger(__name__ + '.pywsgi')
        wsgiserver = WSGIServer(
            (host, port),
            self.flask_app,
            log=wsgi_log,
            error_log=wsgi_log,
        )

        try:
            wsgiserver.init_socket()
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                raise APIServerPortInUseError()
            raise

        self.wsgiserver = wsgiserver

        log.debug('REST API started', node=pex(self.rest_api.raiden_api.address))

        super().start()

    def stop(self):
        if self.wsgiserver is not None:
            self.wsgiserver.stop()
            self.wsgiserver = None

        log.debug('REST API stopped', node=pex(self.rest_api.raiden_api.address))

    def unhandled_exception(self, exception: Exception):
        """ Flask.errorhandler when an exception wasn't correctly handled """
        log.critical(
            'Unhandled exception when processing endpoint request',
            exc_info=True,
            node=pex(self.rest_api.raiden_api.address),
        )
        self.greenlet.kill(exception)
        return api_error([str(exception)], HTTPStatus.INTERNAL_SERVER_ERROR)


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
        self.payment_schema = PaymentSchema()
        self.sent_success_payment_schema = EventPaymentSentSuccessSchema()
        self.received_success_payment_schema = EventPaymentReceivedSuccessSchema()
        self.failed_payment_schema = EventPaymentSentFailedSchema()

    def get_our_address(self):
        return api_response(
            result=dict(our_address=to_checksum_address(self.raiden_api.address)),
        )

    def register_token(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
    ):
        if self.raiden_api.raiden.config['environment_type'] == Environment.PRODUCTION:
            return api_error(
                errors='Registering a new token is currently disabled in the Ethereum mainnet',
                status_code=HTTPStatus.NOT_IMPLEMENTED,
            )
        log.debug(
            'Registering token',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
        )
        try:
            token_network_address = self.raiden_api.token_network_register(
                registry_address,
                token_address,
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
            registry_address: typing.PaymentNetworkID,
            partner_address: typing.Address,
            token_address: typing.TokenAddress,
            settle_timeout: typing.BlockTimeout = None,
            total_deposit: typing.TokenAmount = None,
    ):
        log.debug(
            'Opening channel',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            partner_address=to_checksum_address(partner_address),
            token_address=to_checksum_address(token_address),
            settle_timeout=settle_timeout,
        )
        try:
            self.raiden_api.channel_open(
                registry_address,
                token_address,
                partner_address,
                settle_timeout,
            )
        except (InvalidAddress, InvalidSettleTimeout, SamePeerAddress,
                AddressWithoutCode, DuplicatedChannelError, TokenNotRegistered) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )
        except (InsufficientFunds, InsufficientGasReserve) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )

        if total_deposit:
            # make initial deposit
            log.debug(
                'Depositing to new channel',
                node=pex(self.raiden_api.address),
                registry_address=to_checksum_address(registry_address),
                token_address=to_checksum_address(token_address),
                partner_address=to_checksum_address(partner_address),
                total_deposit=total_deposit,
            )
            try:
                self.raiden_api.set_total_channel_deposit(
                    registry_address=registry_address,
                    token_address=token_address,
                    partner_address=partner_address,
                    total_deposit=total_deposit,
                )
            except InsufficientFunds as e:
                return api_error(
                    errors=str(e),
                    status_code=HTTPStatus.PAYMENT_REQUIRED,
                )
            except (DepositOverLimit, DepositMismatch) as e:
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
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            funds: typing.TokenAmount,
            initial_channel_target: int = None,
            joinable_funds_target: float = None,
    ):
        log.debug(
            'Connecting to token network',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )
        try:
            self.raiden_api.token_network_connect(
                registry_address,
                token_address,
                funds,
                initial_channel_target,
                joinable_funds_target,
            )
        except (InsufficientFunds, InsufficientGasReserve) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
            )
        except (InvalidAmount, InvalidAddress) as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
            )

        return api_response(
            result=dict(),
            status_code=HTTPStatus.NO_CONTENT,
        )

    def leave(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
    ):
        log.debug(
            'Leaving token network',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
        )
        closed_channels = self.raiden_api.token_network_leave(
            registry_address,
            token_address,
        )
        closed_channels = [
            self.channel_schema.dump(channel_state).data
            for channel_state in closed_channels
        ]
        return api_response(result=closed_channels)

    def get_connection_managers_info(self, registry_address: typing.PaymentNetworkID):
        """Get a dict whose keys are token addresses and whose values are
        open channels, funds of last request, sum of deposits and number of channels"""
        log.debug(
            'Getting connection managers info',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
        )
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

    def get_channel_list(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress = None,
            partner_address: typing.Address = None,
    ):
        log.debug(
            'Getting channel list',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=optional_address_to_string(token_address),
            partner_address=optional_address_to_string(partner_address),
        )
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

    def get_tokens_list(self, registry_address: typing.PaymentNetworkID):
        log.debug(
            'Getting token list',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
        )
        raiden_service_result = self.raiden_api.get_tokens_list(registry_address)
        assert isinstance(raiden_service_result, list)
        tokens_list = AddressList(raiden_service_result)
        result = self.address_list_schema.dump(tokens_list)
        return api_response(result=result.data)

    def get_blockchain_events_network(
            self,
            registry_address: typing.PaymentNetworkID,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        log.debug(
            'Getting network events',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            from_block=from_block,
            to_block=to_block,
        )
        try:
            raiden_service_result = self.raiden_api.get_blockchain_events_network(
                registry_address=registry_address,
                from_block=from_block,
                to_block=to_block,
            )
        except InvalidBlockNumberInput as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

        return api_response(result=normalize_events_list(raiden_service_result))

    def get_blockchain_events_token_network(
            self,
            token_address: typing.TokenAddress,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        log.debug(
            'Getting token network blockchain events',
            node=pex(self.raiden_api.address),
            token_address=to_checksum_address(token_address),
            from_block=from_block,
            to_block=to_block,
        )
        try:
            raiden_service_result = self.raiden_api.get_blockchain_events_token_network(
                token_address=token_address,
                from_block=from_block,
                to_block=to_block,
            )
            return api_response(result=normalize_events_list(raiden_service_result))
        except UnknownTokenAddress as e:
            return api_error(str(e), status_code=HTTPStatus.NOT_FOUND)
        except (InvalidBlockNumberInput, InvalidAddress) as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

    def get_raiden_events_payment_history_with_timestamps(
            self,
            token_address: typing.TokenAddress = None,
            target_address: typing.Address = None,
            limit: int = None,
            offset: int = None,
    ):
        log.debug(
            'Getting payment history',
            node=pex(self.raiden_api.address),
            token_address=optional_address_to_string(token_address),
            target_address=optional_address_to_string(target_address),
            limit=limit,
            offset=offset,
        )
        try:
            service_result = self.raiden_api.get_raiden_events_payment_history_with_timestamps(
                token_address=token_address,
                target_address=target_address,
                limit=limit,
                offset=offset,
            )
        except (InvalidNumberInput, InvalidAddress) as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)

        result = []
        for event in service_result:
            if isinstance(event.wrapped_event, EventPaymentSentSuccess):
                serialized_event = self.sent_success_payment_schema.dump(event)
            elif isinstance(event.wrapped_event, EventPaymentSentFailed):
                serialized_event = self.failed_payment_schema.dump(event)
            elif isinstance(event.wrapped_event, EventPaymentReceivedSuccess):
                serialized_event = self.received_success_payment_schema.dump(event)
            else:
                log.warning(
                    'Unexpected event',
                    node=pex(self.raiden_api.address),
                    unexpected_event=event.wrapped_event,
                )

            result.append(serialized_event.data)
        return api_response(result=result)

    def get_raiden_internal_events_with_timestamps(self, limit, offset):
        return [
            str(e)
            for e in self.raiden_api.raiden.wal.storage.get_events_with_timestamps(
                limit=limit,
                offset=offset,
            )
        ]

    def get_blockchain_events_channel(
            self,
            token_address: typing.TokenAddress,
            partner_address: typing.Address = None,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        log.debug(
            'Getting channel blockchain events',
            node=pex(self.raiden_api.address),
            token_address=to_checksum_address(token_address),
            partner_address=optional_address_to_string(partner_address),
            from_block=from_block,
            to_block=to_block,
        )
        try:
            raiden_service_result = self.raiden_api.get_blockchain_events_channel(
                token_address=token_address,
                partner_address=partner_address,
                from_block=from_block,
                to_block=to_block,
            )
            return api_response(result=normalize_events_list(raiden_service_result))
        except (InvalidBlockNumberInput, InvalidAddress) as e:
            return api_error(str(e), status_code=HTTPStatus.CONFLICT)
        except UnknownTokenAddress as e:
            return api_error(str(e), status_code=HTTPStatus.NOT_FOUND)

    def get_channel(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
    ):
        log.debug(
            'Getting channel',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
            partner_address=to_checksum_address(partner_address),
        )
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

    def get_partners_by_token(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
    ):
        log.debug(
            'Getting partners by token',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
        )
        return_list = []
        try:
            raiden_service_result = self.raiden_api.get_channel_list(
                registry_address,
                token_address,
            )
        except InvalidAddress as e:
            return api_error(
                errors=str(e),
                status_code=HTTPStatus.CONFLICT,
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

    def initiate_payment(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            target_address: typing.Address,
            amount: typing.TokenAmount,
            identifier: typing.PaymentID,
    ):
        log.debug(
            'Initiating payment',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
            amount=amount,
            payment_identifier=identifier,
        )

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
        except (InvalidAmount, InvalidAddress, PaymentConflict, UnknownTokenAddress) as e:
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

        payment = {
            'initiator_address': self.raiden_api.address,
            'registry_address': registry_address,
            'token_address': token_address,
            'target_address': target_address,
            'amount': amount,
            'identifier': identifier,
        }
        result = self.payment_schema.dump(payment)
        return api_response(result=result.data)

    def _deposit(
            self,
            registry_address: typing.PaymentNetworkID,
            channel_state: NettingChannelState,
            total_deposit: typing.TokenAmount,
    ):
        log.debug(
            'Depositing to channel',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            channel_identifier=channel_state.identifier,
            total_deposit=total_deposit,
        )

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

    def _close(
            self,
            registry_address: typing.PaymentNetworkID,
            channel_state: NettingChannelState,
    ):
        log.debug(
            'Closing channel',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            channel_identifier=channel_state.identifier,
        )

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
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
            total_deposit: typing.TokenAmount = None,
            state: str = None,
    ):
        log.debug(
            'Patching channel',
            node=pex(self.raiden_api.address),
            registry_address=to_checksum_address(registry_address),
            token_address=to_checksum_address(token_address),
            partner_address=to_checksum_address(partner_address),
            total_deposit=total_deposit,
            state=state,
        )

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
        if total_deposit and total_deposit < 0:
            return api_error(
                errors="Amount to deposit must not be negative.",
                status_code=HTTPStatus.CONFLICT,
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
        except InvalidAddress as e:
            return api_error(
                errors=str(e),
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
