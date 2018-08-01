from typing import Optional, Tuple, Dict, List

import gevent
from eth_utils import is_address, is_checksum_address, is_same_address
from flask import Flask, request
from flask_restful import Api, Resource, reqparse
from gevent import Greenlet
from gevent.pywsgi import WSGIServer
from networkx.exception import NetworkXNoPath
from jsonschema.exceptions import ValidationError
from raiden_libs.messages import FeeInfo, Message, BalanceProof
from raiden_libs.exceptions import MessageTypeError
from raiden_libs.types import Address

from pathfinder.config import API_DEFAULT_PORT, API_HOST, API_PATH
from pathfinder.pathfinding_service import PathfindingService


class PathfinderResource(Resource):

    def __init__(self, pathfinding_service: PathfindingService) -> None:
        self.pathfinding_service = pathfinding_service

    def _validate_token_network_argument(
        self,
        token_network_address: str
    ) -> Optional[Tuple[Dict, int]]:

        if not is_address(token_network_address):
            no_address_message = 'Invalid token network address: {}'
            return {'error': no_address_message.format(token_network_address)}, 400

        if not is_checksum_address(token_network_address):
            address_error = 'Token network address not checksummed: {}'
            return {'error': address_error.format(token_network_address)}, 400

        token_network = self.pathfinding_service.token_networks.get(
            Address(token_network_address)
        )
        if token_network is None:
            return {
                'error': 'Unsupported token network: {}'.format(token_network_address)
            }, 400

        return None

    def _validate_channel_id_argument(self, channel_id: str) -> Optional[Tuple[Dict, int]]:
        try:
            int(channel_id)
        except Exception:
            id_error = 'Channel Id is not an int: {}'
            return {'error': id_error.format(channel_id)}, 400

        return None


class ChannelBalanceResource(PathfinderResource):

    def put(self, token_network_address: str, channel_id: str):
        token_network_error = self._validate_token_network_argument(token_network_address)
        if token_network_error is not None:
            return token_network_error

        channel_id_error = self._validate_channel_id_argument(channel_id)
        if channel_id_error is not None:
            return channel_id_error

        body = request.json
        try:
            balance_proof: BalanceProof = Message.deserialize(body, BalanceProof)
        except MessageTypeError:
            return {'error', 'Not a BalanceProof message'}, 400
        except ValidationError as val_err:
            return {'error': val_err.message}, 400

        # token_network_address and channel_id info is duplicate
        # check that both versions match
        if not is_same_address(token_network_address, balance_proof.token_network_address):
            error = 'The token network address from the balance proof ({}) ' \
                    'and the request ({}) do not match'
            return {
                'error': error.format(
                    balance_proof.token_network_address,
                    token_network_address
                )
            }, 400

        if not channel_id == str(balance_proof.channel_identifier):
            error = 'The channel identifier from the balance proof ({}) ' \
                    'and the request ({}) do not match'
            return {
                'error': error.format(
                    balance_proof.channel_identifier,
                    channel_id
                )
            }, 400

        # Note: signature check is performed by the PathfindingService
        if not self.pathfinding_service.follows_token_network(balance_proof.token_network_address):
            return {
                'error': 'Unsupported token network: {}'.format(token_network_address)
            }, 400

        try:
            self.pathfinding_service.on_balance_proof_message(balance_proof)
        except ValueError as error:
            return {
                'error': 'Error while updating balance proof: {}'.format(str(error))
            }, 400


class ChannelFeeResource(PathfinderResource):

    def put(self, token_network_address: str, channel_id: str):
        token_network_error = self._validate_token_network_argument(token_network_address)
        if token_network_error is not None:
            return token_network_error

        channel_id_error = self._validate_channel_id_argument(channel_id)
        if channel_id_error is not None:
            return channel_id_error

        body = request.json
        try:
            fee_info: FeeInfo = Message.deserialize(body, FeeInfo)
        except MessageTypeError:
            return {'error', 'Not a FeeInfo message'}, 400
        except ValidationError as val_err:
            return {'error': val_err.message}, 400

        # token_network_address and channel_id info is duplicate
        # check that both versions match
        if not is_same_address(token_network_address, fee_info.token_network_address):
            error = 'The token network address from the fee info ({}) ' \
                    'and the request ({}) do not match'
            return {
                'error': error.format(fee_info.token_network_address, token_network_address)
            }, 400

        if not channel_id == str(fee_info.channel_identifier):
            error = 'The channel identifier from the fee info ({}) ' \
                    'and the request ({}) do not match'
            return {
                'error': error.format(fee_info.channel_identifier, channel_id)
            }, 400

        # Note: signature check is performed by the PathfindingService
        if not self.pathfinding_service.follows_token_network(fee_info.token_network_address):
            return {
                'error': 'Unsupported token network: {}'.format(token_network_address)
            }, 400

        try:
            self.pathfinding_service.on_fee_info_message(fee_info)
        except ValueError as error:
            return {
                'error': 'Error while updating fee info: {}'.format(str(error))
            }, 400


class PathsResource(PathfinderResource):
    @staticmethod
    def _validate_args(args):
        required_args = ['from', 'to', 'value', 'num_paths']
        if not all(args[arg] is not None for arg in required_args):
            return {'error': 'Required parameters: {}'.format(required_args)}, 400

        address_error = 'Invalid {} address: {}'
        if not is_address(args['from']):
            return {'error': address_error.format('initiator', args['from'])}, 400
        if not is_address(args['to']):
            return {'error': address_error.format('target', args['to'])}, 400

        address_error = '{} address not checksummed: {}'
        if not is_checksum_address(args['from']):
            return {'error': address_error.format('Initiator', args['from'])}, 400
        if not is_checksum_address(args['to']):
            return {'error': address_error.format('Target', args['to'])}, 400

        if args.value < 0:
            return {'error': 'Payment value must be non-negative: {}'.format(args.value)}, 400

        if args.num_paths <= 0:
            return {'error': 'Number of paths must be positive: {}'.format(args.num_paths)}, 400

        return None

    # url parameters are used because json bodies for GET requests are uncommon
    def get(self, token_network_address: str):
        token_network_error = self._validate_token_network_argument(token_network_address)
        if token_network_error is not None:
            return token_network_error

        parser = reqparse.RequestParser()
        parser.add_argument('from', type=str, help='Payment initiator address.')
        parser.add_argument('to', type=str, help='Payment target address.')
        parser.add_argument('value', type=int, help='Maximum payment value.')
        parser.add_argument('num_paths', type=int, help='Number of paths requested.')

        args = parser.parse_args()
        error = self._validate_args(args)
        if error is not None:
            return error

        token_network = self.pathfinding_service.token_networks.get(
            Address(token_network_address)
        )
        if not token_network:
            return {'error': 'Token network {} not found.'.format(
                token_network_address
            )}, 400
        try:
            paths = token_network.get_paths(
                source=args['from'],
                target=args['to'],
                value=args.value,
                k=args.num_paths
            )
        except NetworkXNoPath:
            return {'error': 'No suitable path found for transfer from {} to {}.'.format(
                args['from'], args['to']
            )}, 400

        return {'result': paths}, 200


class PaymentInfoResource(Resource):
    pass


class ServiceApi:
    def __init__(self, pathfinding_service: PathfindingService) -> None:
        self.flask_app = Flask(__name__)
        self.api = Api(self.flask_app)
        self.rest_server: WSGIServer = None
        self.server_greenlet: Greenlet = None

        resources: List[Tuple[str, Resource, Dict]] = [
            ('/<token_network_address>/<channel_id>/balance', ChannelBalanceResource, {}),
            ('/<token_network_address>/<channel_id>/fee', ChannelFeeResource, {}),
            ('/<token_network_address>/paths', PathsResource, {}),
            ('/<token_network_address>/payment/info', PaymentInfoResource, {})
        ]

        for endpoint_url, resource, kwargs in resources:
            endpoint_url = API_PATH + endpoint_url
            kwargs['pathfinding_service'] = pathfinding_service
            self.api.add_resource(resource, endpoint_url, resource_class_kwargs=kwargs)

    def run(self, port: int = API_DEFAULT_PORT):
        self.rest_server = WSGIServer((API_HOST, port), self.flask_app)
        self.server_greenlet = gevent.spawn(self.rest_server.serve_forever)
