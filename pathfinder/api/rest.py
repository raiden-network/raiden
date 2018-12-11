from typing import Dict, List, Optional, Tuple

import gevent
import socket
import pathfinder
import pkg_resources
from eth_utils import is_address, is_checksum_address
from flask import Flask
from flask_restful import Api, Resource, reqparse
from gevent import Greenlet
from gevent.pywsgi import WSGIServer
from networkx.exception import NetworkXNoPath

from pathfinder.config import API_DEFAULT_PORT, API_HOST, API_PATH
from pathfinder.pathfinding_service import PathfindingService
from raiden_libs.types import Address


class PathfinderResource(Resource):

    def __init__(self, pathfinding_service: PathfindingService) -> None:
        self.pathfinding_service = pathfinding_service

    def _validate_token_network_argument(
        self,
        token_network_address: str,
    ) -> Optional[Tuple[Dict, int]]:

        if not is_address(token_network_address):
            no_address_message = 'Invalid token network address: {}'
            return {'error': no_address_message.format(token_network_address)}, 400

        if not is_checksum_address(token_network_address):
            address_error = 'Token network address not checksummed: {}'
            return {'error': address_error.format(token_network_address)}, 400

        token_network = self.pathfinding_service.token_networks.get(
            Address(token_network_address),
        )
        if token_network is None:
            return {
                'error': 'Unsupported token network: {}'.format(token_network_address),
            }, 400

        return None


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
            Address(token_network_address),
        )
        if not token_network:
            return {'error': 'Token network {} not found.'.format(
                token_network_address,
            )}, 400
        try:
            paths = token_network.get_paths(
                source=args['from'],
                target=args['to'],
                value=args.value,
                k=args.num_paths,
            )
        except NetworkXNoPath:
            return {'error': 'No suitable path found for transfer from {} to {}.'.format(
                args['from'], args['to'],
            )}, 400

        return {'result': paths}, 200


class InfoResource(PathfinderResource):
    def get(self):
        ip = socket.gethostbyname(socket.gethostname())
        # this is the internal IP address, scoped out soon anyway
        settings = 'PLACEHOLDER'
        version = pkg_resources.require(pathfinder.__name__)[0].version
        operator = 'Dominik'
        message = 'This is for Paul'

        return {'ip': ip,
                'settings': settings,
                'version': version,
                'operator': operator,
                'message': message}, 200


class ServiceApi:
    def __init__(self, pathfinding_service: PathfindingService) -> None:
        self.flask_app = Flask(__name__)
        self.api = Api(self.flask_app)
        self.rest_server: WSGIServer = None
        self.server_greenlet: Greenlet = None

        resources: List[Tuple[str, Resource, Dict]] = [
            ('/<token_network_address>/paths', PathsResource, {}),
            ('/info', InfoResource, {}),
        ]

        for endpoint_url, resource, kwargs in resources:
            endpoint_url = API_PATH + endpoint_url
            kwargs['pathfinding_service'] = pathfinding_service
            self.api.add_resource(resource, endpoint_url, resource_class_kwargs=kwargs)

    def run(self, port: int = API_DEFAULT_PORT):
        self.rest_server = WSGIServer((API_HOST, port), self.flask_app)
        self.server_greenlet = gevent.spawn(self.rest_server.serve_forever)
