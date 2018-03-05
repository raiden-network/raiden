import gevent
from eth_utils import decode_hex, is_address, is_checksum_address
from flask import Flask, request
from flask_restful import Api, Resource, reqparse
from gevent import Greenlet
from gevent.pywsgi import WSGIServer

from pathfinder.config import API_DEFAULT_PORT, API_HOST, API_PATH
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.lock import Lock
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.utils.exceptions import InvalidAddressChecksumError


class PathfinderResource(Resource):
    def __init__(self, pathfinding_service: PathfindingService):
        self.pathfinding_service = pathfinding_service


class ChannelBalanceResource(PathfinderResource):

    def put(self):
        body = request.json

        balance_proof_json = body.get('balance_proof')
        if balance_proof_json is None:
            return {'error': 'No balance proof specified.'}, 400
        try:
            balance_proof = BalanceProof(
                nonce=balance_proof_json['nonce'],
                transferred_amount=balance_proof_json['transferred_amount'],
                locksroot=decode_hex(balance_proof_json['locksroot']),
                channel_id=balance_proof_json['channel_identifier'],
                token_network_address=balance_proof_json['token_network_address'],
                chain_id=balance_proof_json['chain_id'],
                additional_hash=decode_hex(balance_proof_json['additional_hash']),
                signature=decode_hex(balance_proof_json['signature'])
            )
        except InvalidAddressChecksumError as err:
            return {'error': str(err)}, 400
        except KeyError as err:
            return {'error': 'Invalid balance proof format. Missing parameter: {}'.format(
                str(err)
            )}, 400

        locks_json = body.get('locks')
        if locks_json is None or not isinstance(locks_json, list):
            return {'error': 'No lock list specified.'}, 400
        locks = [
            Lock(
                amount_locked=lock_json['amount_locked'],
                expiration=lock_json['expiration'],
                hashlock=decode_hex(lock_json['hashlock'])
            )
            for lock_json in locks_json
        ]

        # Note: signature and lock checks are performed by the TokenNetwork.
        token_network = self.pathfinding_service.token_networks.get(
            balance_proof.token_network_address
        )
        if token_network is None:
            return {'error': 'Unsupported token network: {}'.format(
                balance_proof.token_network_address
            )}, 400

        try:
            token_network.update_balance(balance_proof, locks)
        except ValueError as err:
            return {'error': str(err)}, 400


class ChannelFeeResource(PathfinderResource):
    def put(self, channel_id: str):
        pass


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

    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('from', type=str, help='Payment initiator address.')
        parser.add_argument('to', type=str, help='Payment target address.')
        parser.add_argument('value', type=int, help='Maximum payment value.')
        parser.add_argument('num_paths', type=int, help='Number of paths requested.')

        args = parser.parse_args()
        error = self._validate_args(args)
        if error is not None:
            return error


class PaymentInfoResource(Resource):
    def __init__(self):
        pass


class ServiceApi:
    def __init__(self, pathfinding_service: PathfindingService):
        self.flask_app = Flask(__name__)
        self.api = Api(self.flask_app)
        self.rest_server: WSGIServer = None
        self.server_greenlet: Greenlet = None

        resources = [
            ('/balance', ChannelBalanceResource, {}),
            ('/channels/<channel_id>/fee', ChannelFeeResource, {}),
            ('/paths', PathsResource, {}),
            ('/payment/info', PaymentInfoResource, {})
        ]

        for endpoint_url, resource, kwargs in resources:
            endpoint_url = API_PATH + endpoint_url
            kwargs['pathfinding_service'] = pathfinding_service
            self.api.add_resource(resource, endpoint_url, resource_class_kwargs=kwargs)

    def run(self, port: int = API_DEFAULT_PORT):
        self.rest_server = WSGIServer((API_HOST, port), self.flask_app)
        self.server_greenlet = gevent.spawn(self.rest_server.serve_forever)
