"""The Python implementation of the gRPC resolver server."""

from concurrent import futures
from eth_utils import to_bytes,to_hex
import time
import logging
from raiden.utils import sha3

import grpc

import raiden.resolver.resolver_pb2 as resolver_pb2
import raiden.resolver.resolver_pb2_grpc as resolver_pb2_grpc
from raiden.raiden_service import RaidenService
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal



_ONE_DAY_IN_SECONDS = 60 * 60 * 24


class HashResolverServicer(resolver_pb2_grpc.HashResolverServicer):
    """Provides methods that implement functionality of resolver server."""

    def __init__(self):
        pass

    def ResolveHash(self, request, context):

        preimage = None

        x_secret = '2ff886d47b156de00d4cad5d8c332706692b5b572adfe35e6d2f65e92906806e'
        x_secret_hash = to_hex(sha3(to_bytes(hexstr=x_secret)))[2:]

        if request.hash == x_secret_hash:
                preimage=x_secret

        return resolver_pb2.ResolveResponse(
                preimage=preimage,
        )


def serve():
    port = '50051'

    with open('server.key', 'rb') as f:
        private_key = f.read()
    with open('server.crt', 'rb') as f:
        certificate_chain = f.read()

    server_credentials = grpc.ssl_server_credentials(
      ((private_key, certificate_chain,),))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    resolver_pb2_grpc.add_HashResolverServicer_to_server(
        HashResolverServicer(), server)

    server.add_secure_port('[::]:' + port, server_credentials)
    # server.add_insecure_port('[::]:' + port)
    server.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)


def reveal_secret_with_resolver(
    raiden: RaidenService,
    secret_request_event: SendSecretRequest,
) -> bool:
    try:
        if raiden.config['resolver_crt_file'] is None:
            return False

        with open(raiden.config['resolver_crt_file'], 'rb') as f:
            trusted_certs = f.read()

        credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
        grpc_channel = grpc.secure_channel(
            '{}:{}'.format(
                raiden.config['resolver_host'],
                raiden.config['resolver_port'],
            ),
            credentials,
        )
        stub = resolver_pb2_grpc.HashResolverStub(grpc_channel)
        hash_string = to_hex(secret_request_event.secrethash)[2:]
        response = stub.ResolveHash(resolver_pb2.ResolveRequest(hash=hash_string))

        if response is None or response.preimage is None or len(response.preimage) == 0:
            return False

        state_change = ReceiveSecretReveal(
            to_bytes(hexstr=response.preimage),
            secret_request_event.recipient,
        )
        raiden.handle_and_track_state_change(state_change)
        return True

    except Exception:
        return False


if __name__ == '__main__':
    logging.basicConfig()
    serve()
