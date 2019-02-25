"""The Python implementation of the gRPC resolver server."""

from concurrent import futures
import time
import logging
from raiden.utils import sha3

import grpc

import raiden.resolver.resolver_pb2 as resolver_pb2
import raiden.resolver.resolver_pb2_grpc as resolver_pb2_grpc

_ONE_DAY_IN_SECONDS = 60 * 60 * 24


class HashResolverServicer(resolver_pb2_grpc.HashResolverServicer):
    """Provides methods that implement functionality of resolver server."""

    def __init__(self):
        pass

    def ResolveHash(self, request, context):
        response = resolver_pb2.ResolveResponse(
            preimage='7d99ad63945f9f1da98c5ad82ff8a46f7716f1385bf9944776c456c69a231d03',
        )
        return response


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


if __name__ == '__main__':
    logging.basicConfig()
    serve()
