import logging

import grpc

import raiden.resolver.resolver_pb2 as resolver_pb2
import raiden.resolver.resolver_pb2_grpc as resolver_pb2_grpc


def run():

    host = 'localhost'
    port = 50051

    with open('server.crt', 'rb') as f:
        trusted_certs = f.read()

    credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    # with grpc.insecure_channel('localhost:50051') as channel:
    channel = grpc.secure_channel('{}:{}'.format(host, port), credentials)
    stub = resolver_pb2_grpc.HashResolverStub(channel)
    response = stub.ResolveHash(resolver_pb2.ResolveRequest(hash='0x123123123123'))
    assert response is not None
    assert response.preimage is not None
    print(response)


if __name__ == '__main__':
    logging.basicConfig()
    run()
