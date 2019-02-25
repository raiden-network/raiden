import logging

import grpc

import raiden.resolver.resolver_pb2 as resolver_pb2
import raiden.resolver.resolver_pb2_grpc as resolver_pb2_grpc


def run():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = resolver_pb2_grpc.HashResolverStub(channel)
        response = stub.ResolveHash(resolver_pb2.ResolveRequest(hash='0x123123123123'))
        assert response is not None
        assert response.preimage is not None
        print(response)


if __name__ == '__main__':
    logging.basicConfig()
    run()
