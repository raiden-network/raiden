# -*- coding: utf8 -*-
import cPickle

from gevent import socket
from ethereum import slogging

log = slogging.getLogger('raiden.rpc.client')  # pylint: disable=invalid-name


class BlockChainClient(object):
    """ Client for a BlockChainServer/BlockChainMockServer. """

    def __init__(self, host, port):
        self.target = (host, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _call(self, method, data):
        log.debug(
            'rpc call',
            target=self.target,
            method=method,
            # data=data,  - might be binary
        )

        msg = cPickle.dumps((method, data))
        self.socket.sendto(msg, self.target)
        pickled_result, _ = self.socket.recvfrom(4096)
        result = cPickle.loads(pickled_result)

        log.trace('call', result=repr(result))

        if isinstance(result, Exception):
            raise result

        return result

    def get_next_block(self):
        return self._call('next_block', None)

    def get_block_number(self):
        return self._call('block_number', None)

    def get_asset_addresses(self):
        return self._call('asset_addresses', None)

    def get_contracts_by_asset_participant(self, asset_address, participant_address):  # pylint: disable=invalid-name
        return self._call(
            'contracts_by_asset_participant',
            (asset_address, participant_address)
        )

    def new_channel_contract(self, asset_address):
        return self._call('new_channel_contract', asset_address)

    def new_channel(self, asset_address, peer1, peer2):
        return self._call(
            'new_channel',
            (asset_address, peer1, peer2),
        )


class BlockChainService(object):
    """ Class with an interface compatible with local BlockChain. """

    def __init__(self, service_client):
        self.service = service_client

    def next_block(self):
        self.service.get_next_block()

    @property
    def block_number(self):
        return self.service.get_block_number()

    @property
    def asset_addresses(self):
        addresses = self.service.get_asset_addresses()
        log.debug('asset_addresses', num=len(addresses))
        return addresses

    def new_channel_contract(self, asset_address):
        self.service.new_channel_contract(asset_address)

    def contracts_by_asset_participant(self, asset_address, participant_address):
        return self.service.get_contracts_by_asset_participant(asset_address, participant_address)

    def new_channel(self, asset_address, peer1, peer2):
        return self.service.new_channel(asset_address, peer1, peer2)
