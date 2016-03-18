# -*- coding: utf8 -*-
"""
This module implements a simple datagram server that can be used by multiple
nodes to access the blockchain state.

A server can be started by running::

    python -m raiden.rpc.server 127.0.0.11 7777
"""
import cPickle
from operator import attrgetter, methodcaller

from gevent.server import DatagramServer
from ethereum import slogging

from raiden.utils import isaddress
from raiden.blockchain.net_contract import NettingChannelContract

log = slogging.getLogger('raiden.rpc.server')  # pylint: disable=invalid-name


class BlockChainMock(object):
    ''' A mock block chain, the user can assume that this mock represents
    up-to-date information.

    The actions that the user can perform on the blockchain are:

        - Transfer money to a contract/channel to create it
        - Create a new channel, by executing an exiting contract

        - Call a method in an existing channel (close and settle)
        - List existing  channels for a given address (?)

    Note:
        Useful for testing
    '''

    def __init__(self):
        self.block_number = 0
        self.asset_channelhash = dict()

    def next_block(self):
        """ Equivalent to the mining of a new block.

        Note:
            This method does not create any representation of the new block, it
            just increases current block number. This is necessary since the
            channel contract needs the current block number to decide if the
            closing of a channel can be closed or not.
        """
        self.block_number += 1

    def new_channel_contract(self, asset_address):
        """ The equivalent of creating a new contract that will manage channels
        in the blockchain.

        Raises:
            ValueError: If asset_address is not a valid address or is already registered.
        """
        if not isaddress(asset_address):
            raise ValueError('The asset must be a valid address')

        if asset_address in self.asset_channelhash:
            raise ValueError('This asset already has a registered contract')

        self.asset_channelhash[asset_address] = dict()

    def new_channel(self, asset_address, peer1, peer2):
        """ Creates a new channel between peer1 and peer2.

        Raises:
            ValueError: If peer1 or peer2 is not a valid address.
        """
        if not isaddress(peer1):
            raise ValueError('The pee1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        channel = NettingChannelContract(asset_address, peer1, peer2)

        hash_ = ''.join(sorted((peer1, peer2)))  # fixme replace by sha3

        hash_channel = self.asset_channelhash[asset_address]
        hash_channel[hash_] = channel

        return channel

    @property
    def asset_addresses(self):
        """ Return all assets addresses that have a contract. """
        return self.asset_channelhash.keys()

    def contracts_by_asset_participant(self, asset_address, participant_address):
        """ Return all channels for a given asset that `participant_address` is a participant. """
        manager = self.asset_channelhash[asset_address]

        return [
            channel
            for channel in manager.values()
            if participant_address in channel.participants
        ]


class BlockChainMockServer(DatagramServer):
    """ A simple RPC server on top of a mock blockchain.

    This server uses pickle serialization to receive and send data, the request
    format is a two-tuple with `(attribute_or_method, arguments)`, the
    equivalent attribute or method is acessed or called and the result is sent
    back pickled to the caller.

    Note:
        Useful for testing
    """

    def __init__(self, host, port):
        super(BlockChainMockServer, self).__init__('{}:{}'.format(host, port), handle=self.on_msg)
        self.block_chain = BlockChainMock()

    def on_msg(self, msg, sender):
        cmd, data = cPickle.loads(msg)
        log.debug('msg received', cmd=cmd)

        if hasattr(self.block_chain, cmd):
            if cmd in ['block_number', 'asset_addresses']:
                call = attrgetter(cmd)
            elif data is None:
                call = methodcaller(cmd)  # pylint: disable=redefined-variable-type
            elif isinstance(data, tuple):
                call = methodcaller(cmd, *data)
            else:
                call = methodcaller(cmd, data)
        else:
            log.error('no such attribute on `blockchain`', attr=cmd)
            return self.respond('error', sender)

        try:
            result = call(self.block_chain)
        except Exception as exc:  # pylint: disable=broad-except
            log.exception('')
            result = exc

        return self.respond(result, sender)

    def respond(self, obj, recipient):
        msg = cPickle.dumps(obj)
        self.socket.sendto(msg, recipient)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('port', type=int)

    args = parser.parse_args()
    host, port = args.host, args.port

    server = BlockChainMockServer(host, port)
    server.serve_forever()


if __name__ == '__main__':
    slogging.configure(':debug')
    main()
