"""
Note, these are Mocks.
We assume, that they represent up to date information.

Start NetBlockChainServer with
>>> python -c 'import raiden.blockchain; server = raiden.blockchain.NetBlockChainServer("127.0.0.11", 7777); server.serve_forever()'
"""
from utils import isaddress
from gevent.server import DatagramServer
import cPickle
from operator import methodcaller, attrgetter
from gevent import socket
from contracts import ChannelManagerContract
from ethereum import slogging
log = slogging.getLogger('blockchain')


class BlockChain(object):

    def __init__(self):
        self.block_number = 0
        self.channelmanagercontracts = dict()

    def next_block(self):
        self.block_number += 1

    def add_asset(self, asset_address):
        assert isaddress(asset_address)
        assert asset_address not in self.channelmanagercontracts
        log.trace("adding asset", addr=asset_address.encode('hex'))
        print "adding asset    addr={}".format(asset_address.encode('hex'))
        self.channelmanagercontracts[asset_address] = ChannelManagerContract(self, asset_address)

    @property
    def asset_addresses(self):
        return self.channelmanagercontracts.keys()

    def channelmanager_by_asset(self, asset_address):
        return self.channelmanagercontracts[asset_address]


class NetBlockChain(BlockChain):
    """Mock object to be used by raiden services.
    Delegates all calls to its service.
    """

    def __init__(self, host, port):
        self.service = NetBlockChainService(host, port)

    def next_block(self):
        self.service.next_block()

    @property
    def block_number(self):
        return self.service.get_block_number()

    def add_asset(self, asset_address):
        self.service.add_asset(asset_address)

    @property
    def asset_addresses(self):
        log.debug("asset_addresses", num=len(self.service.asset_addresses))
        return self.service.asset_addresses

    def channelmanager_by_asset(self, asset_address):
        return self.service.channelmanager_by_asset(asset_address)


class NetBlockChainService(object):
    """Service Layer for mock blockchain. Calls the configured instance
    over UDP (pickled).
    """

    def __init__(self, host, port):
        self.target = (host, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def call(self, method, data):
        msg = cPickle.dumps((method, data))
        self.socket.sendto(msg, self.target)
        result, _ = self.socket.recvfrom(4096)
        log.trace("call", result=repr(result))
        return cPickle.loads(result)

    def next_block(self):
        return self.call("next_block", None)

    def add_asset(self, asset_address):
        return self.call("add_asset", asset_address)

    def get_block_number(self):
        return self.call("block_number", None)

    @property
    def asset_addresses(self):
        log.debug("calling asset_addresses")
        return self.call("asset_addresses", None)

    def channelmanager_by_asset(self, asset_address):
        log.debug("calling channelmanager_by_asset", addr=asset_address.encode('hex'))
        return self.call("channelmanager_by_asset", asset_address)


class NetBlockChainServer(DatagramServer):
    """DatagramServer that proxies a single instance of a BlockChain.
    """

    def __init__(self, host, port):
        super(NetBlockChainServer, self).__init__('{}:{}'.format(host, port), handle=self.on_msg)
        self.block_number = 0
        self.channelmanagercontracts = dict()
        self.block_chain = BlockChain()

    def on_msg(self, msg, sender):
        cmd, data = cPickle.loads(msg)
        if hasattr(self.block_chain, cmd):
            if cmd in "block_number asset_addresses".split():
                call = attrgetter(cmd)
            elif data is None:
                call = methodcaller(cmd)
            else:
                call = methodcaller(cmd, data)
        else:
            log.error("no such attribute on `blockchain`", attr=cmd)
            return self.respond("error", sender)
        result = call(self.block_chain)
        log.debug("on_msg", result=repr(result))
        return self.respond(result, sender)

    def respond(self, obj, recipient):
        msg = cPickle.dumps(obj)
        self.socket.sendto(msg, recipient)
