import messages
from messages import SignedMessage
from utils import privtoaddr, isaddress, pex
from raiden_protocol import RaidenProtocol
from assetmanager import AssetManager
from transfermanager import TransferManager
from ethereum import slogging
import networkx as nx

log = slogging.get_logger('service')

# TODO: reevaluate names of Custom Exceptions
# base error for raiden"
class RaidenError(Exception):
    pass

class NoPathError(RaidenError):
    pass


class InvalidAddress(RaidenError):
    pass


class InvalidAmount(RaidenError):
    pass


class RaidenAPI(object):
    """
    the external interface to the service
    """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def assets(self):
        return self.raiden.assetmanagers.keys()

    def transfer(self, asset_address, amount, target, cb=None):
        asset_address = self.decode_address(asset_address, 'asset')
        target = self.decode_address(target, 'receiver')
        if amount <= 0 or type(amount) is not int:
            raise InvalidAmount('Amount not int or > 0')
        # only if a path exists, we forward the transfer to the RaidenService
        if not self.raiden.has_path(asset_address, target):
            raise NoPathError('No path to address found')
        assert asset_address in self.assets
        tm = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(tm, TransferManager)
        tm.transfer(amount, target, callback=cb)

    def request_transfer(self, asset_address, amount, target):
        assert isaddress(asset_address) and isaddress(target)
        assert asset_address in self.assets
        tm = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(tm, TransferManager)
        tm.request_transfer(amount, target)

    def exchange(self, asset_A, asset_B, amount_A=None, amount_B=None, callback=None):
        pass

    @staticmethod
    def decode_address(address, address_type):
        assert type(address_type) is str
        if not isaddress(address):
            is_valid = False
            try:
                address = address.decode('hex')
                is_valid = isaddress(address)
            except TypeError:
                pass
            if not is_valid:
                raise InvalidAddress('{} address is not valid.'.format(address_type),
                                     address_type)
        return address


class RaidenService(object):

    """ Runs a service on a node """

    def __init__(self, chain, privkey, transport, discovery):
        self.chain = chain
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol
        self.assetmanagers = dict()
        self.api = RaidenAPI(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def has_path(self, asset, target):
        assetmanager = self.assetmanagers.get(asset)
        if assetmanager is not None:
            channel = assetmanager.channelgraph.G
            if target in channel.nodes():
                return nx.has_path(channel, self.address, target)
        return False

    def setup_assets(self):
        # create asset managers
        for asset_address in AssetManager.get_assets_for_address(self.chain, self.address):
            self.assetmanagers[asset_address] = AssetManager(self, asset_address)

    def sign(self, msg):
        assert isinstance(msg, SignedMessage)
        return msg.sign(self.privkey)

    def on_message(self, msg, msghash):
        log.debug("-" * 60)
        log.debug("ON MESSAGE {} {}".format(self, msg))
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        getattr(self, method)(msg)
        log.debug("SEND ACK{} {}".format(self, msg))
        self.protocol.send_ack(msg.sender, messages.Ack(self.address, msghash))

    def on_message_failsafe(self, msg, msghash):
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        try:
            getattr(self, method)(msg)
        except messages.BaseError as error:
            self.protocol.send_ack(msg.sender, error)
        else:
            self.protocol.send_ack(msg.sender, messages.Ack(self.address, msghash))

    def send(self, recipient, msg):
        # assert msg.sender
        assert isaddress(recipient)
        self.protocol.send(recipient, msg)

    def on_baseerror(self, msg):
        pass

    def on_ping(self, msg):
        pass  # ack already sent, activity monitor should have been notified in on_message

    def on_transfer(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_transfer(msg)

    on_lockedtransfer = on_transfer

    def on_mediatedtransfer(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_mediatedtransfer(msg)

    # events, that need to find a TransferTask

    def on_event_for_transfertask(self, msg):
        for am in self.assetmanagers.values():
            if msg.hashlock in am.transfermanager.transfertasks:
                am.transfermanager.transfertasks[msg.hashlock].on_event(msg)
                return True
    on_secretrequest = on_transfertimeout = on_canceltransfer = on_event_for_transfertask

    def on_secret(self, msg):
        self.on_event_for_transfertask(msg)
        for am in self.assetmanagers.values():
            am.on_secret(msg)

    def on_transferrequest(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_tranferrequest(msg)

    # other

    def on_rejected(self, msg):
        pass

    def on_hashlockrequest(self, msg):
        pass

    def on_exchangerequest(self, msg):
        pass
