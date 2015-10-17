import messages
from messages import SignedMessage
from utils import privtoaddr, isaddress, pex
from raiden_protocol import RaidenProtocol
from assetmanager import AssetManager
from transfermanager import TransferManager


class RaidenAPI(object):

    """
    the external interface to the service
    """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def assets(self):
        return self.raiden.assetmanagers.keys()

    def transfer(self, asset_address, amount, target):
        assert isaddress(asset_address) and isaddress(target)
        assert asset_address in self.assets
        tm = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(tm, TransferManager)
        tm.transfer(amount, target)

    def request_transfer(self, asset_address, amount, target):
        assert isaddress(asset_address) and isaddress(target)
        assert asset_address in self.assets
        tm = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(tm, TransferManager)
        tm.request_transfer(amount, target)

    def exchange(self, asset_A, asset_B, amount_A=None, amount_B=None, callback=None):
        pass


class RaidenService(object):

    def __init__(self, chain, privkey, transport, discovery):
        self.chain = chain
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        self.assetmanagers = dict()
        self.api = RaidenAPI(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def setup_assets(self):
        # create asset managers
        for asset_address in AssetManager.get_assets_for_address(self.chain, self.address):
            self.assetmanagers[asset_address] = AssetManager(self, asset_address)

    def sign(self, msg):
        assert isinstance(msg, SignedMessage)
        return msg.sign(self.privkey)

    def on_message(self, msg):
        print "\nON MESSAGE {} {}".format(self, msg)
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        getattr(self, method)(msg)
        print "SEND ACK{} {}".format(self, msg)
        self.protocol.send_ack(msg.sender, messages.Ack(msg.hash, self.address))

    def on_message_failsafe(self, msg):
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        try:
            getattr(self, method)(msg)
        except messages.BaseError as error:
            self.protocol.send_ack(msg.sender, error)
        else:
            self.protocol.send_ack(msg.sender, messages.Ack(msg.hash, self.address))

    def send(self, recipient, msg):
#        assert msg.sender
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
