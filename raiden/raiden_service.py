import rlp
import messages
from utils import privtoaddr, isaddress, pex
from contracts import NettingChannelContract, ChannelManagerContract
import channel


class RaidenProtocol(object):

    def __init__(self, transport, discovery, raiden_service):
        self.transport = transport
        self.discovery = discovery
        self.raiden_service = raiden_service

    def send(self, receiver_address, msg):
        host_port = self.discovery.get(receiver_address)
        self.transport.send(self.raiden_service, host_port, rlp.encode(msg))

    def receive(self, msg):
        # note, we ignore the sending endpoint, as this can not be known w/ UDP
        msg = messages.deserialize(msg)
        assert msg.sender
        self.raiden_service.on_message(msg)


class AssetManager(object):

    """
    class which handles one asset
    """

    def __init__(self, raiden, asset_address):
        assert isinstance(raiden, RaidenService)
        assert isaddress(asset_address)
        self.raiden = raiden
        self.asset_address = asset_address
        self.channels = dict()  # receiver : Channel

        # create channels for contracts
        channelmanager = raiden.chain.channelmanager_by_asset(asset_address)
        assert isinstance(channelmanager, ChannelManagerContract)
        for netting_contract in channelmanager.nettingcontracts_by_address(raiden.address):
            self.add_channel(netting_contract)

        # create network graph for contract
        channelmanager = raiden.chain.channelmanager_by_asset(asset_address)
        self.channel_graph = ChannelGraph()

    def add_channel(self, contract):
        assert isinstance(contract, NettingChannelContract)
        partner = contract.partner(self.raiden.address)
        self.channels[partner] = channel.Channel(self.raiden, contract)

    @classmethod
    def get_assets_for_address(cls, chain, address):
        "get all assets for which there is a netting channel"
        asset_addresses = []
        for asset_address in chain.asset_addresses:
            channelmanager = chain.channelmanager_by_asset(asset_address)
            assert isinstance(channelmanager, ChannelManagerContract)
            if channelmanager.nettingcontracts_by_address(address):
                asset_addresses.append(asset_address)
        return asset_addresses


class RaidenService(object):

    def __init__(self, chain, privkey, transport, discovery):
        self.chain = chain
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        self.assets = dict()

    def setup_assets(self):
        # create asset managers
        for asset_address in AssetManager.get_assets_for_address(self.chain, self.address):
            self.assets[asset_address] = AssetManager(self, asset_address)

    def on_message(self, msg):
        method = 'on_%s' % msg.__class__.__name__.lower()
        getattr(self, method)(msg)

    def on_ping(self, msg):
        self.send_ack(msg)

    def on_ack(self, msg):
        pass

    def send_ack(self, msg):
        self.protocol.send(msg.sender, messages.Ack(msg.hash).sign(self.address))

    def on_rejected(self, msg):
        pass

    def on_hashlockrequest(self, msg):
        pass

    def on_hashlock(self, msg):
        pass

    def on_transfer(self, msg):
        pass

    def on_lockedtransfer(self, msg):
        pass

    def on_mediatedtransfer(self, msg):
        pass

    def on_transferrequest(self, msg):
        pass

    def on_exchangerequest(self, msg):
        pass
