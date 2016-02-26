from channelgraph import ChannelGraph
from utils import isaddress
from contracts import NettingChannelContract, ChannelManagerContract
import messages
import transfermanager
import raiden_service
import channel
from ethereum import slogging
log = slogging.getLogger("assetmanager")


class AssetManager(object):

    """
    class which handles services for one asset
    """

    def __init__(self, raiden, asset_address):
        assert isinstance(raiden, raiden_service.RaidenService)
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
        self.channelgraph = ChannelGraph(channelmanager)

        # TransferManager for asset
        self.transfermanager = transfermanager.TransferManager(self)

    def add_channel(self, contract):
        assert isinstance(contract, NettingChannelContract)
        partner = contract.partner(self.raiden.address)
        self.channels[partner] = channel.Channel(self.raiden, contract)

    def channel_isactive(self, address):
        network_activity = True  # FIXME
        return network_activity and self.channels[address].isopen

    def on_secret(self, msg):
        assert isinstance(msg, messages.Secret)
        for c in self.channels.values():
            c.claim_locked(msg.secret, msg.hashlock)

    @classmethod
    def get_assets_for_address(cls, chain, address):
        "get all assets for which there is a netting channel"
        asset_addresses = []
        for asset_address in chain.asset_addresses:
            channelmanager = chain.channelmanager_by_asset(asset_address)
            assert isinstance(channelmanager, ChannelManagerContract)
            if channelmanager.nettingcontracts_by_address(address):
                asset_addresses.append(asset_address)
            else:
                log.warning("nettingcontracts_by_address failed for", address=address.encode('hex'))
        log.debug("returning", result=asset_addresses)
        return asset_addresses
