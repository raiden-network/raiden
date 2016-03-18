from channelgraph import ChannelGraph
from utils import isaddress
from contracts import NettingChannelContract
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
        channel_contracts = raiden.chain.contracts_by_asset_participant(
            asset_address,
            raiden.address,
        )

        for netting_contract in channel_contracts:
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
