# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.channelgraph import ChannelGraph
from raiden.channel import Channel
from raiden import messages
from raiden import transfermanager
from raiden.utils import isaddress
from raiden.blockchain.net_contract import NettingChannelContract


log = slogging.getLogger('assetmanager')  # pylint: disable=invalid-name


class AssetManager(object):
    """ Manages services for one asset. """

    def __init__(self, raiden, asset_address):
        # avoid cyclic import
        from raiden.raiden_service import RaidenService
        assert isinstance(raiden, RaidenService)

        assert isaddress(asset_address)
        self.raiden = raiden
        self.asset_address = asset_address
        self.channels = dict()  # receiver : Channel

        # create channels for contracts
        netting_contracts = raiden.chain.contracts_by_asset_participant(
            asset_address,
            raiden.address,
        )

        for netting_contract in netting_contracts:
            self.add_channel(netting_contract)

        # create network graph for contract
        all_netting_contracts = raiden.chain.contracts_by_asset(
            asset_address,
        )
        self.channelgraph = ChannelGraph(all_netting_contracts)

        # TransferManager for asset
        self.transfermanager = transfermanager.TransferManager(self)

    def add_channel(self, contract):
        assert isinstance(contract, NettingChannelContract)
        partner = contract.partner(self.raiden.address)
        self.channels[partner] = Channel(self.raiden, contract)

    def channel_isactive(self, address):
        network_activity = True  # FIXME
        return network_activity and self.channels[address].isopen

    def on_secret(self, msg):
        assert isinstance(msg, messages.Secret)

        for channel in self.channels.values():
            channel.claim_locked(msg.secret, msg.hashlock)
