# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.channel import Channel
from raiden import messages
from raiden import transfermanager
from raiden.utils import isaddress
from raiden.blockchain.net_contract import NettingChannelContract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class AssetManager(object):
    """ Manages netting contracts for a given asset. """

    def __init__(self, raiden, asset_address, channel_graph):
        # avoid cyclic import
        from raiden.raiden_service import RaidenService
        assert isinstance(raiden, RaidenService)

        if not isaddress(asset_address):
            raise ValueError('asset_address must be a valid address')

        self.raiden = raiden
        self.asset_address = asset_address
        self.channels = dict()  # receiver : Channel
        self.channelgraph = channel_graph
        self.transfermanager = transfermanager.TransferManager(self, raiden)

        # get existing netting contracts
        netting_contracts = raiden.chain.contracts_by_asset_participant(
            asset_address,
            raiden.address,
        )

        for netting_contract in netting_contracts:
            self.add_channel(netting_contract)

    def add_channel(self, contract):
        assert isinstance(contract, NettingChannelContract)
        address = self.raiden.address
        balance = contract.participants[address]['deposit']

        partner = contract.partner(address)
        partner_balance = contract.participants[partner]['deposit']

        self.channels[partner] = Channel(
            self.raiden,
            contract,
            balance,
            partner,
            partner_balance,
        )

    def channel_isactive(self, address):
        network_activity = True  # FIXME
        return network_activity and self.channels[address].isopen

    def on_secret(self, msg):
        assert isinstance(msg, messages.Secret)

        for channel in self.channels.values():
            channel.claim_locked(msg.secret, msg.hashlock)
