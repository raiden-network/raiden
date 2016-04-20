# -*- coding: utf8 -*-
from ethereum import slogging

from raiden import messages
from raiden.transfermanager import TransferManager
from raiden.utils import isaddress

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class AssetManager(object):
    """ Manages netting contracts for a given asset. """

    def __init__(self, raiden, asset_address, channel_graph):
        """
        Args:
            raiden (RaidenService): a node's service
            asset_address (address): the asset address managed by this instance
            channelgraph (networkx.Graph): a graph representing the raiden network
        """
        if not isaddress(asset_address):
            raise ValueError('asset_address must be a valid address')

        self.asset_address = asset_address
        self.channelgraph = channel_graph

        transfermanager = TransferManager(self, raiden)
        self.channels = dict()  #: mapping form partner_address -> channel object
        self.transfermanager = transfermanager  #: handle's raiden transfers

    def add_channel(self, partner_address, channel):
        self.channels[partner_address] = channel

    def channel_isactive(self, partner_address):
        network_activity = True  # FIXME
        return network_activity and self.channels[partner_address].isopen

    def on_secret(self, msg):
        assert isinstance(msg, messages.Secret)

        for channel in self.channels.values():
            channel.claim_locked(msg.secret)
