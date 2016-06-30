# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.channel import Channel, ChannelEndState
from raiden.transfermanager import TransferManager
from raiden.utils import isaddress, pex

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
        self.raiden = raiden

        transfermanager = TransferManager(self)
        self.channels = dict()  #: Dict[(partner_address, channel object)]
        self.transfermanager = transfermanager  #: handle's raiden transfers

    def register_channel_by_address(self, netting_contract_address_bin, reveal_timeout):
        """ Register a deployed channel.

        Args:
            netting_contract_address_bin (bin): The netting contract address.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        our_address = self.raiden.address

        channel_details = self.raiden.chain.netting_contract_detail(
            self.asset_address,
            netting_contract_address_bin,
            our_address,
        )

        self.register_channel(netting_contract_address_bin, channel_details, reveal_timeout)

    def register_channel(self, netting_contract_address_bin, channel_details, reveal_timeout):
        """ Register a new channel.

        Args:
            netting_contract_address_bin (bin): The netting contract address.
            channel_details (dict): A dictionary containing the addresses of
                the channel participants and their balances.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
        )

        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
        )

        channel = Channel(
            self.raiden.chain,

            self.asset_address,
            netting_contract_address_bin,

            our_state,
            partner_state,

            reveal_timeout,
        )

        self.channels[partner_state.address] = channel

    def channel_isactive(self, partner_address):
        network_activity = True  # FIXME
        return network_activity and self.channels[partner_address].isopen

    def get_best_routes(self, amount, target, lock_timeout=None):
        """ Yield a two-tuple (path, channel) that can be used to mediate the
        transfer. The result is ordered from the best to worst path.
        """
        available_paths = self.channelgraph.get_shortest_paths(
            self.raiden.address,
            target,
        )

        for path in available_paths:
            assert path[0] == self.raiden.address
            assert path[1] in self.channels
            assert path[-1] == target

            partner = path[1]
            channel = self.channels[partner]

            if not channel.isopen:
                log.info('channel {} - {} is close, ignoring'.format(pex(path[0]), pex(path[1])))
                continue

            # we can't intermediate the transfer if we don't have enough funds
            if amount > channel.distributable:
                log.info('channel {} - {} doesnt have enough funds [{}], ignoring'.format(
                    pex(path[0]),
                    pex(path[1]),
                    amount,
                ))
                continue

            # Our partner won't accept a locked transfer that can expire after
            # the settlement period, otherwise the secret could be revealed
            # after channel is settled and he would lose the asset, or before
            # the minimum required.
            if lock_timeout and not channel.reveal_timeout <= lock_timeout < channel.settle_timeout:
                log.info(
                    'lock_expiration is too large, channel/path cannot be used',
                    lock_timeout=lock_timeout,
                    reveal_timeout=channel.reveal_timeout,
                    settle_timeout=channel.settle_timeout,
                    nodeid=pex(path[0]),
                    partner=pex(path[1]),
                )
                continue

            yield (path, channel)

    def has_path(self, source, target):
        """ True if there is a path from `source` to `target`. """
        return self.channelgraph.has_path(source, target)
