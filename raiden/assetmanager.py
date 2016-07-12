# -*- coding: utf8 -*-
from ethereum import slogging
from ethereum.abi import ContractTranslator

from raiden.channel import Channel, ChannelEndState
from raiden.blockchain.abi import NETTING_CHANNEL_ABI
from raiden.transfermanager import TransferManager
from raiden.tasks import LogListenerTask
from raiden.utils import isaddress, pex

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class AssetManager(object):
    """ Manages netting contracts for a given asset. """

    def __init__(self, raiden, asset_address, channel_manager_address, channel_graph):
        """
        Args:
            raiden (RaidenService): a node's service
            asset_address (address): the asset address managed by this instance
            channelgraph (networkx.Graph): a graph representing the raiden network
        """
        if not isaddress(asset_address):
            raise ValueError('asset_address must be a valid address')

        self.partneraddress_channel = dict()  #: maps the partner address to the channel instance
        self.address_channel = dict()  #: maps the channel address to the channel instance

        self.asset_address = asset_address
        self.channel_manager_address = channel_manager_address
        self.channelgraph = channel_graph
        self.raiden = raiden

        transfermanager = TransferManager(self)
        self.transfermanager = transfermanager

    def has_path(self, source, target):
        """ True if there is a path from `source` to `target`. """
        return self.channelgraph.has_path(source, target)

    def get_channel_by_partner_address(self, partner_address_bin):
        return self.partneraddress_channel[partner_address_bin]

    def get_channel_by_contract_address(self, netting_channel_address_bin):
        return self.address_channel[netting_channel_address_bin]

    def register_channel_by_address(self, netting_channel_address_bin, reveal_timeout):
        """ Register a deployed channel.

        Args:
            netting_channel_address_bin (bin): The netting contract address.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        netting_channel = self.raiden.chain.netting_channel(netting_channel_address_bin)
        self.register_channel(netting_channel, reveal_timeout)

    def register_channel(self, netting_channel, reveal_timeout):
        """ Register a new channel.

        Args:
            netting_channel (network.rpc.client.NettingChannel): The netting channel proxy.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        translator = ContractTranslator(NETTING_CHANNEL_ABI)

        # race condition:
        # - if the filter is installed after a deposit is made it could be
        # missed, to avoid that we first install the filter, then request the
        # state from the node and then poll the filter.
        # - with the above strategy the same deposit could be handled twice,
        # once from the status received from the netting contract and once from
        # the event, to avoid problems the we use the balance instead of the
        # deposit is used.
        newbalance = netting_channel.channelnewbalance_filter()
        newbalance_listener = LogListenerTask(
            newbalance,
            self.raiden.on_event,
            translator,
        )

        secretrevealed = netting_channel.channelsecretrevealed_filter()
        secretrevealed_listener = LogListenerTask(
            secretrevealed,
            self.raiden.on_event,
            translator,
        )

        channel_details = netting_channel.detail(self.raiden.address)
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
        )
        channel = Channel(
            netting_channel,

            our_state,
            partner_state,

            reveal_timeout,
            channel_details['settle_timeout'],

            self.raiden.chain.block_number,
        )

        self.partneraddress_channel[partner_state.address] = channel
        self.address_channel[netting_channel.address] = channel

        newbalance_listener.start()
        secretrevealed_listener.start()
        self.raiden.event_listeners.append(newbalance_listener)
        self.raiden.event_listeners.append(secretrevealed_listener)

    def channel_isactive(self, partner_address):
        # TODO: check if the partner's network is alive
        return self.get_channel_by_partner_address(partner_address).isopen()

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
            assert path[1] in self.partneraddress_channel
            assert path[-1] == target

            partner = path[1]
            channel = self.partneraddress_channel[partner]

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
