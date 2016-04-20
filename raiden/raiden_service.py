# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.assetmanager import AssetManager
from raiden.channelgraph import ChannelGraph
from raiden.channel import Channel, ChannelEndState
from raiden import messages
from raiden.raiden_protocol import RaidenProtocol
from raiden.transfermanager import TransferManager
from raiden.utils import privtoaddr, isaddress, pex


log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


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
        transfer_manager = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(transfer_manager, TransferManager)
        transfer_manager.transfer(amount, target)

    def request_transfer(self, asset_address, amount, target):
        assert isaddress(asset_address) and isaddress(target)
        assert asset_address in self.assets
        transfer_manager = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(transfer_manager, TransferManager)
        transfer_manager.request_transfer(amount, target)

    def exchange(self, asset_a, asset_b, amount_a=None, amount_b=None, callback=None):  # pylint: disable=too-many-arguments
        pass


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

    def setup_assets(self, asset_list, min_locktime):
        """ For each `asset` in `asset_list` create a corresponding
        `AssetManager`, and for each open channel that this node has create a
        corresponding `Channel`.

        Args:
            asset_list (List[address]): A list of asset addresses that need to
            be considered.
        """
        for asset_address in asset_list:
            # create network graph for contract
            edges = self.chain.addresses_by_asset(asset_address)
            channel_graph = ChannelGraph(edges)

            asset_manager = AssetManager(self, asset_address, channel_graph)
            self.assetmanagers[asset_address] = asset_manager

            netting_address = self.chain.nettingaddresses_by_asset_participant(
                asset_address,
                self.address,
            )

            for nettingcontract_address in netting_address:
                channel_details = self.chain.netting_contract_detail(
                    asset_address,
                    nettingcontract_address,
                    self.address,
                )

                our_state = ChannelEndState(
                    self.address,
                    channel_details['our_balance'],
                )

                partner_state = ChannelEndState(
                    channel_details['partner_address'],
                    channel_details['partner_balance'],
                )

                channel = Channel(
                    self.chain,
                    asset_address,
                    nettingcontract_address,
                    our_state,
                    partner_state,
                    min_locktime=min_locktime,
                )

                asset_manager.add_channel(channel_details['partner_address'], channel)

    def sign(self, msg):
        assert isinstance(msg, messages.SignedMessage)
        return msg.sign(self.privkey)

    def on_message(self, msg, msghash):
        log.debug('ON MESSAGE {} {}'.format(pex(self.address), msg))
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        getattr(self, method)(msg)
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
        asset_manager = self.assetmanagers[msg.asset]
        asset_manager.transfermanager.on_transfer(msg)

    on_lockedtransfer = on_directtransfer = on_transfer

    def on_mediatedtransfer(self, msg):
        asset_manager = self.assetmanagers[msg.asset]
        asset_manager.transfermanager.on_mediatedtransfer(msg)

    # events, that need to find a TransferTask

    def on_event_for_transfertask(self, msg):
        if isinstance(msg, messages.LockedTransfer):
            hashlock = msg.lock.hashlock
        else:
            # TransferTimeout, Secret, SecretRequest, ConfirmTransfer
            hashlock = msg.hashlock

        for asset_manager in self.assetmanagers.values():
            if hashlock in asset_manager.transfermanager.transfertasks:
                asset_manager.transfermanager.transfertasks[hashlock].on_event(msg)
                return True

    on_secretrequest = on_transfertimeout = on_canceltransfer = on_event_for_transfertask

    def on_secret(self, msg):
        self.on_event_for_transfertask(msg)
        for asset_manager in self.assetmanagers.values():
            asset_manager.on_secret(msg)

    def on_transferrequest(self, msg):
        asset_manager = self.assetmanagers[msg.asset]
        asset_manager.transfermanager.on_tranferrequest(msg)

    # other

    def on_rejected(self, msg):
        pass

    def on_hashlockrequest(self, msg):
        pass

    def on_exchangerequest(self, msg):
        pass
