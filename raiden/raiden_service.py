# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.assetmanager import AssetManager
from raiden.channelgraph import ChannelGraph
from raiden.channel import Channel, ChannelEndState
from raiden import messages
from raiden.raiden_protocol import RaidenProtocol
from raiden.utils import privtoaddr, isaddress, pex


log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def safe_address_decode(address):
    try:
        address = address.decode('hex')
    except TypeError:
        pass

    return address


class RaidenError(Exception):
    pass


class NoPathError(RaidenError):
    pass


class InvalidAddress(RaidenError):
    pass


class InvalidAmount(RaidenError):
    pass


class RaidenAPI(object):
    """ The external interface to the service. """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def assets(self):
        return self.raiden.assetmanagers.keys()

    def transfer(self, asset_address, amount, target, callback=None):
        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        asset_address = safe_address_decode(asset_address)
        target = safe_address_decode(target)

        if not isaddress(asset_address) or asset_address not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        if not self.raiden.has_path(asset_address, target):
            raise NoPathError('No path to address found')

        transfer_manager = self.raiden.assetmanagers[asset_address].transfermanager
        transfer_manager.transfer(amount, target, callback=callback)

    def request_transfer(self, asset_address, amount, target):
        if not isaddress(asset_address) or asset_address not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        transfer_manager = self.raiden.assetmanagers[asset_address].transfermanager
        transfer_manager.request_transfer(amount, target)

    def exchange(self, asset_a, asset_b, amount_a=None, amount_b=None, callback=None):  # pylint: disable=too-many-arguments
        pass


class RaidenService(object):
    """ Runs a service on a node """

    def __init__(self, chain, privkey, transport, discovery, config):  # pylint: disable=too-many-arguments
        self.chain = chain
        self.config = config
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol
        self.assetmanagers = dict()
        self.api = RaidenAPI(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def setup_asset(self, asset_address, reveal_timeout):
        """ Initialize a `AssetManager`, and for each open channel that this
        node has create a corresponding `Channel`.

        Args:
            asset_address (address): A list of asset addresses that need to
                be considered.
            reveal_timeout (int): Minimum number of blocks required for the
                settling of a netting contract.
        """
        netting_address = self.chain.nettingaddresses_by_asset_participant(
            asset_address,
            self.address,
        )

        asset_manager = self.get_or_create_asset_manager(asset_address)

        for netting_contract_address in netting_address:
            self.setup_channel(
                asset_manager,
                asset_address,
                netting_contract_address,
                reveal_timeout,
            )

    def get_or_create_asset_manager(self, asset_address):
        """ Return the AssetManager for the given `asset_address`. """
        if asset_address not in self.assetmanagers:
            edges = self.chain.addresses_by_asset(asset_address)
            channel_graph = ChannelGraph(edges)

            asset_manager = AssetManager(self, asset_address, channel_graph)
            self.assetmanagers[asset_address] = asset_manager

        return self.assetmanagers[asset_address]

    def setup_channel(self, asset_manager, asset_address, netting_contract_address, reveal_timeout):
        """ Initialize the Channel for the given netting contract. """

        channel_details = self.chain.netting_contract_detail(
            asset_address,
            netting_contract_address,
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
            netting_contract_address,
            our_state,
            partner_state,
            reveal_timeout,
        )

        asset_manager.add_channel(channel_details['partner_address'], channel)

    def has_path(self, asset, target):
        if asset not in self.assetmanagers:
            return False

        graph = self.assetmanagers[asset].channelgraph
        return graph.has_path(self.address, target)

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
