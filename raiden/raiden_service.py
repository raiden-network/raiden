# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.assetmanager import AssetManager
from raiden.channelgraph import ChannelGraph
from raiden.messages import Ack, SignedMessage
from raiden.encoding import messages
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


class RaidenService(object):  # pylint: disable=too-many-instance-attributes
    """ A Raiden node. """

    def __init__(self, chain, privkey, transport, discovery, config):  # pylint: disable=too-many-arguments
        self.assetmanagers = dict()

        self.chain = chain
        self.config = config
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol

        message_handler = RaidenMessageHandler(self)
        event_handler = RaidenEventHandler(self)

        self.api = RaidenAPI(self)
        self.event_handler = event_handler
        self.message_handler = message_handler

        self.on_message = message_handler.on_message

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def get_or_create_asset_manager(self, asset_address, channel_manager_address):
        """ Return the AssetManager for the given `asset_address`. """
        if asset_address not in self.assetmanagers:
            edges = self.chain.addresses_by_asset(asset_address)
            channel_graph = ChannelGraph(edges)

            asset_manager = AssetManager(
                self,
                asset_address,
                channel_manager_address,
                channel_graph,
            )
            self.assetmanagers[asset_address] = asset_manager

        return self.assetmanagers[asset_address]

    def get_asset_manager(self, asset_address):
        return self.assetmanagers[asset_address]

    def sign(self, message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError('{} is not signable.'.format(repr(message)))

        message.sign(self.privkey)

    def send(self, recipient, message):
        """ Send `message` to `recipient` using the raiden protocol.

        The protocol will take care of resending the message on a given
        interval until an Acknowledgment is received or a given number of
        tries.
        """

        if not isaddress(recipient):
            raise ValueError('recipient is not a valid address.')

        self.protocol.send(recipient, message)

    def send_and_wait(self, recipient, message, timeout, event):
        """ Send `message` to `recipient` and wait for the response or `timeout`.

        Args:
            recipient (address): The address of the node that will receive the
                message.
            transfer: The transfer message.
            timeout (float): How long should we wait for a response from `recipient`.
            event (gevent.event.AsyncResult): Event that will receive the result.

        Returns:
            None: If the wait timed out
            object: The result from the event
        """
        self.send(recipient, message)
        return event.wait(timeout)

    def message_for_task(self, message, hashlock):
        for asset_manager in self.assetmanagers.values():
            task = asset_manager.transfermanager.transfertasks.get(hashlock)

            if task is not None:
                task.on_event(message)
                return True

        return False

    def register_asset(self, asset_address_bin, channel_manager_address):
        """ Discover and register the channels for the given asset. """

        if not self.chain.code_exists(asset_address_bin.encode('hex')):
            raise ValueError('Invalid address, does not contain code')

        asset_manager = self.get_or_create_asset_manager(
            asset_address_bin,
            channel_manager_address,
        )

        all_netting_contracts = self.chain.nettingaddresses_by_asset_participant(
            asset_address_bin,
            self.address,
        )

        for netting_contract_address in all_netting_contracts:
            asset_manager.register_channel_by_address(
                netting_contract_address,
                self.config['reveal_timeout'],
            )

    def stop(self):
        # TODO:
        # - uninstall all the filters
        pass


class RaidenAPI(object):
    """ CLI interface. """

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

        asset_manager = self.raiden.get_asset_manager(asset_address)

        if not isaddress(asset_address) or asset_address not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        if not asset_manager.has_path(self.raiden.address, target):
            raise NoPathError('No path to address found')

        transfer_manager = self.raiden.assetmanagers[asset_address].transfermanager
        transfer_manager.transfer(amount, target, callback=callback)


class RaidenMessageHandler(object):
    """ Class responsable to handle the protocol messages.

    Note:
        This class is not intented to be used standalone, use RaidenService
        instead.
    """
    def __init__(self, raiden):
        self.raiden = raiden

    def on_message(self, message, msghash):
        """ Handles `message` and sends a ACK on success. """
        cmdid = message.cmdid

        # using explicity dispatch to make the code grepable
        if cmdid == messages.ACK:
            pass

        elif cmdid == messages.PING:
            self.message_ping(message)

        elif cmdid == messages.SECRETREQUEST:
            self.message_secretrequest(message)

        elif cmdid == messages.SECRET:
            self.message_secret(message)

        elif cmdid == messages.DIRECTTRANSFER:
            self.message_directtransfer(message)

        elif cmdid == messages.MEDIATEDTRANSFER:
            self.message_mediatedtransfer(message)

        elif cmdid == messages.REFUNDTRANSFER:
            self.message_refundtransfer(message)

        elif cmdid == messages.TRANSFERTIMEOUT:
            self.message_transfertimeout(message)

        elif cmdid == messages.CONFIRMTRANSFER:
            self.message_confirmtransfer(message)

        else:
            raise Exception("Unknow cmdid '{}'.".format(cmdid))

        ack = Ack(
            self.raiden.address,
            msghash,
        )

        self.raiden.protocol.send_ack(
            message.sender,
            ack,
        )

    def message_ping(self, message):
        pass

    def message_confirmtransfer(self, message):
        pass

    def message_secretrequest(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_secret(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_refundtransfer(self, message):
        self.raiden.message_for_task(message, message.lock.hashlock)

    def message_transfertimeout(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_directtransfer(self, message):
        asset_manager = self.raiden.assetmanagers[message.asset]
        asset_manager.transfermanager.on_directtransfer_message(message)

    def message_mediatedtransfer(self, message):
        asset_manager = self.raiden.assetmanagers[message.asset]
        asset_manager.transfermanager.on_mediatedtransfer_message(message)


class RaidenEventHandler(object):
    """ Class responsable to handle all the blockchain events.

    Note:
        This class is not intented to be used standalone, use RaidenService
        instead.
    """

    def __init__(self, raiden):
        self.raiden = raiden

    def event_open_channel(self, netting_contract_address_bin, event):
        asset_address_bin = event['assetAddress'].decode('hex')
        asset_manager = self.raiden.get_asset_manager(asset_address_bin)

        if event['participant1'].decode('hex') == self.raiden.address:
            channel_details = {
                'our_address': event['participant1'].decode('hex'),
                'our_deposit': event['deposit1'],
                'partner_address': event['participant2'].decode('hex'),
                'partner_deposit': event['deposit2'],
                'settle_timeout':  event['settleTimeout'],
            }
        else:
            channel_details = {
                'our_address': event['participant2'].decode('hex'),
                'our_deposit': event['deposit2'],
                'partner_address': event['participant1'].decode('hex'),
                'partner_deposit': event['deposit1'],
                'settle_timeout':  event['settleTimeout'],
            }

        asset_manager.register_channel(
            netting_contract_address_bin,
            channel_details,
            self.raiden.app.config['reveal_timeout'],
        )

    def event_secret_revealed(self, netting_contract_address_bin, event):
        # TODO:
        # - find the corresponding channel for the hashlock and claim it
        pass
