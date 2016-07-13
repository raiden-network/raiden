# -*- coding: utf8 -*-
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder

from raiden.assetmanager import AssetManager
from raiden.blockchain.abi import CHANNEL_MANAGER_ABI
from raiden.channelgraph import ChannelGraph
from raiden.tasks import LogListenerTask
from raiden.encoding import messages
from raiden.messages import Ack, SignedMessage
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
        self.managers_by_asset_address = dict()
        self.managers_by_address = dict()
        self.event_listeners = list()

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
        self.on_event = event_handler.on_event

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def get_manager_by_asset_address(self, asset_address_bin):
        return self.managers_by_asset_address[asset_address_bin]

    def get_manager_by_address(self, manager_address_bin):
        return self.managers_by_address[manager_address_bin]

    def find_channel_by_address(self, netting_channel_address_bin):
        for manager in self.managers_by_address.itervalues():
            channel = manager.address_channel.get(netting_channel_address_bin)

            if channel is not None:
                return channel

        raise ValueError('unknow channel {}'.format(encode_hex(netting_channel_address_bin)))

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
        """ Sends the message to the corresponding task.

        The corresponding task is found by matching the hashlock.

        Return:
            bool: True if a correspoding task is found, False otherwise.
        """
        for asset_manager in self.managers_by_asset_address.values():
            task = asset_manager.transfermanager.transfertasks.get(hashlock)

            if task is not None:
                task.on_event(message)
                return True

        return False

    def register_channel_manager(self, channel_manager):
        """ Discover and register the channels for the given asset. """
        translator = ContractTranslator(CHANNEL_MANAGER_ABI)

        # To avoid missing changes, first create the filter, call the
        # contract and then start polling.
        channelnew = channel_manager.channelnew_filter(self.address)

        all_netting_contracts = channel_manager.channels_by_participant(self.address)

        channel_listener = LogListenerTask(
            channelnew,
            self.on_event,
            translator,
        )
        channel_listener.start()
        self.event_listeners.append(channel_listener)

        asset_address_bin = channel_manager.asset_address()
        channel_manager_address_bin = channel_manager.address
        edges = channel_manager.channels_addresses()
        channel_graph = ChannelGraph(edges)

        asset_manager = AssetManager(
            self,
            asset_address_bin,
            channel_manager_address_bin,
            channel_graph,
        )
        self.managers_by_asset_address[asset_address_bin] = asset_manager
        self.managers_by_address[channel_manager_address_bin] = asset_manager

        for netting_contract_address in all_netting_contracts:
            asset_manager.register_channel_by_address(
                netting_contract_address,
                self.config['reveal_timeout'],
            )

    def stop(self):
        for listener in self.event_listeners:
            listener.stop_event.set(True)
            self.chain.uninstall_filter(listener.filter_id)


class RaidenAPI(object):
    """ CLI interface. """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def assets(self):
        return self.raiden.managers_by_asset_address.keys()

    def transfer(self, asset_address, amount, target, callback=None):
        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        asset_address_bin = safe_address_decode(asset_address)
        target = safe_address_decode(target)

        asset_manager = self.raiden.get_manager_by_asset_address(asset_address_bin)

        if not isaddress(asset_address_bin) or asset_address_bin not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        if not asset_manager.has_path(self.raiden.address, target):
            raise NoPathError('No path to address found')

        transfer_manager = self.raiden.managers_by_asset_address[asset_address_bin].transfermanager
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
        asset_manager = self.raiden.managers_by_asset_address[message.asset]
        asset_manager.transfermanager.on_directtransfer_message(message)

    def message_mediatedtransfer(self, message):
        asset_manager = self.raiden.managers_by_asset_address[message.asset]
        asset_manager.transfermanager.on_mediatedtransfer_message(message)


class RaidenEventHandler(object):
    """ Class responsable to handle all the blockchain events.

    Note:
        This class is not intented to be used standalone, use RaidenService
        instead.
    """

    def __init__(self, raiden):
        self.raiden = raiden

    def on_event(self, emmiting_contract_address, event):  # pylint: disable=unused-argument
        if event['_event_type'] == 'ChannelNew':
            self.event_channelnew(emmiting_contract_address, event)

        elif event['_event_type'] == 'ChannelNewBalance':
            self.event_channelnewbalance(emmiting_contract_address, event)

        elif event['_event_type'] == 'ChannelClosed':
            self.event_channelclosed(emmiting_contract_address, event)

        elif event['_event_type'] == 'ChannelSecretRevealed':
            self.event_channelsecretrevealed(emmiting_contract_address, event)

        else:
            log.error('Unknow event {}'.format(repr(event)))

    def event_channelnew(self, manager_address, event):  # pylint: disable=unused-argument
        log.info(
            'New channel created',
            channel_address=event['nettingChannel'],
            manager_address=encode_hex(manager_address),
        )

        netting_channel_address_bin = address_decoder(event['nettingChannel'])

        asset_manager = self.raiden.get_manager_by_address(manager_address)
        asset_manager.register_channel_by_address(
            netting_channel_address_bin,
            self.raiden.config['reveal_timeout'],
        )

    def event_channelnewbalance(self, netting_contract_address_bin, event):
        asset_address_bin = address_decoder(event['assetAddress'])
        participant_address_bin = address_decoder(event['participant'])

        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_contract_address(netting_contract_address_bin)

        # throws if the address is wrong
        channel_state = channel.get_state_for(participant_address_bin)

        if channel_state.contract_balance != event['balance']:
            channel_state.update_contract_balance(event['balance'])

    def event_channelclosed(self, netting_contract_address_bin, event):  # pylint: disable=unused-argument
        # Channel.isopen does a fresh rpc call each time, just ignore this event
        # channel = self.raiden.find_channel_by_address(netting_contract_address_bin)
        pass

    def event_channelsecretrevealed(self, netting_contract_address_bin, event):
        # TODO:
        # - find the corresponding channel for the hashlock and claim it
        # secret = event['secret']
        # hashlock = sha3(secret)
        raise NotImplementedError()
