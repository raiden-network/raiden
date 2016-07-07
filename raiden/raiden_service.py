# -*- coding: utf8 -*-
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder, quantity_encoder

from raiden.assetmanager import AssetManager
from raiden.blockchain.abi import CHANNEL_MANAGER_ABI, NETTING_CHANNEL_ABI
from raiden.blockchain.events import channelnew_filter, channelnewbalance_filter
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
        self.managers_by_asset_address = dict()  # Dict[(address, AssetManager)]: maps the _asset_ address to the corresponding manager
        self.managers_by_address = dict()  # Dict[(address, AssetManager)]: maps the _manager_ address to the corresponding manager
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

    def get_or_create_asset_manager(self, asset_address_bin, channel_manager_address_bin):
        """ Return the AssetManager for the given `asset_address_bin`. """
        if asset_address_bin not in self.managers_by_asset_address:
            edges = self.chain.addresses_by_asset(asset_address_bin)
            channel_graph = ChannelGraph(edges)

            asset_manager = AssetManager(
                self,
                asset_address_bin,
                channel_manager_address_bin,
                channel_graph,
            )
            self.managers_by_asset_address[asset_address_bin] = asset_manager
            self.managers_by_address[channel_manager_address_bin] = asset_manager

        return self.managers_by_asset_address[asset_address_bin]

    def get_manager_by_asset_address(self, asset_address_bin):
        return self.managers_by_asset_address[asset_address_bin]

    def get_manager_by_address(self, manager_address_bin):
        return self.managers_by_address[manager_address_bin]

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
        for asset_manager in self.managers_by_asset_address.values():
            task = asset_manager.transfermanager.transfertasks.get(hashlock)

            if task is not None:
                task.on_event(message)
                return True

        return False

    def register_asset(self, asset_address_bin, channel_manager_address_bin):
        """ Discover and register the channels for the given asset. """

        if not self.chain.code_exists(asset_address_bin.encode('hex')):
            raise ValueError('Invalid address, does not contain code')

        translator = ContractTranslator(CHANNEL_MANAGER_ABI)

        # first create the filter then call the contract, this could result in
        # duplicated netting contracts
        filter_id = channelnew_filter(
            channel_manager_address_bin,
            self.address,
            self.chain.client,
        )

        all_netting_contracts = self.chain.nettingaddresses_by_asset_participant(
            asset_address_bin,
            self.address,
        )

        channel_listener = LogListenerTask(
            self.chain.client,
            filter_id,
            self.on_event,
            translator,
        )
        channel_listener.start()
        self.event_listeners.append(channel_listener)

        asset_manager = self.get_or_create_asset_manager(
            asset_address_bin,
            channel_manager_address_bin,
        )
        for netting_contract_address in all_netting_contracts:
            asset_manager.register_channel_by_address(
                netting_contract_address,
                self.config['reveal_timeout'],
            )

    def stop(self):
        for listener in self.event_listeners:
            listener.stop_event.set(True)

            self.chain.client.call(
                'eth_uninstallFilter',
                quantity_encoder(listener.filter_id),
            )


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

        else:
            log.error('Unknow event {}'.format(repr(event)))

    def event_channelnew(self, manager_address, event):  # pylint: disable=unused-argument
        log.info(
            'New channel created',
            channel_address=event['nettingChannel'],
            manager_address=encode_hex(manager_address),
        )

        address = self.raiden.address
        client = self.raiden.chain.client
        translator = ContractTranslator(NETTING_CHANNEL_ABI)
        netting_channel_address_bin = address_decoder(event['nettingChannel'])

        newbalance_filter_id = channelnewbalance_filter(
            netting_channel_address_bin,
            address,
            client,
        )

        newbalance_listener = LogListenerTask(
            client,
            newbalance_filter_id,
            self.on_event,
            translator,
        )

        # race condition:
        # - if the filter is installed after a deposit is made it could be
        # missed, to avoid that we first install the filter, then request the
        # state from the node and then poll the filter.
        # - with the above strategy the same deposit could be handled twice,
        # once from the status received from the netting contract and once from
        # the event, to avoid problems the we use the balance instead of the
        # deposit is used.
        asset_manager = self.raiden.get_manager_by_address(manager_address)
        asset_manager.register_channel_by_address(
            netting_channel_address_bin,
            self.raiden.config['reveal_timeout'],
        )

        newbalance_listener.start()
        self.raiden.event_listeners.append(newbalance_listener)

    def event_channelnewbalance(self, netting_contract_address_bin, event):
        asset_address_bin = address_decoder(event['assetAddress'])

        participant_address_bin = address_decoder(event['participant'])

        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_contract_address(netting_contract_address_bin)

        channel_state = channel.get_state_for(participant_address_bin)

        if channel_state.contract_balance != event['balance']:
            channel_state.update_contract_balance(event['balance'])

    def event_secret_revealed(self, netting_contract_address_bin, event):
        # TODO:
        # - find the corresponding channel for the hashlock and claim it
        pass
