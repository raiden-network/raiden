# -*- coding: utf8 -*-
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder

from raiden.assetmanager import AssetManager
from raiden.blockchain.abi import CHANNEL_MANAGER_ABI, REGISTRY_ABI
from raiden.channelgraph import ChannelGraph
from raiden.tasks import LogListenerTask
from raiden.encoding import messages
from raiden.messages import Ack, SignedMessage
from raiden.raiden_protocol import RaidenProtocol
from raiden.utils import privtoaddr, isaddress, pex
from raiden.app import DEFAULT_SETTLE_TIMEOUT, DEFAULT_REVEAL_TIMEOUT

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


class InvalidState(RaidenError):
    pass


class InsufficientFunds(RaidenError):
    pass


class RaidenService(object):  # pylint: disable=too-many-instance-attributes
    """ A Raiden node. """

    def __init__(self, chain, privkey, transport, discovery, config):  # pylint: disable=too-many-arguments
        self.registries = list()
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
        """ Return the manager for the given `asset_address_bin`.  """
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
            message: The transfer message.
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

    def register_registry(self, registry):
        """ Register the registry and intialize all the related assets and
        channels.
        """
        translator = ContractTranslator(REGISTRY_ABI)

        assetadded = registry.assetadded_filter()

        all_manager_addresses = registry.manager_addresses()

        asset_listener = LogListenerTask(
            assetadded,
            self.on_event,
            translator,
        )
        asset_listener.start()
        self.event_listeners.append(asset_listener)

        self.registries.append(registry)

        for manager_address in all_manager_addresses:
            channel_manager = self.chain.manager(manager_address)
            self.register_channel_manager(channel_manager)

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
            self.chain.uninstall_filter(listener.filter_.filter_id_raw)


class RaidenAPI(object):
    """ CLI interface. """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    @property
    def assets(self):
        """ Return a list of the assets registered with the default registry. """
        return self.raiden.chain.default_registry.asset_addresses()

    def open(self, asset_address, partner_address,
             settle_timeout=DEFAULT_SETTLE_TIMEOUT,
             reveal_timeout=DEFAULT_REVEAL_TIMEOUT):
        """ Open a channel with the peer at `partner_address`
        with the given `asset_address`.
        """
        if settle_timeout < DEFAULT_SETTLE_TIMEOUT:
            raise ValueError('Minimum `settle_timeout` is {} blocks.'.format(DEFAULT_SETTLE_TIMEOUT))
        # Obtain the channel manager
        channel_manager = self.raiden.chain.manager_by_asset(asset_address.decode('hex'))
        # Obtain the asset manager
        asset_manager = self.raiden.get_manager_by_asset_address(asset_address.decode('hex'))
        # Create a new netting channel and store its address
        netcontract_address = channel_manager.new_netting_channel(self._raiden.address,
                                                                partner_address.decode('hex'),
                                                                settle_timeout)
        # Obtain the netting channel from the address
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)

        # Register the netting channel with the asset manager
        asset_manager.register_channel(netting_channel, reveal_timeout or self.reveal_timeout)
        return netting_channel

    def deposit(self, asset_address, partner_address, amount):
        """ Deposit `amount` in the channel with the peer at `partner_address` and the
        given `asset_address` in order to be able to do transfers.
        """
        # Obtain the asset manager
        asset_manager = self.raiden.get_manager_by_asset_address(asset_address.decode('hex'))
        assert asset_manager
        # Get the address for the netting contract
        netcontract_address = asset_manager.get_channel_by_partner_address(
            partner_address.decode('hex')).external_state.netting_channel.address
        assert len(netcontract_address)

        # Obtain a reference to the asset and approve the amount for funding
        asset = self.raiden.chain.asset(asset_address.decode('hex'))
        # Check balance of asset:
        balance = asset.balance_of(self.raiden.address.encode('hex'))

        if not balance >= amount:
            raise InsufficientFunds("Not enough balance for token'{}' [{}]: have={}, need={}".format(
                asset.proxy.name(), asset_address, balance, amount
            ))
        # Approve the locking of funds
        asset.approve(netcontract_address, amount)

        # Obtain the netting channel and fund it by depositing the amount
        netting_channel = self.chain.netting_channel(netcontract_address)
        netting_channel.deposit(self.raiden.address, amount)
        return netting_channel

    def transfer(self, asset_address, amount, target, callback=None):
        """ Do a transfer with `target` with the given `amount` of `asset_address`. """
        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        asset_address_bin = safe_address_decode(asset_address)
        target_bin = safe_address_decode(target)

        asset_manager = self.raiden.get_manager_by_asset_address(asset_address_bin)

        if not isaddress(asset_address_bin) or asset_address_bin not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target_bin):
            raise InvalidAddress('target address is not valid.')

        if not asset_manager.has_path(self.raiden.address, target_bin):
            raise NoPathError('No path to address found')

        transfer_manager = self.raiden.managers_by_asset_address[asset_address_bin].transfermanager
        task = transfer_manager.transfer(amount, target_bin, callback=callback)
        task.join()

    def close(self, asset_address, partner_address):
        """ Close a channel opened with `partner_address` for the given `asset_address`. """
        asset_address_bin = safe_address_decode(asset_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(asset_address_bin) or asset_address_bin not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_partner_address(partner_address_bin)

        first_transfer = None
        if channel.received_transfers:
            first_transfer = channel.received_transfers[-1]

        second_transfer = None
        if channel.sent_transfers:
            second_transfer = channel.sent_transfers[-1]

        netting_channel = channel.external_state.netting_channel
        netting_channel.close(
            self.raiden.address,
            first_transfer,
            second_transfer,
        )

    def settle(self, asset_address, partner_address):
        """ Settle a closed channel with `partner_address` for the given `asset_address`. """
        asset_address_bin = safe_address_decode(asset_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(asset_address_bin) or asset_address_bin not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_partner_address(partner_address_bin)

        if channel.isopen:
            raise InvalidState('channel is still open.')

        netting_channel = channel.external_state.netting_channel

        if not (self.raiden.chain.client.block_number() >=
                (channel.external_state.closed_block +
                 netting_channel.detail(self.raiden.address)['settle_timeout'])):
            raise InvalidState('settlement period not over.')

        netting_channel.settle()
        return netting_channel


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
        log.info('ping received')

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
        asset_manager = self.raiden.get_manager_by_asset_address(message.asset)
        asset_manager.transfermanager.on_directtransfer_message(message)

    def message_mediatedtransfer(self, message):
        asset_manager = self.raiden.get_manager_by_asset_address(message.asset)
        asset_manager.transfermanager.on_mediatedtransfer_message(message)


class RaidenEventHandler(object):
    """ Class responsable to handle all the blockchain events.

    Note:
        This class is not intented to be used standalone, use RaidenService
        instead.
    """

    def __init__(self, raiden):
        self.raiden = raiden

    def on_event(self, emitting_contract_address, event):  # pylint: disable=unused-argument
        log.debug(
            'event received',
            type=event['_event_type'],
            contract=emitting_contract_address,
        )

        if event['_event_type'] == 'AssetAdded':
            self.event_assetadded(emitting_contract_address, event)

        elif event['_event_type'] == 'ChannelNew':
            self.event_channelnew(emitting_contract_address, event)

        elif event['_event_type'] == 'ChannelNewBalance':
            self.event_channelnewbalance(emitting_contract_address, event)

        elif event['_event_type'] == 'ChannelClosed':
            self.event_channelclosed(emitting_contract_address, event)

        elif event['_event_type'] == 'ChannelSettled':
            self.event_channelsettled(emitting_contract_address, event)

        elif event['_event_type'] == 'ChannelSecretRevealed':
            self.event_channelsecretrevealed(emitting_contract_address, event)

        else:
            log.error('Unknown event {}'.format(repr(event)))

    def event_assetadded(self, registry_address, event):
        manager_address = address_decoder(event['channelManagerAddress'])
        manager = self.raiden.chain.manager(manager_address)
        self.raiden.register_channel_manager(manager)

    def event_channelnew(self, manager_address, event):  # pylint: disable=unused-argument
        if address_decoder(event['participant1']) != self.raiden.address and address_decoder(event['participant2']) != self.raiden.address:
            log.info('ignoring new channel, this is node is not a participant.')
            return

        netting_channel_address_bin = address_decoder(event['nettingChannel'])

        # shouldnt raise, filters are installed only for registered managers
        asset_manager = self.raiden.get_manager_by_address(manager_address)
        asset_manager.register_channel_by_address(
            netting_channel_address_bin,
            self.raiden.config['reveal_timeout'],
        )

        log.info(
            'New channel created',
            channel_address=event['nettingChannel'],
            manager_address=encode_hex(manager_address),
        )

    def event_channelnewbalance(self, netting_contract_address_bin, event):
        asset_address_bin = address_decoder(event['assetAddress'])
        participant_address_bin = address_decoder(event['participant'])

        # shouldn't raise, all three addresses need to be registered
        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_contract_address(netting_contract_address_bin)
        channel_state = channel.get_state_for(participant_address_bin)

        if channel_state.contract_balance != event['balance']:
            channel_state.update_contract_balance(event['balance'])

        if channel.external_state.opened_block == 0:
            channel.external_state.opened_block = event['blockNumber']

    def event_channelclosed(self, netting_contract_address_bin, event):
        channel = self.raiden.find_channel_by_address(netting_contract_address_bin)
        channel.external_state.closed_block = event['blockNumber']

        channel.external_state.netting_channel.update_transfer(
            channel.our_state.address,
            channel.received_transfers[-1],
        )

        # TODO: unlock

    def event_channelsettled(self, netting_contract_address_bin, event):
        log.debug("channel settle event received",
                  netting_contract=netting_contract_address_bin.encode('hex'),
                  event=event)
        channel = self.raiden.find_channel_by_address(netting_contract_address_bin)
        channel.external_state.settled_block = event['blockNumber']
        log.debug("set channel.external_state.settled_block", settled_block=event['blockNumber'])

    def event_channelsecretrevealed(self, netting_contract_address_bin, event):
        channel = self.raiden.chain.netting_channel(netting_contract_address_bin)
        asset_address_bin = channel.asset_address()
        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)

        # XXX: should reveal the secret to other asset managers?
        # update all channels and propagate the secret
        manager.register_secret(event['secret'])
