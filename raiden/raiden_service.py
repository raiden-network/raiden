# -*- coding: utf-8 -*-
import logging
import itertools

import gevent
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder
from secp256k1 import PrivateKey

from raiden.assetmanager import AssetManager
from raiden.transfermanager import (
    Exchange,
    ExchangeKey,
    UnknownAddress,
    UnknownAssetAddress
)
from raiden.blockchain.abi import CHANNEL_MANAGER_ABI, REGISTRY_ABI
from raiden.network.channelgraph import ChannelGraph
from raiden.tasks import AlarmTask, LogListenerTask, StartExchangeTask, HealthcheckTask
from raiden.encoding import messages
from raiden.messages import SignedMessage
from raiden.network.protocol import RaidenProtocol
from raiden.utils import privatekey_to_address, isaddress, pex, GLOBAL_CTX

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name

DEFAULT_REVEAL_TIMEOUT = 30
DEFAULT_SETTLE_TIMEOUT = DEFAULT_REVEAL_TIMEOUT * 20


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

    def __init__(self, chain, private_key_bin, transport, discovery, config):
        # pylint: disable=too-many-arguments

        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        private_key = PrivateKey(
            private_key_bin,
            ctx=GLOBAL_CTX,
            raw=True,
        )
        pubkey = private_key.pubkey.serialize(compressed=False)

        self.registries = list()
        self.managers_by_asset_address = dict()
        self.managers_by_address = dict()
        self.event_listeners = list()

        self.chain = chain
        self.config = config
        self.privkey = private_key_bin
        self.pubkey = pubkey
        self.private_key = private_key
        self.address = privatekey_to_address(private_key_bin)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol

        message_handler = RaidenMessageHandler(self)
        event_handler = RaidenEventHandler(self)

        alarm = AlarmTask(chain)
        alarm.start()
        if config['max_unresponsive_time'] > 0:
            self.healthcheck = HealthcheckTask(
                self,
                config['send_ping_time'],
                config['max_unresponsive_time']
            )
            self.healthcheck.start()
        else:
            self.healthcheck = None

        self.api = RaidenAPI(self)
        self.alarm = alarm
        self.event_handler = event_handler
        self.message_handler = message_handler

        self.on_message = message_handler.on_message
        self.on_event = event_handler.on_event

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def get_manager_by_asset_address(self, asset_address_bin):
        """ Return the manager for the given `asset_address_bin`.  """
        try:
            return self.managers_by_asset_address[asset_address_bin]
        except KeyError:
            raise UnknownAssetAddress(asset_address_bin)

    def get_manager_by_address(self, manager_address_bin):
        return self.managers_by_address[manager_address_bin]

    def find_channel_by_address(self, netting_channel_address_bin):
        for manager in self.managers_by_address.itervalues():
            channel = manager.address_channel.get(netting_channel_address_bin)

            if channel is not None:
                return channel

        raise ValueError('unknown channel {}'.format(encode_hex(netting_channel_address_bin)))

    def sign(self, message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError('{} is not signable.'.format(repr(message)))

        message.sign(self.private_key, self.address)

    def send(self, *args):
        raise NotImplementedError('use send_and_wait or send_async')

    def send_async(self, recipient, message):
        """ Send `message` to `recipient` using the raiden protocol.

        The protocol will take care of resending the message on a given
        interval until an Acknowledgment is received or a given number of
        tries.
        """

        if not isaddress(recipient):
            raise ValueError('recipient is not a valid address.')

        if recipient == self.address:
            raise ValueError('programming error, sending message to itself')

        return self.protocol.send_async(recipient, message)

    def send_and_wait(self, recipient, message, timeout):
        """ Send `message` to `recipient` and wait for the response or `timeout`.

        Args:
            recipient (address): The address of the node that will receive the
                message.
            message: The transfer message.
            timeout (float): How long should we wait for a response from `recipient`.

        Returns:
            None: If the wait timed out
            object: The result from the event
        """
        if not isaddress(recipient):
            raise ValueError('recipient is not a valid address.')

        self.protocol.send_and_wait(recipient, message, timeout)

    # api design regarding locks:
    # - `register_secret` method was added because secret registration can be a
    #   cross asset operation
    # - unlocking a lock is not a cross asset operation, for this reason it's
    #   only available in the asset manager

    def register_secret(self, secret):
        """ Register the secret with any channel that has a hashlock on it.

        This must search through all channels registered for a given hashlock
        and ignoring the assets. Useful for refund transfer, split transfer,
        and exchanges.
        """
        for asset_manager in self.managers_by_asset_address.values():
            try:
                asset_manager.register_secret(secret)
            except:  # pylint: disable=bare-except
                # Only channels that care about the given secret can be
                # registered and channels that have claimed the lock must
                # be removed, so an exception should not happen at this
                # point, nevertheless handle it because we dont want a
                # error in a channel to mess the state from others.
                log.error('programming error')

    def message_for_task(self, message, hashlock):
        """ Sends the message to the corresponding task.

        The corresponding task is found by matching the hashlock.

        Return:
            Nothing if a corresponding task is found,raise Exception otherwise
        """
        found = False
        for asset_manager in self.managers_by_asset_address.values():
            task = asset_manager.transfermanager.transfertasks.get(hashlock)

            if task is not None:
                task.on_response(message)
                found = True

        if not found:
            # Log a warning and don't process further
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received %s hashlock message from unknown channel.'
                    'Sender: %s',
                    message.__class__.__name__,
                    pex(message.sender),
                )
            raise UnknownAddress

    def register_registry(self, registry):
        """ Register the registry and intialize all the related assets and
        channels.
        """
        translator = ContractTranslator(REGISTRY_ABI)

        assetadded = registry.assetadded_filter()

        all_manager_addresses = registry.manager_addresses()

        task_name = 'Registry {}'.format(pex(registry.address))
        asset_listener = LogListenerTask(
            task_name,
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
        channelnew = channel_manager.channelnew_filter()

        all_netting_contracts = channel_manager.channels_by_participant(self.address)

        task_name = 'ChannelManager {}'.format(pex(channel_manager.address))
        channel_listener = LogListenerTask(
            task_name,
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
            listener.stop_async()
            self.chain.uninstall_filter(listener.filter_.filter_id_raw)

        for asset_manager in self.managers_by_asset_address.itervalues():
            for task in asset_manager.transfermanager.transfertasks.itervalues():
                task.kill()

        wait_for = [self.alarm]
        self.alarm.stop_async()
        if self.healthcheck is not None:
            self.healthcheck.stop_async()
            wait_for.append(self.healthcheck)
        self.protocol.stop_async()

        wait_for.extend(self.event_listeners)
        wait_for.extend(self.protocol.address_greenlet.itervalues())

        for asset_manager in self.managers_by_asset_address.itervalues():
            wait_for.extend(asset_manager.transfermanager.transfertasks.itervalues())

        gevent.wait(wait_for)


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
             settle_timeout=None, reveal_timeout=None):
        """ Open a channel with the peer at `partner_address`
        with the given `asset_address`.
        """
        if reveal_timeout is None:
            reveal_timeout = self.raiden.config['reveal_timeout']

        if settle_timeout is None:
            settle_timeout = self.raiden.config['settle_timeout']

        if settle_timeout < self.raiden.config['settle_timeout']:
            raise ValueError('Configured minimum `settle_timeout` is {} blocks.'.format(
                self.raiden.config['settle_timeout']))

        channel_manager = self.raiden.chain.manager_by_asset(asset_address.decode('hex'))
        asset_manager = self.raiden.get_manager_by_asset_address(asset_address.decode('hex'))
        netcontract_address = channel_manager.new_netting_channel(
            self.raiden.address,
            partner_address.decode('hex'),
            settle_timeout,
        )
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        asset_manager.register_channel(netting_channel, reveal_timeout)

        return netting_channel

    def deposit(self, asset_address, partner_address, amount):
        """ Deposit `amount` in the channel with the peer at `partner_address` and the
        given `asset_address` in order to be able to do transfers.
        """
        asset_manager = self.raiden.get_manager_by_asset_address(asset_address.decode('hex'))
        channel = asset_manager.get_channel_by_partner_address(partner_address.decode('hex'))
        netcontract_address = channel.external_state.netting_channel.address
        assert len(netcontract_address)

        # Obtain a reference to the asset and approve the amount for funding
        asset = self.raiden.chain.asset(asset_address.decode('hex'))
        balance = asset.balance_of(self.raiden.address.encode('hex'))

        if not balance >= amount:
            msg = "Not enough balance for token'{}' [{}]: have={}, need={}".format(
                asset.proxy.name(), asset_address, balance, amount
            )
            raise InsufficientFunds(msg)

        asset.approve(netcontract_address, amount)

        # Obtain the netting channel and fund it by depositing the amount
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        netting_channel.deposit(self.raiden.address, amount)

        return netting_channel

    def exchange(self, from_asset, from_amount, to_asset, to_amount, target_address):
        from_asset_bin = safe_address_decode(from_asset)
        to_asset_bin = safe_address_decode(to_asset)
        target_bin = safe_address_decode(target_address)

        try:
            self.raiden.get_manager_by_asset_address(from_asset_bin)
            self.raiden.get_manager_by_asset_address(from_asset_bin)
        except UnknownAssetAddress as e:
            log.error(
                'no asset manager for %s',
                e.asset_address,
            )
            return

        task = StartExchangeTask(
            self.raiden,
            from_asset_bin,
            from_amount,
            to_asset_bin,
            to_amount,
            target_bin,
        )
        task.start()
        return task

    def expect_exchange(
            self,
            identifier,
            from_asset,
            from_amount,
            to_asset,
            to_amount,
            target_address):

        exchange = Exchange(
            identifier,
            from_asset,
            from_amount,
            target_address,
            to_asset,
            to_amount,
            self.raiden.address,
        )

        asset_manager = self.raiden.get_manager_by_asset_address(from_asset)
        asset_manager.transfermanager.exchanges[ExchangeKey(from_asset, from_amount)] = exchange

    def transfer_and_wait(self, asset_address, amount, target, identifier=None,
                          callback=None, timeout=None):
        """ Do a transfer with `target` with the given `amount` of `asset_address`. """
        # pylint: disable=too-many-arguments

        async_result = self.transfer_async(
            asset_address,
            amount,
            target,
            identifier,
            callback,
        )
        return async_result.wait(timeout=timeout)

    transfer = transfer_and_wait  # expose a synchronous interface to the user

    def transfer_async(
            self,
            asset_address,
            amount,
            target,
            identifier=None,
            callback=None):
        # pylint: disable=too-many-arguments

        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        asset_address_bin = safe_address_decode(asset_address)
        target_bin = safe_address_decode(target)

        if not isaddress(asset_address_bin) or asset_address_bin not in self.assets:
            raise InvalidAddress('asset address is not valid.')

        if not isaddress(target_bin):
            raise InvalidAddress('target address is not valid.')

        asset_manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        if not asset_manager.has_path(self.raiden.address, target_bin):
            raise NoPathError('No path to address found')

        transfer_manager = asset_manager.transfermanager
        async_result = transfer_manager.transfer_async(
            amount,
            target_bin,
            identifier=identifier,
            callback=callback,
        )
        return async_result

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

        if not (self.raiden.chain.client.blocknumber() >=
                (channel.external_state.closed_block +
                 netting_channel.detail(self.raiden.address)['settle_timeout'])):
            raise InvalidState('settlement period not over.')

        netting_channel.settle()
        return netting_channel

    def register_on_withdrawable_callbacks(self, callbacks):
        # wrap in list if only one callback
        try:
            iter(callbacks)
        except TypeError:
            callbacks = [callbacks]
        all_asset_managers = self.raiden.managers_by_asset_address.values()
        # get all channel the node participates in:
        all_channel = [am.partneraddress_channel.values() for am in all_asset_managers]
        # and flatten the list:
        all_channel = list(itertools.chain.from_iterable(all_channel))

        for callback in callbacks:
            for channel in all_channel:
                channel.register_withdrawable_callback(callback)

            for asset_manager in all_asset_managers:
                asset_manager.transfermanager.register_callback_for_result(callback)


class RaidenMessageHandler(object):
    """ Class responsible to handle the protocol messages.

    Note:
        This class is not intended to be used standalone, use RaidenService
        instead.
    """
    def __init__(self, raiden):
        self.raiden = raiden

    def on_message(self, message, msghash):  # noqa pylint: disable=unused-argument
        """ Handles `message` and sends an ACK on success. """
        cmdid = message.cmdid

        # using explicity dispatch to make the code grepable
        if cmdid == messages.ACK:
            pass

        elif cmdid == messages.PING:
            self.message_ping(message)

        elif cmdid == messages.SECRETREQUEST:
            self.message_secretrequest(message)

        elif cmdid == messages.REVEALSECRET:
            self.message_revealsecret(message)

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
            raise Exception("Unhandled message cmdid '{}'.".format(cmdid))

    def message_ping(self, message):  # pylint: disable=unused-argument,no-self-use
        log.info('ping received')

    def message_confirmtransfer(self, message):
        # TODO: Whenever this is implemented, don't forget to edit the
        # corresponding test in test_transfer.py
        pass

    def message_revealsecret(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_secretrequest(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_secret(self, message):
        # notify the waiting tasks about the message (multiple tasks could
        # happen in exchanges were a node is on both asset transfers), and make
        # sure that the secret is register if it fails (or it has exited
        # because the transfer was considered done)
        try:
            self.raiden.message_for_task(message, message.hashlock)
        finally:
            try:
                # register the secret with all channels interested in it (this
                # must not withdraw or unlock otherwise the state changes could
                # flow in the wrong order in the path)
                self.raiden.register_secret(message.secret)

                # make sure we have a proper state change
                asset_manager = self.raiden.get_manager_by_asset_address(message.asset)
                asset_manager.handle_secretmessage(message)
            except:  # pylint: disable=bare-except
                log.exception('Unhandled exception')

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
    """ Class responsible to handle all the blockchain events.

    Note:
        This class is not intended to be used standalone, use RaidenService
        instead.
    """

    def __init__(self, raiden):
        self.raiden = raiden

    def on_event(self, emitting_contract_address_bin, event):  # pylint: disable=unused-argument
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'event received',
                type=event['_event_type'],
                contract=pex(emitting_contract_address_bin),
            )

        if event['_event_type'] == 'AssetAdded':
            self.event_assetadded(emitting_contract_address_bin, event)

        elif event['_event_type'] == 'ChannelNew':
            self.event_channelnew(emitting_contract_address_bin, event)

        elif event['_event_type'] == 'ChannelNewBalance':
            self.event_channelnewbalance(emitting_contract_address_bin, event)

        elif event['_event_type'] == 'ChannelClosed':
            self.event_channelclosed(emitting_contract_address_bin, event)

        elif event['_event_type'] == 'ChannelSettled':
            self.event_channelsettled(emitting_contract_address_bin, event)

        elif event['_event_type'] == 'ChannelSecretRevealed':
            self.event_channelsecretrevealed(emitting_contract_address_bin, event)

        else:
            log.error('Unknown event %s', repr(event))

    def event_assetadded(self, registry_address_bin, event):  # pylint: disable=unused-argument
        manager_address_bin = address_decoder(event['channel_manager_address'])
        manager = self.raiden.chain.manager(manager_address_bin)
        self.raiden.register_channel_manager(manager)

    def event_channelnew(self, manager_address_bin, event):  # pylint: disable=unused-argument
        # should not raise, filters are installed only for registered managers
        asset_manager = self.raiden.get_manager_by_address(manager_address_bin)

        participant1 = address_decoder(event['participant1'])
        participant2 = address_decoder(event['participant2'])

        # update our global network graph for routing
        asset_manager.channelgraph.add_path(
            participant1,
            participant2,
        )

        if participant1 == self.raiden.address or participant2 == self.raiden.address:
            netting_channel_address_bin = address_decoder(event['netting_channel'])

            try:
                asset_manager.register_channel_by_address(
                    netting_channel_address_bin,
                    self.raiden.config['reveal_timeout'],
                )
            except ValueError:
                # This can happen if the new channel's settle_timeout is
                # smaller than raiden.config['reveal_timeout']
                log.exception('Channel registration failed.')
            else:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'New channel created',
                        channel_address=event['netting_channel'],
                        manager_address=pex(manager_address_bin),
                    )
        else:
            log.info('ignoring new channel, this is node is not a participant.')

    def event_channelnewbalance(self, netting_contract_address_bin, event):
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'channel new balance event received',
                netting_contract=pex(netting_contract_address_bin),
                event=event,
            )

        asset_address_bin = address_decoder(event['asset_address'])
        participant_address_bin = address_decoder(event['participant'])

        # should not raise, all three addresses need to be registered
        manager = self.raiden.get_manager_by_asset_address(asset_address_bin)
        channel = manager.get_channel_by_contract_address(netting_contract_address_bin)
        channel_state = channel.get_state_for(participant_address_bin)

        if channel_state.contract_balance != event['balance']:
            channel_state.update_contract_balance(event['balance'])

        if channel.external_state.opened_block == 0:
            channel.external_state.set_opened(event['block_number'])

    def event_channelclosed(self, netting_contract_address_bin, event):
        channel = self.raiden.find_channel_by_address(netting_contract_address_bin)
        channel.external_state.set_closed(event['block_number'])

    def event_channelsettled(self, netting_contract_address_bin, event):
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'channel settle event received',
                netting_contract=pex(netting_contract_address_bin),
                event=event,
            )

        channel = self.raiden.find_channel_by_address(netting_contract_address_bin)
        channel.external_state.set_settled(event['block_number'])

    def event_channelsecretrevealed(self, netting_contract_address_bin, event):
        # pylint: disable=unused-argument
        self.raiden.register_secret(event['secret'])
