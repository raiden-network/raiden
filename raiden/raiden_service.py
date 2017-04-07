# -*- coding: utf-8 -*-
import logging
from collections import namedtuple

import gevent
from gevent.queue import Empty as QueueEmpty
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder
from secp256k1 import PrivateKey

from raiden.tokenmanager import TokenManager
from raiden.transfermanager import (
    Exchange,
    ExchangeKey,
    UnknownAddress,
    UnknownTokenAddress
)
from raiden.blockchain.abi import (
    CHANNEL_MANAGER_ABI,
    REGISTRY_ABI,
    NETTING_CHANNEL_ABI
)
from raiden.network.channelgraph import ChannelGraph
from raiden.tasks import AlarmTask, StartExchangeTask, HealthcheckTask
from raiden.encoding import messages
from raiden.messages import SignedMessage
from raiden.network.protocol import RaidenProtocol
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    safe_address_decode,
    GLOBAL_CTX,
)


log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


EventListener = namedtuple('EventListener', ('event_name', 'filter_', 'translator'))


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
        self.managers_by_token_address = dict()
        self.managers_by_address = dict()

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
        # ignore the blocknumber
        alarm.register_callback(lambda _: event_handler.poll_all_event_listeners())
        alarm.start()

        self._blocknumber = alarm.last_block_number
        alarm.register_callback(self.set_block_number)

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
        self.start_event_listener = event_handler.start_event_listener

        self.on_message = message_handler.on_message
        self.on_event = event_handler.on_event

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def set_block_number(self, blocknumber):
        self._blocknumber = blocknumber

    def get_block_number(self):
        return self._blocknumber

    def get_manager_by_token_address(self, token_address_bin):
        """ Return the manager for the given `token_address_bin`.  """
        try:
            return self.managers_by_token_address[token_address_bin]
        except KeyError:
            raise UnknownTokenAddress(token_address_bin)

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
    #   cross token operation
    # - unlocking a lock is not a cross token operation, for this reason it's
    #   only available in the token manager

    def register_secret(self, secret):
        """ Register the secret with any channel that has a hashlock on it.

        This must search through all channels registered for a given hashlock
        and ignoring the tokens. Useful for refund transfer, split transfer,
        and exchanges.
        """
        for token_manager in self.managers_by_token_address.values():
            try:
                token_manager.register_secret(secret)
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
        for token_manager in self.managers_by_token_address.values():
            task = token_manager.transfermanager.transfertasks.get(hashlock)

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
        """ Register the registry and intialize all the related tokens and
        channels.
        """
        translator = ContractTranslator(REGISTRY_ABI)

        tokenadded = registry.tokenadded_filter()

        all_manager_addresses = registry.manager_addresses()

        self.start_event_listener(
            'Registry {}'.format(pex(registry.address)),
            tokenadded,
            translator,
        )

        self.registries.append(registry)

        for manager_address in all_manager_addresses:
            channel_manager = self.chain.manager(manager_address)
            self.register_channel_manager(channel_manager)

    def register_channel_manager(self, channel_manager):
        """ Discover and register the channels for the given token. """
        translator = ContractTranslator(CHANNEL_MANAGER_ABI)

        # To avoid missing changes, first create the filter, call the
        # contract and then start polling.
        channelnew = channel_manager.channelnew_filter()

        all_netting_contracts = channel_manager.channels_by_participant(self.address)

        self.start_event_listener(
            'ChannelManager {}'.format(pex(channel_manager.address)),
            channelnew,
            translator,
        )

        token_address_bin = channel_manager.token_address()
        channel_manager_address_bin = channel_manager.address
        edges = channel_manager.channels_addresses()
        channel_graph = ChannelGraph(edges)

        token_manager = TokenManager(
            self,
            token_address_bin,
            channel_manager_address_bin,
            channel_graph,
        )
        self.managers_by_token_address[token_address_bin] = token_manager
        self.managers_by_address[channel_manager_address_bin] = token_manager

        for netting_contract_address in all_netting_contracts:
            token_manager.register_channel_by_address(
                netting_contract_address,
                self.config['reveal_timeout'],
            )

    def stop(self):
        for token_manager in self.managers_by_token_address.itervalues():
            for task in token_manager.transfermanager.transfertasks.itervalues():
                task.kill()

        wait_for = [self.alarm]
        self.alarm.stop_async()
        if self.healthcheck is not None:
            self.healthcheck.stop_async()
            wait_for.append(self.healthcheck)
        self.protocol.stop_async()

        wait_for.extend(self.protocol.address_greenlet.itervalues())

        for token_manager in self.managers_by_token_address.itervalues():
            wait_for.extend(token_manager.transfermanager.transfertasks.itervalues())

        self.event_handler.uninstall_listeners()
        gevent.wait(wait_for)


class RaidenAPI(object):
    """ CLI interface. """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    @property
    def tokens(self):
        """ Return a list of the tokens registered with the default registry. """
        return self.raiden.chain.default_registry.token_addresses()

    def get_balance(self, token_address, partner_address):
        raise NotImplementedError()

    def get_completed_transfers(self, token_address=None, partner_address=None):
        raise NotImplementedError()

    def get_channel(self, channel_address):
        channel_address_bin = address_decoder(channel_address)
        channel_list = self.get_channel_list()
        for channel in channel_list:
            if channel.channel_address == channel_address_bin:
                return channel

        raise ValueError("Channel not found")

    def open(
            self,
            token_address,
            partner_address,
            settle_timeout=None,
            reveal_timeout=None):
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if reveal_timeout is None:
            reveal_timeout = self.raiden.config['reveal_timeout']

        if settle_timeout is None:
            settle_timeout = self.raiden.config['settle_timeout']

        if settle_timeout < self.raiden.config['settle_timeout']:
            raise ValueError('Configured minimum `settle_timeout` is {} blocks.'.format(
                self.raiden.config['settle_timeout']))

        channel_manager = self.raiden.chain.manager_by_token(token_address.decode('hex'))
        token_manager = self.raiden.get_manager_by_token_address(token_address.decode('hex'))
        netcontract_address = channel_manager.new_netting_channel(
            self.raiden.address,
            partner_address.decode('hex'),
            settle_timeout,
        )
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        token_manager.register_channel(netting_channel, reveal_timeout)

        channel = token_manager.get_channel_by_contract_address(netcontract_address)
        return channel

    def deposit(self, token_address, partner_address, amount):
        """ Deposit `amount` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.
        """
        token_manager = self.raiden.get_manager_by_token_address(token_address.decode('hex'))
        channel = token_manager.get_channel_by_partner_address(partner_address.decode('hex'))
        netcontract_address = channel.channel_address
        assert len(netcontract_address)

        # Obtain a reference to the token and approve the amount for funding
        token = self.raiden.chain.token(token_address.decode('hex'))
        balance = token.balance_of(self.raiden.address.encode('hex'))

        if not balance >= amount:
            msg = "Not enough balance for token'{}' [{}]: have={}, need={}".format(
                token.proxy.name(), token_address, balance, amount
            )
            raise InsufficientFunds(msg)

        token.approve(netcontract_address, amount)

        # Obtain the netting channel and fund it by depositing the amount
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        netting_channel.deposit(self.raiden.address, amount)

        return channel

    def exchange(self, from_token, from_amount, to_token, to_amount, target_address):
        try:
            self.raiden.get_manager_by_token_address(from_token)
        except UnknownTokenAddress as e:
            log.error(
                'no token manager for %s',
                e.token_address,
            )
            return

        task = StartExchangeTask(
            self.raiden,
            from_token,
            from_amount,
            to_token,
            to_amount,
            target_address,
        )
        task.start()
        return task

    def expect_exchange(
            self,
            identifier,
            from_token,
            from_amount,
            to_token,
            to_amount,
            target_address):

        exchange = Exchange(
            identifier,
            from_token,
            from_amount,
            target_address,
            to_token,
            to_amount,
            self.raiden.address,
        )

        token_manager = self.raiden.get_manager_by_token_address(from_token)
        token_manager.transfermanager.exchanges[ExchangeKey(from_token, from_amount)] = exchange

    def get_channel_list(self, token_address=None, partner_address=None):
        """Returns a list of channels associated with the optionally given
           `token_address` and/or `partner_address`.

        Args:
            token_address (bin): an optionally provided token address
            partner_address (bin): an optionally provided partner address

        Return:
            A list containing all channels the node participates. Optionally
            filtered by a token address and/or partner address.

        Raises:
            UnknownTokenAddress:
                An error occurred when the token address is unknown to the
                node.

            KeyError:
                An error occurred when the given partner address isn't associated
                with the given token address.
        """
        if token_address:
            token_manager = self.raiden.get_manager_by_token_address(token_address)
            if partner_address:
                return [token_manager.partneraddress_channel[partner_address]]
            return token_manager.address_channel.values()
        else:
            channel_list = []
            if partner_address:
                for manager in self.raiden.managers_by_token_address.values():
                    if partner_address in manager.partneraddress_channel:
                        channel_list.extend([manager.partneraddress_channel[partner_address]])
                return channel_list
            for manager in self.raiden.managers_by_token_address.values():
                channel_list.extend(manager.address_channel.values())
            return channel_list

    def get_tokens_list(self):
        """Returns a list of tokens the node knows about"""
        tokens_list = []
        for token_address in self.managers_by_token_address:
            tokens_list.append(token_address)

        return tokens_list

    def transfer_and_wait(
            self,
            token_address,
            amount,
            target,
            identifier=None,
            timeout=None):
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments

        async_result = self.transfer_async(
            token_address,
            amount,
            target,
            identifier,
        )
        return async_result.wait(timeout=timeout)

    transfer = transfer_and_wait  # expose a synchronous interface to the user

    def transfer_async(
            self,
            token_address,
            amount,
            target,
            identifier=None):
        # pylint: disable=too-many-arguments

        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        token_address_bin = safe_address_decode(token_address)
        target_bin = safe_address_decode(target)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(target_bin):
            raise InvalidAddress('target address is not valid.')

        token_manager = self.raiden.get_manager_by_token_address(token_address_bin)
        if not token_manager.has_path(self.raiden.address, target_bin):
            raise NoPathError('No path to address found')

        transfer_manager = token_manager.transfermanager
        async_result = transfer_manager.transfer_async(
            amount,
            target_bin,
            identifier=identifier,
        )
        return async_result

    def close(self, token_address, partner_address):
        """ Close a channel opened with `partner_address` for the given `token_address`. """
        token_address_bin = safe_address_decode(token_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        manager = self.raiden.get_manager_by_token_address(token_address_bin)
        channel = manager.get_channel_by_partner_address(partner_address_bin)

        first_transfer = None
        if channel.received_transfers:
            first_transfer = channel.received_transfers[-1]

        netting_channel = channel.external_state.netting_channel
        netting_channel.close(
            self.raiden.address,
            first_transfer,
        )

        return channel

    def settle(self, token_address, partner_address):
        """ Settle a closed channel with `partner_address` for the given `token_address`. """
        token_address_bin = safe_address_decode(token_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        manager = self.raiden.get_manager_by_token_address(token_address_bin)
        channel = manager.get_channel_by_partner_address(partner_address_bin)

        if channel.isopen:
            raise InvalidState('channel is still open.')

        netting_channel = channel.external_state.netting_channel

        if (self.raiden.chain.block_number() <=
            (channel.external_state.closed_block +
             netting_channel.detail(self.raiden.address)['settle_timeout'])):
            raise InvalidState('settlement period is not yet over.')

        netting_channel.settle()
        return channel

    def get_token_network_events(self, token_address, from_block, to_block=''):
        return self.raiden.event_handler.get_token_network_events(
            token_address,
            from_block,
            to_block
        )

    def get_network_events(self, from_block, to_block=''):
        return self.raiden.event_handler.get_network_events(
            from_block,
            to_block
        )

    def get_channel_events(self, channel_address, from_block, to_block=''):
        return self.raiden.event_handler.get_channel_events(
            channel_address,
            from_block,
            to_block
        )


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

        else:
            raise Exception("Unhandled message cmdid '{}'.".format(cmdid))

    def message_ping(self, message):  # pylint: disable=unused-argument,no-self-use
        log.info('ping received')

    def message_revealsecret(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_secretrequest(self, message):
        self.raiden.message_for_task(message, message.hashlock)

    def message_secret(self, message):
        # notify the waiting tasks about the message (multiple tasks could
        # happen in exchanges were a node is on both token transfers), and make
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
                token_manager = self.raiden.get_manager_by_token_address(message.token)
                token_manager.handle_secretmessage(message)
            except:  # pylint: disable=bare-except
                log.exception('Unhandled exception')

    def message_refundtransfer(self, message):
        self.raiden.message_for_task(message, message.lock.hashlock)

    def message_directtransfer(self, message):
        token_manager = self.raiden.get_manager_by_token_address(message.token)
        token_manager.transfermanager.on_directtransfer_message(message)

    def message_mediatedtransfer(self, message):
        token_manager = self.raiden.get_manager_by_token_address(message.token)
        token_manager.transfermanager.on_mediatedtransfer_message(message)


class RaidenEventHandler(object):
    """ Class responsible to handle all the blockchain events.

    Note:
        This class is not intended to be used standalone, use RaidenService
        instead.
    """

    blockchain_event_types = [
        'TokenAdded',
        'ChannelNew',
        'ChannelNewBalance',
        'ChannelClosed',
        'ChannelSettled',
        'ChannelSecretRevealed'
    ]

    def __init__(self, raiden):
        self.raiden = raiden
        self.event_listeners = list()
        self.logged_events = dict()

    def get_token_network_events(self, token_address, from_block, to_block=''):
        # Note: Issue #452 (https://github.com/raiden-network/raiden/issues/452)
        # tracks a suggested TODO, which will reduce the 3 RPC calls here to only
        # one using `eth_getLogs`. It will require changes in all testing frameworks
        # to be implemented though.
        translator = ContractTranslator(CHANNEL_MANAGER_ABI)
        token_address_bin = address_decoder(token_address)
        channel_manager = self.raiden.chain.manager_by_token(token_address_bin)
        filter_ = None
        try:
            filter_ = channel_manager.channelnew_filter(from_block, to_block)
            events = filter_.getall()
        finally:
            if filter_ is not None:
                filter_.uninstall()
        return [translator.decode_event(event['topics'], event['data']) for event in events]

    def get_network_events(self, from_block, to_block=''):
        # Note: Issue #452 (https://github.com/raiden-network/raiden/issues/452)
        # tracks a suggested TODO, which will reduce the 3 RPC calls here to only
        # one using `eth_getLogs`. It will require changes in all testing frameworks
        # to be implemented though.

        # Assuming only one token registry for the moment
        translator = ContractTranslator(REGISTRY_ABI)
        filter_ = None
        try:
            filter_ = self.raiden.registries[0].tokenadded_filter(from_block, to_block)
            events = filter_.getall()
        finally:
            if filter_ is not None:
                filter_.uninstall()
        return [translator.decode_event(event['topics'], event['data']) for event in events]

    def get_channel_events(self, channel_address, event_id, from_block, to_block=''):
        # Note: Issue #452 (https://github.com/raiden-network/raiden/issues/452)
        # tracks a suggested TODO, which will reduce the 3 RPC calls here to only
        # one using `eth_getLogs`. It will require changes in all testing frameworks
        # to be implemented though.
        translator = ContractTranslator(NETTING_CHANNEL_ABI)
        channel = self.raiden.api.get_channel(channel_address)
        filter_ = None
        try:
            filter_ = channel.external_state.netting_channel.events_filter(
                [event_id],
                from_block,
                to_block,
            )
            events = filter_.getall()
        finally:
            if filter_ is not None:
                filter_.uninstall()
        return [translator.decode_event(event['topics'], event['data']) for event in events]

    def start_event_listener(self, event_name, filter_, translator):
        event = EventListener(
            event_name,
            filter_,
            translator,
        )
        self.event_listeners.append(event)

        self.poll_event_listener(event_name, filter_, translator)

    def poll_event_listener(self, event_name, filter_, translator):
        for log_event in filter_.changes():
            log.debug('New Events', task=event_name)

            event = translator.decode_event(
                log_event['topics'],
                log_event['data'],
            )

            if event is not None:
                originating_contract = log_event['address']

                try:
                    # intentionally forcing all the events to go through
                    # the event handler
                    self.on_event(originating_contract, event)
                except:  # pylint: disable=bare-except
                    log.exception('unexpected exception on log listener')

    def poll_all_event_listeners(self):
        for event_listener in self.event_listeners:
            self.poll_event_listener(*event_listener)

    def uninstall_listeners(self):
        chain = self.raiden.chain

        for listener in self.event_listeners:
            chain.uninstall_filter(listener.filter_.filter_id_raw)

        self.event_listeners = list()

    def on_event(self, emitting_contract_address_bin, event):  # pylint: disable=unused-argument
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'event received',
                type=event['_event_type'],
                contract=pex(emitting_contract_address_bin),
            )

        if event['_event_type'] == 'TokenAdded':
            self.event_tokenadded(emitting_contract_address_bin, event)

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

    def event_tokenadded(self, registry_address_bin, event):  # pylint: disable=unused-argument
        manager_address_bin = address_decoder(event['channel_manager_address'])
        manager = self.raiden.chain.manager(manager_address_bin)
        self.raiden.register_channel_manager(manager)

    def event_channelnew(self, manager_address_bin, event):  # pylint: disable=unused-argument
        # should not raise, filters are installed only for registered managers
        token_manager = self.raiden.get_manager_by_address(manager_address_bin)

        participant1 = address_decoder(event['participant1'])
        participant2 = address_decoder(event['participant2'])

        # update our global network graph for routing
        token_manager.channelgraph.add_path(
            participant1,
            participant2,
        )

        if participant1 == self.raiden.address or participant2 == self.raiden.address:
            netting_channel_address_bin = address_decoder(event['netting_channel'])

            try:
                token_manager.register_channel_by_address(
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
            log.info('ignoring new channel, this node is not a participant.')

    def event_channelnewbalance(self, netting_contract_address_bin, event):
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'channel new balance event received',
                netting_contract=pex(netting_contract_address_bin),
                event=event,
            )

        token_address_bin = address_decoder(event['token_address'])
        participant_address_bin = address_decoder(event['participant'])

        # should not raise, all three addresses need to be registered
        manager = self.raiden.get_manager_by_token_address(token_address_bin)
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
