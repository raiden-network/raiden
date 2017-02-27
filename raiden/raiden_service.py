# -*- coding: utf-8 -*-
import logging
import random
from collections import namedtuple, defaultdict

import gevent

from gevent.queue import Empty as QueueEmpty
from gevent.event import AsyncResult
from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from pyethapp.jsonrpc import address_decoder
from secp256k1 import PrivateKey

from raiden.tokenmanager import TokenManager
from raiden.tasks import (
    StartMediatedTransferTask,
    MediateTransferTask,
    EndMediatedTransferTask,
    ExchangeTask,
)
from raiden.blockchain.abi import (
    CHANNEL_MANAGER_ABI,
    REGISTRY_ABI,
    NETTING_CHANNEL_ABI
)
from raiden.exceptions import (
    UnknownAddress,
    TransferWhenClosed,
    UnknownTokenAddress,
    NoPathError,
    InvalidAddress,
    InvalidAmount,
    InvalidState,
    InsufficientFunds,
)
from raiden.network.channelgraph import ChannelGraph
from raiden.tasks import AlarmTask, StartExchangeTask, HealthcheckTask
from raiden.encoding import messages
from raiden.messages import (
    SignedMessage,
    RevealSecret,
    Secret,
)
from raiden.network.protocol import RaidenProtocol
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    safe_address_decode,
    GLOBAL_CTX,
    sha3,
)

from raiden.transfer.mediated_transfer.events import SendMediatedTransfer

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


EventListener = namedtuple('EventListener', ('event_name', 'filter_', 'translator'))
Exchange = namedtuple('Exchange', (
    'identifier',
    'from_token',
    'from_amount',
    'from_nodeaddress',  # the node' address of the owner of the `from_token`
    'to_token',
    'to_amount',
    'to_nodeaddress',  # the node' address of the owner of the `to_token`
))
ExchangeKey = namedtuple('ExchangeKey', (
    'from_token',
    'from_amount',
))


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

        self.transfertasks = defaultdict(dict)
        self.exchanges = dict()

        # This is a map from a hashlock to a list of channels, the same
        # hashlock can be used in more than one token (for exchanges), a
        # channel should be removed from this list only when the lock is
        # released/withdrawed but not when the secret is registered.
        self.hashlock_channel = defaultdict(lambda: defaultdict(list))

        self.chain = chain
        self.config = config
        self.privkey = private_key_bin
        self.pubkey = pubkey
        self.private_key = private_key
        self.address = privatekey_to_address(private_key_bin)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol

        blockchain_log_handler = BlockchainEventsHandler(self)
        message_handler = RaidenMessageHandler(self)
        state_machine_event_handler = StateMachineEventHandler(self)

        alarm = AlarmTask(chain)
        # ignore the blocknumber
        alarm.register_callback(lambda _: blockchain_log_handler.poll_all_event_listeners())
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
        self.blockchain_log_handler = blockchain_log_handler
        self.message_handler = message_handler
        self.state_machine_event_handler = state_machine_event_handler
        self.start_event_listener = blockchain_log_handler.start_event_listener

        self.on_message = message_handler.on_message
        self.on_log = blockchain_log_handler.on_log
        self.on_event = state_machine_event_handler.on_event

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
        hashlock = sha3(secret)
        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for token_manager in self.managers_by_token_address.values():
            channels_list = self.hashlock_channel[token_manager.token_address][hashlock]

            for channel in channels_list:
                try:
                    channel.register_secret(secret)

                    # This will potentially be executed multiple times and could suffer
                    # from amplification, the protocol will ignore messages that were
                    # already registered and send it only until a first Ack is
                    # received.
                    self.send_async(
                        channel.partner_state.address,
                        revealsecret_message,
                    )
                except:  # pylint: disable=bare-except
                    # Only channels that care about the given secret can be
                    # registered and channels that have claimed the lock must
                    # be removed, so an exception should not happen at this
                    # point, nevertheless handle it because we dont want a
                    # error in a channel to mess the state from others.
                    log.error('programming error')

    def register_task_for_hashlock(self, task, token, hashlock):
        """ Register the task to receive messages based on hashlock.

        Registration is required otherwise the task won't receive any messages
        from the protocol, un-registering is done by the `on_hashlock_result`
        function.

        Note:
            Messages are dispatched solely on the hashlock value (being part of
            the message, eg. SecretRequest, or calculated from the message
            content, eg.  RevealSecret), this means the sender needs to be
            checked for the received messages.
        """
        self.transfertasks[hashlock][token] = task

    def register_channel_for_hashlock(self, token_address, channel, hashlock):
        channels_registered = self.hashlock_channel[token_address][hashlock]

        if channel not in channels_registered:
            channels_registered.append(channel)

    def handle_secret(self, identifier, token_address, secret, partner_secret_message, hashlock):
        """ Unlock/Witdraws locks, register the secret, and send Secret
        messages as necessary.

        This function will:
            - Unlock the locks created by this node and send a Secret message to
            the corresponding partner so that she can withdraw the token.
            - Withdraw the lock from sender.
            - Register the secret for the locks received and reveal the secret
            to the senders

        Note:
            The channel needs to be registered with
            `raiden.register_channel_for_hashlock`.
        """
        # handling the secret needs to:
        # - unlock the token for all `forward_channel` (the current one
        #   and the ones that failed with a refund)
        # - send a message to each of the forward nodes allowing them
        #   to withdraw the token
        # - register the secret for the `originating_channel` so that a
        #   proof can be made, if necessary
        # - reveal the secret to the `sender` node (otherwise we
        #   cannot withdraw the token)
        channels_list = self.hashlock_channel[token_address][hashlock]
        channels_to_remove = list()

        # Dont use the partner_secret_message.token since it might not match with the
        # current token manager
        our_secret_message = Secret(
            identifier,
            secret,
            token_address,
        )
        self.sign(our_secret_message)

        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for channel in channels_list:
            # unlock a sent lock
            if channel.partner_state.balance_proof.is_unclaimed(hashlock):
                channel.release_lock(secret)
                self.send_async(
                    channel.partner_state.address,
                    our_secret_message,
                )
                channels_to_remove.append(channel)

            # withdraw a pending lock
            if channel.our_state.balance_proof.is_unclaimed(hashlock):
                if partner_secret_message:
                    valid_sender = partner_secret_message.sender == channel.partner_state.address
                    valid_token = partner_secret_message.token == channel.token_address

                    if valid_sender and valid_token:
                        channel.withdraw_lock(secret)
                        channels_to_remove.append(channel)
                    else:
                        channel.register_secret(secret)
                        self.send_async(
                            channel.partner_state.address,
                            revealsecret_message,
                        )
                else:
                    channel.register_secret(secret)
                    self.send_async(
                        channel.partner_state.address,
                        revealsecret_message,
                    )

        for channel in channels_to_remove:
            channels_list.remove(channel)

        if len(channels_list) == 0:
            del self.hashlock_channel[token_address][hashlock]

    def on_hashlock_result(self, token, hashlock, success):
        """ Clear the task when it's finished. """
        del self.transfertasks[hashlock][token]

    def message_for_task(self, message, hashlock):
        """ Sends the message to the corresponding task.

        The corresponding task is found by matching the hashlock.

        Return:
            Nothing if a corresponding task is found,raise Exception otherwise
        """

        if self.transfertasks[hashlock]:
            for task in self.transfertasks[hashlock].itervalues():
                task.on_response(message)

        else:
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
        wait_for = [self.alarm]

        for token_task in self.transfertasks.itervalues():
            for task in token_task.itervalues():
                task.kill()

            wait_for.extend(token_task.itervalues())

        self.alarm.stop_async()
        if self.healthcheck is not None:
            self.healthcheck.stop_async()
            wait_for.append(self.healthcheck)
        self.protocol.stop_async()

        wait_for.extend(self.protocol.address_greenlet.itervalues())

        self.blockchain_log_handler.uninstall_listeners()
        gevent.wait(wait_for)

    def on_directtransfer_message(self, transfer):
        token_manager = self.get_manager_by_token_address(transfer.token)

        if transfer.sender not in token_manager.partneraddress_channel:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received direct transfer message from unknown sender %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        channel = token_manager.partneraddress_channel[transfer.sender]

        if not channel.isopen:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received direct transfer message from %s after channel closing',
                    pex(transfer.sender),
                )
            raise TransferWhenClosed
        channel.register_transfer(transfer)

    def on_mediatedtransfer_message(self, transfer):
        token_address = transfer.token
        token_manager = self.get_manager_by_token_address(token_address)

        if transfer.sender not in token_manager.partneraddress_channel:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received mediated transfer message from unknown channel.'
                    'Sender: %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        channel = token_manager.partneraddress_channel[transfer.sender]
        if not channel.isopen:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received mediated transfer message from %s after channel closing',
                    pex(transfer.sender),
                )
            raise TransferWhenClosed
        channel.register_transfer(transfer)  # raises if the transfer is invalid

        exchange_key = ExchangeKey(transfer.token, transfer.lock.amount)
        if exchange_key in self.exchanges:
            exchange = self.exchanges[exchange_key]

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'EXCHANGE TRANSFER RECEIVED node:%s %s > %s hashlock:%s'
                    ' from_token:%s from_amount:%s to_token:%s to_amount:%s [%s]',
                    pex(self.address),
                    pex(transfer.sender),
                    pex(self.address),
                    pex(transfer.lock.hashlock),
                    pex(exchange.from_token),
                    exchange.from_amount,
                    pex(exchange.to_token),
                    exchange.to_amount,
                    repr(transfer),
                )

            exchange_task = ExchangeTask(
                self,
                from_mediated_transfer=transfer,
                to_token=exchange.to_token,
                to_amount=exchange.to_amount,
                target=exchange.from_nodeaddress,
            )
            exchange_task.start()

        elif transfer.target == token_manager.raiden.address:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MEDIATED TRANSFER RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(token_manager.raiden.address),
                    pex(transfer.sender),
                    pex(token_manager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            try:
                token_manager.raiden.message_for_task(
                    transfer,
                    transfer.lock.hashlock
                )
            except UnknownAddress:
                # assumes that the registered task(s) tooks care of the message
                # (used for exchanges)
                secret_request_task = EndMediatedTransferTask(
                    self,
                    token_address,
                    transfer,
                )
                secret_request_task.start()

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'TRANSFER TO BE MEDIATED RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(token_manager.raiden.address),
                    pex(transfer.sender),
                    pex(token_manager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            transfer_task = MediateTransferTask(
                self,
                token_address,
                transfer,
                0,  # TODO: calculate the fee
            )
            transfer_task.start()

    def create_default_identifier(self, token_address, target):
        """
        The default message identifier value is the first 8 bytes of the sha3 of:
            - Our Address
            - Our target address
            - The token address
            - A random 8 byte number for uniqueness
        """
        hash_ = sha3("{}{}{}{}".format(
            self.address,
            target,
            token_address,
            random.randint(0, 18446744073709551614L)
        ))
        return int(hash_[0:8].encode('hex'), 16)

    def transfer_async(self, token_address, amount, target, identifier=None):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """
        token_manager = self.get_manager_by_token_address(token_address)

        # Create a default identifier value
        if identifier is None:
            identifier = self.create_default_identifier(token_address, target)

        direct_channel = token_manager.partneraddress_channel.get(target)
        if direct_channel:
            async_result = self._direct_or_mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel,
            )
            return async_result

        else:
            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                target,
            )

            return async_result

    def _direct_or_mediated_transfer(self, token_address, amount, identifier, direct_channel):
        """ Check the direct channel and if possible use it, otherwise start a
        mediated transfer.
        """

        if not direct_channel.isopen:
            log.info(
                'DIRECT CHANNEL %s > %s is closed',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
            )

            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel.partner_state.address,
            )
            return async_result

        elif amount > direct_channel.distributable:
            log.info(
                'DIRECT CHANNEL %s > %s doesnt have enough funds [%s]',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
                amount,
            )

            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel.partner_state.address,
            )
            return async_result

        else:
            direct_transfer = direct_channel.create_directtransfer(amount, identifier)
            self.sign(direct_transfer)
            direct_channel.register_transfer(direct_transfer)

            async_result = self.protocol.send_async(
                direct_channel.partner_state.address,
                direct_transfer,
            )
            return async_result

    def _mediated_transfer(self, token_address, amount, identifier, target):
        async_result = AsyncResult()
        task = StartMediatedTransferTask(
            self,
            token_address,
            amount,
            identifier,
            target,
            async_result,
        )
        task.start()

        return async_result


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

    def create_default_identifier(self, target, token_address):
        """
        The default message identifier value is the first 8 bytes of the sha3 of:
            - Our Address
            - Our target address
            - The token address
            - A random 8 byte number for uniqueness
        """
        return self.raiden.create_default_identifier(target, token_address)

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
        channel = token_manager.partneraddress_channel[partner_address.decode('hex')]
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
                e.address,
            )
            return

        identifier = None  # TODO: fix identifier
        task = StartExchangeTask(
            identifier,
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
        if not token_manager.channelgraph.has_path(self.raiden.address, target_bin):
            raise NoPathError('No path to address found')

        async_result = self.raiden.transfer_async(
            token_address_bin,
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
        channel = manager.partneraddress_channel[partner_address]

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
        channel = manager.partneraddress_channel[partner_address]

        if channel.isopen:
            raise InvalidState('channel is still open.')

        netting_channel = channel.external_state.netting_channel

        current_block = self.raiden.chain.block_number()
        settle_timeout = netting_channel.detail(self.raiden.address)['settle_timeout']
        settle_expiration = channel.external_state.closed_block + settle_timeout

        if current_block <= settle_expiration:
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

                secret = message.secret
                identifier = message.identifier
                token = message.token
                secret = message.secret
                hashlock = sha3(secret)

                self.raiden.handle_secret(
                    identifier,
                    token,
                    secret,
                    message,
                    hashlock,
                )
            except:  # pylint: disable=bare-except
                log.exception('Unhandled exception')

    def message_refundtransfer(self, message):
        self.raiden.message_for_task(message, message.lock.hashlock)

    def message_directtransfer(self, message):
        self.raiden.on_directtransfer_message(message)

    def message_mediatedtransfer(self, message):
        self.raiden.on_mediatedtransfer_message(message)


class StateMachineEventHandler(object):
    def __init__(self, raiden):
        self.raiden = raiden

    def on_event(self, event):
        if isinstance(event, SendMediatedTransfer):
            next_hop = event.node_address
            fee = 0

            manager = self.raiden.get_manager_by_token_address(event.token)
            channel = manager.partneraddress_channel[next_hop]

            mediated_transfer = channel.create_mediatedtransfer(
                self.raiden.address,
                event.target,
                fee,
                event.amount,
                event.message_id,
                event.expiration,
                event.hashlock,
            )

            self.raiden.sign(mediated_transfer)
            self.raiden.send_async(next_hop, mediated_transfer)

            # TODO: implement the network timeout raiden.config['msg_timeout']
            # and cancel the current transfer it hapens


class BlockchainEventsHandler(object):
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
                    self.on_log(originating_contract, event)
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

    def on_log(self, emitting_contract_address_bin, event):  # pylint: disable=unused-argument
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
