# -*- coding: utf-8 -*-
import logging
from binascii import hexlify, unhexlify

from ethereum import slogging

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_REGISTRY,

    EVENT_TOKEN_ADDED,
)
from raiden.exceptions import (
    NoTokenManager,
    TransactionThrew,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    isaddress,
    pex,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.network.proxies.channel_manager import ChannelManager
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class Registry:
    def __init__(
            self,
            jsonrpc_client,
            registry_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(registry_address):
            raise ValueError('registry_address must be a valid address')

        check_address_has_code(jsonrpc_client, registry_address, 'Registry')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY),
            address_encoder(registry_address),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout

        self.address_to_channelmanager = dict()
        self.token_to_channelmanager = dict()

    def manager_address_by_token(self, token_address):
        """ Return the channel manager address for the given token or None if
        there is no correspoding address.
        """
        address = self.proxy.call(
            'channelManagerByToken',
            token_address,
        )

        if address == b'':
            check_address_has_code(self.client, self.address)
            return None

        return address_decoder(address)

    def add_token(self, token_address):
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        transaction_hash = estimate_and_transact(
            self.proxy,
            'addToken',
            token_address,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('AddToken', receipt_or_none)

        manager_address = self.manager_address_by_token(token_address)

        if manager_address is None:
            log.error('Transaction failed and check_transaction_threw didnt detect it')
            raise RuntimeError('channelManagerByToken failed')

        if log.isEnabledFor(logging.INFO):
            log.info(
                'add_token called',
                token_address=pex(token_address),
                registry_address=pex(self.address),
                manager_address=pex(manager_address),
            )

        return manager_address

    def token_addresses(self):
        return [
            address_decoder(address)
            for address in self.proxy.call('tokenAddresses')
        ]

    def manager_addresses(self):
        return [
            address_decoder(address)
            for address in self.proxy.call('channelManagerAddresses')
        ]

    def tokenadded_filter(self, from_block=None, to_block=None):
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_TOKEN_ADDED)]

        registry_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            registry_address_bin,
            topics,
            from_block=from_block,
            to_block=to_block,
        )

        return Filter(
            self.client,
            filter_id_raw,
        )

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if not isaddress(manager_address):
            raise ValueError('manager_address must be a valid address')

        if manager_address not in self.address_to_channelmanager:
            manager = ChannelManager(
                self.client,
                manager_address,
                self.poll_timeout,
            )

            token_address = manager.token_address()

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.address_to_channelmanager[manager_address]

    def manager_by_token(self, token_address):
        """ Find the channel manager for `token_address` and return a proxy to
        interact with it.

        If the token is not already registered it raises `EthNodeCommunicationError`,
        since we try to instantiate a Channel manager with an empty address.
        """
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        if token_address not in self.token_to_channelmanager:
            check_address_has_code(self.client, token_address)  # check that the token exists
            manager_address = self.manager_address_by_token(token_address)

            if manager_address is None:
                raise NoTokenManager(
                    'Manager for token 0x{} does not exist'.format(hexlify(token_address))
                )

            manager = ChannelManager(
                self.client,
                manager_address,
                self.poll_timeout,
            )

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.token_to_channelmanager[token_address]
