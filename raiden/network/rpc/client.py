# -*- coding: utf8 -*-
import string
import random
from collections import defaultdict
from itertools import count

from ethereum import slogging
from ethereum import _solidity
from ethereum.utils import denoms, privtoaddr, int_to_big_endian, encode_hex
from pyethapp.jsonrpc import address_decoder, data_decoder, quantity_encoder

from raiden.utils import isaddress, pex
from raiden.blockchain.net_contract import NettingChannelContract
from raiden.blockchain.events import channelnew_filter, channelnewbalance_filter
from raiden.blockchain.events import decode_topic
from raiden.blockchain.abi import (
    HUMAN_TOKEN_ABI,
    CHANNEL_MANAGER_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
LETTERS = string.printable
MOCK_REGISTRY_ADDRESS = '7265676973747279726567697374727972656769'

# GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT = 9 * 10 ** 10  # hack: temporarily fix for high gas usage in the registry contract
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')
GAS_PRICE = denoms.wei
DEFAULT_TIMEOUT = 3

FILTER_ID_GENERATOR = count()

solidity = _solidity.get_solidity()  # pylint: disable=invalid-name


def make_address():
    return bytes(''.join(random.choice(LETTERS) for _ in range(20)))


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes,unused-argument

    def __init__(self, jsonrpc_client, registry_address):
        self.address_asset = dict()
        self.address_manager = dict()
        self.address_contract = dict()
        self.address_registry = dict()
        self.asset_manager = dict()

        self.client = jsonrpc_client
        self.default_registry = self.registry(registry_address)

    def asset(self, asset_address):
        """ Return a proxy to interact with an asset. """
        if asset_address not in self.address_asset:
            self.address_asset[asset_address] = Asset(
                self.client,
                asset_address,
            )

        return self.address_asset[asset_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_contract:
            channel = NettingChannel(self.client, netting_channel_address)
            self.address_contract[netting_channel_address] = channel

        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_manager:
            manager = ChannelManager(self.client, manager_address)
            asset_address = manager.asset_address()

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.address_manager[manager_address]

    def manager_by_asset(self, asset_address):
        """ Find the channel manager for `asset_address` and return a proxy to interact with it. """
        if asset_address not in self.asset_manager:
            asset = self.asset(asset_address)  # check that the asset exists
            manager_address = self.default_registry.manager_address_by_asset(asset.address)
            manager = ChannelManager(self.client, manager_address)

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.asset_manager[asset_address]

    def registry(self, registry_address):
        if registry_address not in self.address_registry:
            self.address_registry[registry_address] = Registry(
                self.client,
                registry_address,
            )

        return self.address_registry[registry_address]

    def block_number(self):
        return self.client.blocknumber()

    def uninstall_filter(self, filter_id):
        self.client.call('eth_uninstallFilter', quantity_encoder(filter_id))


class Filter(object):
    def __init__(self, jsonrpc_client, filter_id):
        self.filter_id = filter_id
        self.client = jsonrpc_client

    def changes(self):
        filter_changes = self.client.get_filterchanges(
            'eth_getFilterChanges',
            quantity_encoder(self.filter_id),
        )

        result = list()
        for log_event in filter_changes:
            address = address_decoder(log_event['address'])
            data = data_decoder(log_event['data'])
            topics = [
                decode_topic(topic)
                for topic in log_event['topics']
            ]

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
            })

        return result

    def uninstall(self):
        self.client.call(
            'eth_uninstallFilter',
            quantity_encoder(self.filter_id),
        )


class Asset(object):
    def __init__(self, jsonrpc_client, asset_address, startgas=GAS_LIMIT,  # pylint: disable=too-many-arguments
                 gasprice=GAS_PRICE, timeout=DEFAULT_TIMEOUT):
        result = jsonrpc_client.call(
            'eth_getCode',
            asset_address.encode('hex'),
            'latest',
        )

        if result == '0x':
            raise ValueError('Address given for asset {} does not contain code'.format(
                asset_address.encode('hex'),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            HUMAN_TOKEN_ABI,
            asset_address.encode('hex'),
        )

        self.address = asset_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.timeout = timeout

    def approve(self, contract_address, allowance):
        """ Aprove `contract_address` to transfer up to `deposit` amount of token. """
        transaction_hash = self.proxy.approve.transact(
            contract_address,
            allowance,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.balanceOf.call(address)


class Registry(object):
    def __init__(self, jsonrpc_client, registry_address, startgas=GAS_LIMIT,  # pylint: disable=too-many-arguments
                 gasprice=GAS_PRICE, timeout=DEFAULT_TIMEOUT):
        result = jsonrpc_client.call(
            'eth_getCode',
            registry_address.encode('hex'),
            'latest',
        )

        if result == '0x':
            raise ValueError('Asset address {} does not contain code'.format(
                registry_address.encode('hex'),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            REGISTRY_ABI,
            registry_address.encode('hex'),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.timeout = timeout

    def manager_address_by_asset(self, asset_address):
        """ Return the channel manager address for the given asset. """
        return self.proxy.channelManagerByAsset.call(asset_address)

    def add_asset(self, asset_address):
        transaction_hash = self.proxy.addAsset(
            asset_address,
            startgas=self.startgas,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

        return self.proxy.channelManagerByAsset.call(
            asset_address,
            startgas=GAS_LIMIT,
        ).decode('hex')

    def asset_addresses(self):
        return [
            address.decode('hex')
            for address in self.proxy.assetAddresses.call(startgas=self.startgas)
        ]


class ChannelManager(object):
    def __init__(self, jsonrpc_client, manager_address, startgas=GAS_LIMIT,  # pylint: disable=too-many-arguments
                 gasprice=GAS_PRICE, timeout=DEFAULT_TIMEOUT):
        result = jsonrpc_client.call(
            'eth_getCode',
            manager_address.encode('hex'),
            'latest',
        )

        if result == '0x':
            raise ValueError('Channel manager address {} does not contain code'.format(
                manager_address.encode('hex'),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CHANNEL_MANAGER_ABI,
            manager_address.encode('hex'),
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.timeout = timeout

    def asset_address(self):
        """ Return the asset of this manager. """
        return self.proxy.assetToken.call()

    def new_channel(self, peer1, peer2, settle_timeout):
        if privtoaddr(self.client.privkey) == peer1:
            other = peer2
        else:
            other = peer1

        transaction_hash = self.proxy.newChannel.transact(
            other,
            settle_timeout,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

        address_encoded = self.proxy.get.call(
            other,
            startgas=GAS_LIMIT,
        )
        return address_encoded.decode('hex')

    def channels_addresses(self):
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.getAllChannels.call(startgas=self.startgas)

        channel_flat = [
            channel.decode('hex')
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def channels_by_participant(self, participant_address):  # pylint: disable=invalid-name
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.nettingContractsByAddress.call(
            participant_address,
            startgas=self.startgas,
        )

        return [
            address.decode('hex')
            for address in address_list
        ]

    def channelnew_filter(self, participant_address):
        """ Install a new filter for ChannelNew events.

        Return:
            Filter: The filter instance.
        """
        filter_id = channelnew_filter(
            self.proxy.address,
            participant_address,
            self.client,
        )
        return Filter(self.client, filter_id)


class NettingChannel(object):
    def __init__(self, jsonrpc_client, channel_address, startgas=GAS_LIMIT,  # pylint: disable=too-many-arguments
                 gasprice=GAS_PRICE, timeout=DEFAULT_TIMEOUT):
        result = jsonrpc_client.call(
            'eth_getCode',
            channel_address.encode('hex'),
            'latest',
        )

        if result == '0x':
            raise ValueError('Address given for netting channel {} does not contain code'.format(
                channel_address.encode('hex'),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            NETTING_CHANNEL_ABI,
            channel_address.encode('hex'),
        )

        self.address = channel_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.timeout = timeout

    def asset_address(self):
        return self.proxy.assetAddress.call()

    def detail(self, our_address):
        data = self.proxy.addressAndBalance.call(startgas=self.startgas)

        if data[0].decode('hex') == our_address:
            return {
                'our_address': data[0].decode('hex'),
                'our_balance': data[1],
                'partner_address': data[2].decode('hex'),
                'partner_balance': data[3],
            }

        if data[2].decode('hex') == our_address:
            return {
                'our_address': data[2].decode('hex'),
                'our_balance': data[3],
                'partner_address': data[0].decode('hex'),
                'partner_balance': data[1],
            }

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def settle_timeout(self):
        settle_timeout = self.proxy.settleTimeout.call()
        return settle_timeout

    def isopen(self):
        if self.proxy.closed(startgas=self.startgas) != 0:
            return False

        return self.proxy.opened(startgas=self.startgas) != 0

    def partner(self, our_address):
        data = self.proxy.addressAndBalance.call(startgas=GAS_LIMIT)

        if data[0].decode('hex') == our_address:
            return data[2].decode('hex')

        if data[2].decode('hex') == our_address:
            return data[0].decode('hex')

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def deposit(self, amount):
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        transaction_hash = self.proxy.deposit.transact(
            amount,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

    def close(self, our_address, first_transfer, second_transfer):
        raise NotImplementedError()

    def settle(self):
        raise NotImplementedError()

    def channelnewbalance_filter(self):
        filter_id = channelnewbalance_filter(
            self.proxy.address,
            self.client.address,
            self.client,
        )
        return Filter(self.client, filter_id)


class BlockChainServiceMock(object):
    """ Mock implementation of BlockChainService that doesn't do JSON-RPC and
    doesn't require a running node.

    A mock block chain, the user can assume that this mock represents
    up-to-date information.

    The actions that the user can perform on the blockchain are:

        - Transfer money to a contract/channel to create it
        - Create a new channel, by executing an exiting contract

        - Call a method in an existing channel (close and settle)
        - List existing  channels for a given address (?)

    Note:
        This class is built for testing purposes.
    """
    # HACK: Using a singleton to share state among all nodes in a test
    _instance = None

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        # This check was added to force proper cleanup (set _instance to
        # None at the end of each test)
        if cls._instance is None:
            raise Exception(
                'Do not instantiate this class directly, use the '
                'blockchain_service fixture'
            )

        if cls._instance is True:
            blockchain_service = super(BlockChainServiceMock, cls).__new__(cls, *args, **kwargs)

            # __init__ is executed multiple times, so we need to do the
            # initializatoin here (otherwise the values would be overwritten)
            blockchain_service.block_number_ = 0
            blockchain_service.address_asset = dict()
            blockchain_service.address_manager = dict()
            blockchain_service.address_contract = dict()
            blockchain_service.address_registry = dict()
            blockchain_service.asset_manager = dict()

            registry = RegistryMock(
                blockchain_service,
                address=MOCK_REGISTRY_ADDRESS,
            )
            blockchain_service.default_registry = registry
            blockchain_service.address_registry[MOCK_REGISTRY_ADDRESS] = registry

            cls._instance = blockchain_service

        return cls._instance
    # /HACK

    # Note: all these methods need to be "atomic" because the mock is going to
    # be used by multiple clients. Not using blocking functions should be
    # sufficient
    def __init__(self, jsonrpc_client, registry_address, timeout=None):
        pass

    def next_block(self):
        """ Equivalent to the mining of a new block.

        Note:
            This method does not create any representation of the new block, it
            just increases current block number. This is necessary since the
            channel contract needs the current block number to decide if the
            closing of a channel can be closed or not.
        """
        self.block_number_ += 1

    def block_number(self):
        return self.block_number_

    def asset(self, asset_address):
        return self.address_asset[asset_address]

    def netting_channel(self, netting_channel_address):
        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        return self.address_manager[manager_address]

    def manager_by_asset(self, asset_address):
        return self.asset_manager[asset_address]

    def registry(self, registry_address):
        return self.address_registry[registry_address]

    def uninstall_filter(self, filter_id):
        pass


class FilterMock(object):
    def __init__(self, jsonrpc_client, filter_id):
        self.filter_id = filter_id
        self.client = jsonrpc_client
        self.events = list()

    def changes(self):
        events = self.events
        self.events = list()
        return events

    def event(self, event):
        self.events.append(event)

    def uninstall(self):
        self.events = list()


class AssetMock(object):
    def __init__(self, blockchain, address=None):
        self.address = address or make_address()
        self.blockchain = blockchain

        self.contract_allowance = defaultdict(int)

    def approve(self, contract_address, allowance):
        self.contract_allowance[contract_address] += allowance

    def balance_of(self, address):  # pylint: disable=unused-argument,no-self-use
        return float('inf')


class RegistryMock(object):
    def __init__(self, blockchain, address=None):
        self.address = address or make_address()
        self.blockchain = blockchain

        self.asset_manager = dict()
        self.address_asset = dict()

    def manager_address_by_asset(self, asset_address):
        return self.asset_manager[asset_address].address

    def add_asset(self, asset_address):
        """ The equivalent of instatiating a new `ChannelManagerContract`
        contract that will manage channels for a given asset in the blockchain.

        Raises:
            ValueError: If asset_address is not a valid address or is already registered.
        """
        if asset_address in self.address_asset:
            raise ValueError('duplicated address {}'.format(encode_hex(asset_address)))

        asset = AssetMock(self.blockchain, address=asset_address)
        manager = ChannelManagerMock(self.blockchain, asset_address)

        self.address_asset[asset_address] = asset
        self.asset_manager[asset_address] = manager

        self.blockchain.address_asset[asset_address] = asset
        self.blockchain.address_manager[manager.address] = manager
        self.blockchain.asset_manager[asset_address] = manager

    def asset_addresses(self):
        return self.address_asset.keys()


class ChannelManagerMock(object):
    def __init__(self, blockchain, asset_address, address=None):
        self.address = address or make_address()
        self.blockchain = blockchain

        self.asset_address_ = asset_address
        self.pair_channel = dict()
        self.participant_channels = defaultdict(list)
        self.participant_filter = defaultdict(list)
        self.address_filter = defaultdict(list)

    def asset_address(self):
        return self.asset_address_

    def new_netting_channel(self, peer1, peer2, settle_timeout):
        """ Creates a new netting contract between peer1 and peer2.

        Raises:
            ValueError: If peer1 or peer2 is not a valid address.
        """
        if not isaddress(peer1):
            raise ValueError('The pee1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        pair = tuple(sorted((peer1, peer2)))
        if pair in self.pair_channel:
            raise ValueError('({}, {}) already have a channel'.format(
                encode_hex(peer1),
                encode_hex(peer2)
            ))

        channel = NettingChannelMock(
            self.blockchain,
            self.asset_address(),
            peer1,
            peer2,
            settle_timeout,
        )
        self.pair_channel[pair] = channel
        self.participant_channels[peer1].append(channel)
        self.participant_channels[peer2].append(channel)

        self.blockchain.address_contract[channel.address] = channel

        # generate the events
        for filter_ in self.address_filter[peer1]:
            filter_.event()

        for filter_ in self.address_filter[peer2]:
            filter_.event()

        return channel.address

    def channels_addresses(self):
        return self.pair_channel.keys()

    def channels_by_participant(self, peer_address):
        return [
            channel.address
            for channel in self.participant_channels[peer_address]
        ]

    def channelnew_filter(self, participant_address):
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.address_filter[participant_address] = filter_
        return filter_


class NettingChannelMock(object):
    def __init__(self, blockchain, asset_address, peer1, peer2, settle_timeout,  # pylint: disable=too-many-arguments
                 address=None):
        self.address = address or make_address()
        self.blockchain = blockchain

        self.contract = NettingChannelContract(
            asset_address,
            self.address,
            peer1,
            peer2,
            settle_timeout,
        )

    def asset_address(self):
        return self.contract.asset_address

    def detail(self, our_address):
        partner_address = self.contract.partner(our_address)

        our_balance = self.contract.participants[our_address].deposit
        partner_balance = self.contract.participants[partner_address].deposit

        return {
            'our_address': our_address,
            'our_balance': our_balance,
            'partner_address': partner_address,
            'partner_balance': partner_balance,
            'settle_timeout': self.contract.settle_timeout,
        }

    def settle_timeout(self):
        return self.contract.settle_timeout

    def isopen(self):
        return self.contract.isopen

    def partner(self, our_address):
        return self.contract.partner(our_address)

    def deposit(self, our_address, amount):
        self.contract.deposit(our_address, amount, self.blockchain.block_number())

    def close(self, our_address, first_transfer, second_transfer):
        ctx = {
            'block_number': self.blockchain.block_number(),
            'msg.sender': our_address,
        }

        first_encoded = None
        second_encoded = None

        if first_transfer is not None:
            first_encoded = first_transfer.encode()

        if second_transfer is not None:
            second_encoded = second_transfer.encode()

        self.contract.close(
            ctx,
            first_encoded,
            second_encoded,
        )

    def update_transfer(self, our_address, transfer):
        ctx = {
            'block_number': self.blockchain.block_number(),
            'msg.sender': our_address,
        }

        if transfer is not None:
            self.contract.update_transfer(
                ctx,
                transfer.encode(),
            )

    def unlock(self, our_address, unlocked_transfers):
        ctx = {
            'block_number': self.blockchain.block_number(),
            'msg.sender': our_address,
        }

        for merkle_proof, locked_encoded, secret in unlocked_transfers:
            merkleproof_encoded = ''.join(merkle_proof)

            self.contract.unlock(
                ctx,
                locked_encoded,
                merkleproof_encoded,
                secret,
            )

    def settle(self):
        ctx = {
            'block_number': self.blockchain.block_number(),
        }
        self.contract.settle(ctx)

    def channelnewbalance_filter(self):
        raise NotImplementedError()
