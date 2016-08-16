# -*- coding: utf8 -*-
from collections import defaultdict
from itertools import count

from ethereum.utils import encode_hex

from raiden import messages
from raiden.utils import isaddress, make_address
from raiden.blockchain.net_contract import NettingChannelContract

MOCK_REGISTRY_ADDRESS = '7265676973747279726567697374727972656769'
FILTER_ID_GENERATOR = count()


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

            # do not start at 0, since that is taken as the default None value
            # for uint in the smart contract
            blockchain_service.block_number_ = 1
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
    def __init__(self, privatekey_bin, registry_address, **kwargs):
        self.privatekey_bin = privatekey_bin

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

    def uninstall_filter(self, filter_id_raw):
        pass


class FilterMock(object):
    def __init__(self, jsonrpc_client, filter_id_raw):
        self.filter_id_raw = filter_id_raw
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

    def transfer(self, address_to, amount):
        pass


class RegistryMock(object):
    def __init__(self, blockchain, address=None):
        self.address = address or make_address()
        self.blockchain = blockchain

        self.asset_manager = dict()
        self.address_asset = dict()
        self.assetadded_filters = list()

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

    def manager_addresses(self):
        return [
            manager.address
            for manager in self.asset_manager.values()
        ]

    def assetadded_filter(self):
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.assetadded_filters.append(filter_)
        return filter_


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

        self.newbalance_filters = list()
        self.secretrevealed_filters = list()
        self.channelclose_filters = list()
        self.channelsettle_filters = list()

    def asset_address(self):
        return self.contract.asset_address

    def settle_timeout(self):
        return self.contract.settle_timeout

    def isopen(self):
        return self.contract.isopen

    def partner(self, our_address):
        return self.contract.partner(our_address)

    def deposit(self, our_address, amount):
        self.contract.deposit(our_address, amount, self.blockchain.block_number())

    def opened(self):
        return self.contract.opened

    def closed(self):
        return self.contract.closed

    def settled(self):
        return self.contract.settled

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

    def unlock(self, our_address, unlock_proofs):
        ctx = {
            'block_number': self.blockchain.block_number(),
            'msg.sender': our_address,
        }

        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

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
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.newbalance_filters.append(filter_)
        return filter_

    def channelsecretrevealed_filter(self):
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.secretrevealed_filters.append(filter_)
        return filter_

    def channelclosed_filter(self):
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.channelclose_filters.append(filter_)
        return filter_

    def channelsettled_filter(self):
        filter_ = FilterMock(None, next(FILTER_ID_GENERATOR))
        self.channelsettle_filters.append(filter_)
        return filter_
