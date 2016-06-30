# -*- coding: utf8 -*-
import os
import string
import random

from ethereum import slogging

from ethereum import _solidity
from ethereum.utils import sha3, privtoaddr, int_to_big_endian

import raiden
from raiden.utils import isaddress, pex
from raiden.blockchain.net_contract import NettingChannelContract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
LETTERS = string.printable
MOCK_REGISTRY_ADDRESS = '7265676973747279726567697374727972656769'
GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')

solidity = _solidity.get_solidity()  # pylint: disable=invalid-name


def make_address():
    return bytes(''.join(random.choice(LETTERS) for _ in range(20)))


def get_contract_path(contract_name):
    project_directory = os.path.dirname(raiden.__file__)
    contract_path = os.path.join(project_directory, 'smart_contracts', contract_name)
    return os.path.realpath(contract_path)


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes,unused-argument

    def __init__(self, jsonrpc_client, registry_address, timeout=None):
        asset_compiled = _solidity.compile_contract(
            get_contract_path('HumanStandardToken.sol'),
            'HumanStandardToken',
            combined='abi',
        )

        channel_manager_compiled = _solidity.compile_contract(
            get_contract_path('ChannelManagerContract.sol'),
            'ChannelManagerContract',
            combined='abi',
        )

        netting_channel_compiled = _solidity.compile_contract(
            get_contract_path('NettingChannelContract.sol'),
            'NettingChannelContract',
            combined='abi',
        )

        registry_compiled = _solidity.compile_contract(
            get_contract_path('Registry.sol'),
            'Registry',
            combined='abi',
        )

        asset_abi = asset_compiled['abi']
        """ The HumanStandardToken abi definition. """
        channel_manager_abi = channel_manager_compiled['abi']
        """ The ChannelManagerContract abi definition. """
        netting_contract_abi = netting_channel_compiled['abi']
        """ The NettingContract abi definition. """
        registry_abi = registry_compiled['abi']
        """ The Registry abi definition. """

        registry_proxy = jsonrpc_client.new_contract_proxy(
            registry_abi,
            registry_address.encode('hex'),
        )

        self.assets = dict()
        self.asset_managerproxy = dict()
        self.contract_by_address = dict()

        self.client = jsonrpc_client

        self.registry_address = registry_address
        self.registry_proxy = registry_proxy
        self.timeout = timeout

        self.asset_abi = asset_abi
        self.channel_manager_abi = channel_manager_abi
        self.netting_contract_abi = netting_contract_abi
        self.registry_abi = registry_abi

        if not self._code_exists(registry_address.encode('hex')):
            raise ValueError('Registry {} does not exists'.format(registry_address))

    def _code_exists(self, address):
        """ Return True if the address contains code, False otherwise. """
        result = self.client.call('eth_getCode', address, 'latest')

        return result != '0x'

    def _get_asset(self, asset_address):
        if asset_address not in self.assets:
            if not self._code_exists(asset_address.encode('hex')):
                raise ValueError('The asset {} does not exists'.format(asset_address))

            asset_proxy = self.client.new_abi_contract(self.asset_abi, asset_address.encode('hex'))
            self.assets[asset_address] = asset_proxy

        return self.assets[asset_address]

    def _get_manager(self, asset_address):
        if asset_address not in self.asset_managerproxy:
            if not self._code_exists(asset_address.encode('hex')):
                raise ValueError('The asset {} does not exists'.format(asset_address))

            manager_address = self.registry_proxy.channelManagerByAsset.call(asset_address)

            if not self._code_exists(manager_address):
                # The registry returned an address that has no code!
                raise ValueError('Got unexpected address from the contract.')

            manager_proxy = self.client.new_abi_contract(self.channel_manager_abi, manager_address)
            self.asset_managerproxy[asset_address] = manager_proxy

        return self.asset_managerproxy[asset_address]

    def _get_contract(self, netting_contract_address):
        if netting_contract_address not in self.contract_by_address:
            if not self._code_exists(netting_contract_address.encode('hex')):
                msg = 'The contract {} does not exists.'.format(netting_contract_address)
                raise ValueError(msg)

            contract_proxy = self.client.new_abi_contract(
                self.netting_contract_abi,
                netting_contract_address,
            )
            self.contract_by_address[netting_contract_address] = contract_proxy

        return self.contract_by_address[netting_contract_address]

    # CALLS

    @property
    def asset_addresses(self):
        return [
            address.decode('hex')
            for address in self.registry_proxy.assetAddresses.call(startgas=GAS_LIMIT)
        ]

    @property
    def block_number(self):
        return self.client.blocknumber()

    def netting_addresses(self, asset_address):
        raise NotImplementedError()

    def addresses_by_asset(self, asset_address):
        manager_proxy = self._get_manager(asset_address)

        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = manager_proxy.getAllChannels.call(startgas=GAS_LIMIT)

        channel_flat = [
            channel.decode('hex')
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def nettingaddresses_by_asset_participant(self, asset_address, participant_address):  # pylint: disable=invalid-name
        manager_proxy = self._get_manager(asset_address)

        address_list = manager_proxy.nettingContractsByAddress.call(
            participant_address,
            startgas=GAS_LIMIT,
        )

        return [
            address.decode('hex')
            for address in address_list
        ]

    def netting_contract_detail(self, asset_address, netting_contract_address, our_address):
        contract_proxy = self._get_contract(netting_contract_address)
        data = contract_proxy.addrAndDep.call(startgas=GAS_LIMIT)

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

    def netting_contract_settle_timeout(self, asset_address, netting_contract_address):
        contract_proxy = self._get_contract(netting_contract_address)
        return contract_proxy.lockedTime.call()

    def isopen(self, asset_address, netting_contract_address):
        contract_proxy = self._get_contract(netting_contract_address)

        if contract_proxy.closed(startgas=GAS_LIMIT) != 0:
            return False

        return contract_proxy.opened(startgas=GAS_LIMIT) != 0

    def partner(self, asset_address, netting_contract_address, our_address):
        contract_proxy = self._get_contract(netting_contract_address)
        data = contract_proxy.addrAndDep.call(startgas=GAS_LIMIT)

        if data[0].decode('hex') == our_address:
            return data[2].decode('hex')
        return data[0].decode('hex')

    # TRANSACTIONS

    def new_channel_manager_contract(self, asset_address):
        transaction_hash = self.registry_proxy.addAsset(
            asset_address,
            startgas=GAS_LIMIT,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

        return self.registry_proxy.channelManagerByAsset.call(
            asset_address,
            startgas=GAS_LIMIT,
        ).decode('hex')

    def new_netting_contract(self, asset_address, peer1, peer2, settle_timeout):
        channel_manager_proxy = self._get_manager(asset_address)

        if privtoaddr(self.client.privkey) == peer1:
            other = peer2
        else:
            other = peer1

        transaction_hash = channel_manager_proxy.newChannel.transact(
            other,
            settle_timeout,
            startgas=GAS_LIMIT,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.timeout)

        address_encoded = channel_manager_proxy.get.call(
            other,
            startgas=GAS_LIMIT,
        )
        return address_encoded.decode('hex')

    def asset_approve(self, asset_address, netcontract_address, deposit):
        asset_proxy = self._get_asset(asset_address)
        transaction_hash = asset_proxy.approve.transact(
            netcontract_address,
            deposit,
            startgas=GAS_LIMIT,
        )
        self.client.poll(transaction_hash.decode('hex'))

    def deposit(self, asset_address, netting_contract_address, our_address, amount):
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        contract_proxy = self._get_contract(netting_contract_address)
        transaction_hash = contract_proxy.deposit.transact(
            amount,
            startgas=GAS_LIMIT,
        )
        self.client.poll(transaction_hash.decode('hex'))

    def close(self, asset_address, netting_contract_address, our_address,  # pylint: disable=too-many-arguments
              first_transfer, second_transfer):
        raise NotImplementedError()

    def settle(self, asset_address, netting_contract_address):
        raise NotImplementedError()


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
            blockchain_service.block_number = 0
            blockchain_service.asset_hashchannel = dict()
            blockchain_service.asset_address = dict()

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
        self.block_number += 1

    def new_channel_manager_contract(self, asset_address):
        """ The equivalent of instatiating a new `ChannelManagerContract`
        contract that will manage channels for a given asset in the blockchain.

        Raises:
            ValueError: If asset_address is not a valid address or is already registered.
        """
        if not isaddress(asset_address):
            raise ValueError('The asset must be a valid address')

        if asset_address in self.asset_hashchannel:
            raise ValueError('This asset already has a registered contract')

        manager_address = make_address()
        self.asset_hashchannel[asset_address] = dict()
        self.asset_address[asset_address] = manager_address
        return manager_address

    def new_netting_contract(self, asset_address, peer1, peer2, settle_timeout):
        """ Creates a new netting contract between peer1 and peer2.

        Raises:
            ValueError: If peer1 or peer2 is not a valid address.
        """
        if not isaddress(peer1):
            raise ValueError('The pee1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        netcontract_address = bytes(sha3(peer1 + peer2)[:20])
        hash_channel = self.asset_hashchannel[asset_address]

        if netcontract_address in hash_channel:
            raise ValueError('netting contract already exists')

        channel = NettingChannelContract(
            asset_address,
            netcontract_address,
            peer1,
            peer2,
            settle_timeout,
        )
        hash_channel[netcontract_address] = channel
        return netcontract_address

    @property
    def asset_addresses(self):
        """ Return all assets addresses that have a managing contract
        associated with it.
        """
        return self.asset_hashchannel.keys()

    def netting_addresses(self, asset_address):
        """ Return all netting contract addreses for the given `asset_address`. """
        return self.asset_hashchannel[asset_address].keys()

    def netting_contract_settle_timeout(self, asset_address, netting_contract_address):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]
        return contract.settle_timeout

    # this information is required for building the network graph used for
    # routing
    def addresses_by_asset(self, asset_address):
        """ Return a list of two-tuples `(address1, address2)`, where each tuple
        is an existing open channel in the network for the given `asset_address`.
        """
        hash_channel = self.asset_hashchannel[asset_address]

        return [
            channel.participants.keys()
            for channel in hash_channel.values()
        ]

    def nettingaddresses_by_asset_participant(self, asset_address, participant_address):  # pylint: disable=invalid-name
        """ Return all channels for a given asset that `participant_address` is
        a participant.
        """
        if asset_address not in self.asset_hashchannel:
            raise ValueError('Unknow asset {}'.format(asset_address.encode('hex')))

        asset_manager = self.asset_hashchannel[asset_address]

        return [
            channel.netcontract_address
            for channel in asset_manager.values()
            if participant_address in channel.participants
        ]

    def netting_contract_detail(self, asset_address, contract_address, our_address):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[contract_address]

        our_address = our_address
        partner_address = contract.partner(our_address)

        our_balance = contract.participants[our_address].deposit
        partner_balance = contract.participants[partner_address].deposit

        return {
            'our_address': our_address,
            'our_balance': our_balance,
            'partner_address': partner_address,
            'partner_balance': partner_balance,
        }

    def isopen(self, asset_address, netting_contract_address):
        """ Return the current status of the channel. """
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        return contract.isopen

    def asset_approve(self, asset_address, netcontract_address, deposit):
        pass

    def deposit(self, asset_address, netting_contract_address, our_address, amount):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        contract.deposit(our_address, amount, self.block_number)

    def partner(self, asset_address, netting_contract_address, our_address):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]
        return contract.partner(our_address)

    def close(self, asset_address, netting_contract_address, our_address,  # pylint: disable=unused-argument,too-many-arguments
              first_transfer, second_transfer):  # pylint: disable=unused-argument,too-many-arguments

        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        ctx = {
            'block_number': self.block_number,
            'msg.sender': our_address,
        }

        first_encoded = None
        second_encoded = None

        if first_transfer is not None:
            first_encoded = first_transfer.encode()

        if second_transfer is not None:
            second_encoded = second_transfer.encode()

        contract.close(
            ctx,
            first_encoded,
            second_encoded,
        )

    def update_transfer(self, asset_address, netting_contract_address, our_address, transfer):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        ctx = {
            'block_number': self.block_number,
            'msg.sender': our_address,
        }

        if transfer is not None:
            contract.update_transfer(
                ctx,
                transfer.encode(),
            )

    def unlock(self, asset_address, netting_contract_address, our_address,  # pylint: disable=unused-argument,too-many-arguments
               unlocked_transfers):  # pylint: disable=unused-argument,too-many-arguments

        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        ctx = {
            'block_number': self.block_number,
            'msg.sender': our_address,
        }

        for merkle_proof, locked_encoded, secret in unlocked_transfers:
            merkleproof_encoded = ''.join(merkle_proof)

            contract.unlock(
                ctx,
                locked_encoded,
                merkleproof_encoded,
                secret,
            )

    def settle(self, asset_address, netting_contract_address):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]
        ctx = {
            'block_number': self.block_number,
        }
        contract.settle(ctx)
