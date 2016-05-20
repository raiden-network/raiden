# -*- coding: utf8 -*-
import os
import string
import random

from ethereum import slogging
from ethereum import _solidity
from ethereum.utils import sha3
from pyethapp.rpc_client import JSONRPCClient

import raiden
from raiden.utils import isaddress
from raiden.blockchain.net_contract import NettingChannelContract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
LETTERS = string.printable

solidity = _solidity.get_solidity()  # pylint: disable=invalid-name


def make_address():
    return bytes(''.join(random.choice(LETTERS) for _ in range(20)))


def get_contract_path(contract_name):
    project_directory = os.path.dirname(raiden.__file__)
    contract_path = os.path.join(project_directory, 'smart_contracts', contract_name)
    return os.path.realpath(contract_path)


def get_abi_from_file(filename):
    with open(filename) as handler:
        code = handler.read()
        return solidity.mk_full_signature(code)


def get_code_signature(filename, libraries=None):
    with open(filename) as handler:
        code = handler.read()
        signature = solidity.mk_full_signature(code)

        if libraries is not None:
            bytecode = solidity.compile(code, libraries=libraries)
        else:
            bytecode = solidity.compile(code)

        return (bytecode, signature)


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """

    def __init__(self, host_port, privkey, address, registry_address):
        """
        Args:
            host_port (Tuple[(str, int)]): two-tuple with the (address, host)
                of the JSON-RPC server.
        """
        channel_manager_abi = get_abi_from_file(get_contract_path('channelManagerContract.sol'))
        netting_contract_abi = get_abi_from_file(get_contract_path('nettingChannelContract.sol'))
        registry_abi = get_abi_from_file(get_contract_path('registry.sol'))

        jsonrpc_client = JSONRPCClient(
            sender=address,
            privkey=privkey,
        )

        registry_proxy = jsonrpc_client.new_abi_contract(registry_abi, registry_address)

        self.asset_managerproxy = dict()
        self.contract_by_address = dict()

        self.host_port = host_port
        self.privkey = privkey
        self.client = jsonrpc_client

        self.registry_address = registry_address
        self.registry_proxy = registry_proxy

        self.channel_manager_abi = channel_manager_abi
        self.netting_contract_abi = netting_contract_abi
        self.registry_abi = registry_abi

        if not self._code_exists(registry_address):
            raise ValueError('Registry {} does not exists'.format(registry_address))

    def _code_exists(self, address):
        """ Return True if the address contains code, False otherwise. """
        result = client.call('eth_getCode', address, 'latest')

        return result != '0x'

    def _get_manager(self, asset_address):
        if asset_address not in self.asset_managerproxy:
            if not self._code_exists(asset_address):
                raise ValueError('The asset {} does not exists'.format(asset_address))

            manager_address = self.registry_proxy.channelManagerByAsset(asset_address)

            if not self._code_exists(manager_address):
                # The registry returned an address that has no code!
                raise ValueError('Got unexpected address from the contract.')

            manager_proxy = self.client.new_abi_contract(self.channel_manager_abi, manager_address)
            self.asset_managerproxy[asset_address] = manager_proxy

        return self.asset_managerproxy[asset_address]

    def _get_contract(self, netting_contract_address):
        if netting_contract_address not in self.contract_by_address:
            if not self._code_exists(netting_contract_address):
                raise ValueError('The contract {} does not exists.'.format(netting_contract_address))

            contract_proxy = self.client.new_abi_contract(self.netting_contract_abi, netting_contract_address)
            self.contract_by_address[netting_contract_address] = contract_proxy

        return self.contract_by_address[netting_contract_address]

    # CALLS

    @property
    def asset_addresses(self):
        return self.registry_proxy.assetAddresses.call()

    def netting_addresses(self, asset_address):
        raise NotImplementedError()

    def addresses_by_asset(self, asset_address):
        raise NotImplementedError()

    def nettingaddresses_by_asset_participant(self, asset_address, participant_address):
        manager_proxy = self._get_manager(asset_address)
        return manager_proxy.nettingContractsByAddress.call(asset_address)

    def netting_contract_detail(self, asset_address, contract_address, our_address):
        raise NotImplementedError()

    def isopen(self, asset_address, netting_contract_address):
        contract_proxy = self._get_contract(netting_contract_address)
        return contract_proxy.isOpen.call()

    def partner(self, asset_address, netting_contract_address, our_address):
        contract = self._get_contract(netting_contract_address)
        return contract.nettingContractsByAddress.call(our_address)

    # TRANSACTIONS

    def new_channel_manager_contract(self, asset_address):
        raise NotImplementedError()

    def new_netting_contract(self, asset_address, peer1, peer2):
        raise NotImplementedError()

    def deposit(self, asset_address, netting_contract_address, our_address, amount):
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        contract_proxy = self._get_contract(netting_contract_address)
        transaction_hash = contract_proxy.deposit.transact(value=amount)
        self.proxy.poll(transaction_hash.decode('hex'))

    def close(self, asset_address, netting_contract_address, our_address,
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
        Useful for testing
    """

    # Note: all these methods need to be "atomic" because the mock is going to
    # be used by multiple clients. Not using blocking functions should be
    # sufficient

    def __init__(self):
        self.block_number = 0
        self.asset_hashchannel = dict()
        self.asset_address = dict()

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

    def new_netting_contract(self, asset_address, peer1, peer2):
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

        channel = NettingChannelContract(asset_address, netcontract_address, peer1, peer2)
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
