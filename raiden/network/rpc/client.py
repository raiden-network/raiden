# -*- coding: utf8 -*-
import string
import random

from ethereum import slogging

from raiden.utils import isaddress, sha3
from raiden.blockchain.net_contract import NettingChannelContract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
LETTERS = string.printable


def make_address():
    return bytes(''.join(random.choice(LETTERS) for _ in range(20)))


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=no-self-use,invalid-name,too-many-arguments
    def next_block(self):
        raise NotImplementedError()

    def new_channel_manager_contract(self, asset_address):
        raise NotImplementedError()

    def new_netting_contract(self, asset_address, peer1, peer2):
        raise NotImplementedError()

    @property
    def asset_addresses(self):
        raise NotImplementedError()

    def netting_addresses(self, asset_address):
        raise NotImplementedError()

    def addresses_by_asset(self, asset_address):
        raise NotImplementedError()

    def nettingaddresses_by_asset_participant(self, asset_address, participant_address):
        raise NotImplementedError()

    def netting_contract_detail(self, asset_address, contract_address, our_address):
        raise NotImplementedError()

    def isopen(self, asset_address, netting_contract_address):
        raise NotImplementedError()

    def deposit(self, asset_address, netting_contract_address, our_address, amount):
        raise NotImplementedError()

    def partner(self, asset_address, netting_contract_address, our_address):
        raise NotImplementedError()

    def close(self, asset_address, netting_contract_address, our_address,
              last_sent_transfers, ctx, *unlocked):
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

        our_balance = contract.participants[our_address]['deposit']
        partner_balance = contract.participants[partner_address]['deposit']

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
              last_sent_transfers, unlocked_transfers):  # pylint: disable=unused-argument,too-many-arguments

        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]

        ctx = {
            'block_number': self.block_number,
        }
        contract.close(our_address, last_sent_transfers, ctx, *unlocked_transfers)

    def settle(self, asset_address, netting_contract_address):
        hash_channel = self.asset_hashchannel[asset_address]
        contract = hash_channel[netting_contract_address]
        ctx = {
            'block_number': self.block_number,
        }
        contract.settle(ctx)
        # XXX: return?
