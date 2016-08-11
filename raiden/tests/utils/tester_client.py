# -*- coding: utf8 -*-
from collections import defaultdict
from itertools import count

from ethereum import tester, slogging
from ethereum.utils import encode_hex, privtoaddr
from pyethapp.jsonrpc import address_encoder, address_decoder

from raiden import messages
from raiden.blockchain.abi import get_contract_path
from raiden.utils import pex, isaddress
from raiden.blockchain.abi import (
    HUMAN_TOKEN_ABI,
    CHANNEL_MANAGER_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
FILTER_ID_GENERATOR = count()


def deploy_registry(tester_state):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    netting_library_address = tester_state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
    )

    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    channelmanager_library_address = tester_state.contract(
        None,
        path=channelmanager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': address_encoder(netting_library_address),
        }
    )

    registry_path = get_contract_path('Registry.sol')
    registry_address = tester_state.contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        libraries={
            'ChannelManagerLibrary': address_encoder(channelmanager_library_address)
        }
    )
    return registry_address


class FilterTesterMock(object):
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


class BlockChainServiceTesterMock(object):
    def __init__(self, privatekey, registry_address, **kwargs):
        # self.tester_state = tester.state()
        # registry_address = deploy_registry(self.tester_state)
        default_registry = RegistryTesterMock(self, registry_address)

        self.privatekey = privatekey
        self.default_registry = default_registry

        self.address_asset = dict()
        self.address_manager = dict()
        self.address_contract = dict()
        self.address_registry = dict()
        self.asset_manager = dict()

    def next_block(self):
        self.tester_state.mine(number_of_blocks=1)

    def block_number(self):
        return self.tester_state.block.number

    def asset(self, asset_address):
        """ Return a proxy to interact with an asset. """
        if asset_address not in self.address_asset:
            self.address_asset[asset_address] = AssetTesterMock(
                self.tester_state,
                self.privatekey,
                asset_address,
            )

        return self.address_asset[asset_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_contract:
            channel = NettingChannelTesterMock(
                self.tester_state,
                self.privatekey,
                netting_channel_address,
            )
            self.address_contract[netting_channel_address] = channel

        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_manager:
            manager = ChannelManagerTesterMock(
                self.tester_state,
                self.privatekey,
                manager_address,
            )

            asset_address = manager.asset_address()

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.address_manager[manager_address]

    def manager_by_asset(self, asset_address):
        """ Find the channel manager for `asset_address` and return a proxy to
        interact with it.
        """
        if asset_address not in self.asset_manager:
            manager_address = self.default_registry.manager_address_by_asset(asset_address)
            manager = ChannelManagerTesterMock(
                self.tester_state,
                self.privatekey,
                address_decoder(manager_address),
            )

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.asset_manager[asset_address]

    def registry(self, registry_address):
        if registry_address not in self.address_registry:
            self.address_registry[registry_address] = RegistryTesterMock(
                self.tester_state,
                self.privatekey,
                registry_address,
            )

        return self.address_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        pass


class AssetTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_state,
            HUMAN_TOKEN_ABI,
            address,
            default_key=private_key,
        )

    def approve(self, contract_address, allowance):
        self.proxy.approve(contract_address, allowance)

    def balance_of(self, address):
        self.proxy.balanceOf(address)


class RegistryTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.registry_proxy = tester.ABIContract(
            self.tester_state,
            REGISTRY_ABI,
            self.address,
            default_key=self.blockchain.privatekey,
        )
        self.assetadded_filters = list()

    def manager_address_by_asset(self, asset_address):
        channel_manager_address_hex = self.registry_proxy.channelManagerByAsset(asset_address)
        return channel_manager_address_hex.decode('hex')

    def add_asset(self, asset_address):
        self.registry_proxy.addAsset(asset_address)

    def asset_addresses(self):
        return [
            address.decode('hex')
            for address in self.registry_proxy.assetAddresses()
        ]

    def manager_addresses(self):
        return [
            address.decode('hex')
            for address in self.registry_proxy.channelManagerAddresses()
        ]

    def assetadded_filter(self):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.assetadded_filters.append(filter_)
        return filter_


class ChannelManagerTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_state,
            CHANNEL_MANAGER_ABI,
            address,
            default_key=private_key,
        )
        self.participant_filter = defaultdict(list)
        self.address_filter = defaultdict(list)

    def asset_address(self):
        asset_address_hex = self.proxy.tokenAddress()
        asset_address = address_decoder(asset_address_hex)
        return asset_address

    def new_netting_channel(self, peer1, peer2, settle_timeout):
        """ Creates a new netting contract between peer1 and peer2.

        Raises:
            ValueError: If peer1 or peer2 is not a valid address.
        """
        if not isaddress(peer1):
            raise ValueError('The pee1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        if privtoaddr(self.private_key) == peer1:
            other = peer2
        else:
            other = peer1

        netting_channel_address_hex = self.proxy.newChannel(other, settle_timeout)

        channel = NettingChannelTesterMock(
            self.tester_state,
            self.private_key,
            netting_channel_address_hex,
        )

        self.blockchain.address_contract[channel.address] = channel

        # generate the events
        for filter_ in self.address_filter[peer1]:
            filter_.event()

        for filter_ in self.address_filter[peer2]:
            filter_.event()

        return channel.address

    def channels_addresses(self):
        channel_flat_encoded = self.proxy.getChannelsParticipants()

        channel_flat = [
            channel.decode('hex')
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def channels_by_participant(self, peer_address):
        return [
            address_decoder(address)
            for address in self.proxy.nettingContractsByAddress(peer_address)
        ]

    def channelnew_filter(self, participant_address):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.address_filter[participant_address] = filter_
        return filter_


class NettingChannelTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_state,
            NETTING_CHANNEL_ABI,
            address,
            default_key=private_key,
        )

        self.newbalance_filters = list()
        self.secretrevealed_filters = list()
        self.channelclose_filters = list()
        self.channelsettle_filters = list()

    def asset_address(self):
        return address_decoder(self.proxy.assetAddress())

    def settle_timeout(self):
        return self.proxy.settleTimeout()

    def isopen(self):
        if self.proxy.closed() != 0:
            return False

        return self.proxy.opened() != 0

    def partner(self, our_address):
        return address_decoder(self.proxy.partner(our_address))

    def deposit(self, our_address, amount):
        self.proxy.deposit(amount)

    def opened(self):
        return self.proxy.opened()

    def closed(self):
        return self.proxy.closed()

    def settled(self):
        return self.proxy.settled()

    def detail(self, our_address):
        data = self.proxy.addressAndBalance()
        settle_timeout = self.proxy.settleTimeout()

        if address_decoder(data[0]) == our_address:
            return {
                'our_address': address_decoder(data[0]),
                'our_balance': data[1],
                'partner_address': address_decoder(data[2]),
                'partner_balance': data[3],
                'settle_timeout': settle_timeout,
            }

        if address_decoder(data[2]) == our_address:
            return {
                'our_address': address_decoder(data[2]),
                'our_balance': data[3],
                'partner_address': address_decoder(data[0]),
                'partner_balance': data[1],
                'settle_timeout': settle_timeout,
            }

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def close(self, our_address, first_transfer, second_transfer):
        if first_transfer and second_transfer:
            first_encoded = first_transfer.encode()
            second_encoded = second_transfer.encode()

            self.proxy.close(
                first_encoded,
                second_encoded,
            )
            log.info('close called', contract=pex(self.address), first_transfer=first_transfer, second_transfer=second_transfer)

        elif first_transfer:
            first_encoded = first_transfer.encode()

            self.proxy.closeSingleTransfer(first_encoded)
            log.info('close called', contract=pex(self.address), first_transfer=first_transfer)

        elif second_transfer:
            second_encoded = second_transfer.encode()

            self.proxy.closeSingleTransfer.transact(second_encoded)
            log.info('close called', contract=pex(self.address), second_transfer=second_transfer)

        else:
            # TODO: allow to close nevertheless
            raise ValueError('channel wasnt used')

    def update_transfer(self, our_address, transfer):
        if transfer is not None:
            transfer_encoded = transfer.encode()
            self.proxy.updateTransfer(transfer_encoded)

        log.info('update_transfer called', contract=pex(self.address), transfer=transfer)

    def unlock(self, our_address, unlock_proofs):
        unlock_proofs = list(unlock_proofs)  # force a list to get the length (could be a generator)
        log.info('{} locks to unlock'.format(len(unlock_proofs)), contract=pex(self.address))

        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

            merkleproof_encoded = ''.join(merkle_proof)

            self.proxy.unlock(
                locked_encoded,
                merkleproof_encoded,
                secret,
            )

            lock = messages.Lock.from_bytes(locked_encoded)
            log.info('unlock called', contract=pex(self.address), lock=lock, secret=encode_hex(secret))

    def settle(self):
        self.proxy.settle()

    def channelnewbalance_filter(self):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.newbalance_filters.append(filter_)
        return filter_

    def channelsecretrevealed_filter(self):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.secretrevealed_filters.append(filter_)
        return filter_

    def channelclosed_filter(self):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.channelclose_filters.append(filter_)
        return filter_

    def channelsettled_filter(self):
        filter_ = FilterTesterMock(None, next(FILTER_ID_GENERATOR))
        self.channelsettle_filters.append(filter_)
        return filter_
