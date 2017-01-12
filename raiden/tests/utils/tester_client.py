# -*- coding: utf-8 -*-
from collections import defaultdict
from itertools import count

from ethereum import tester, slogging, _solidity
from ethereum.abi import ContractTranslator
from ethereum.utils import decode_hex, encode_hex
from pyethapp.jsonrpc import address_decoder
from pyethapp.rpc_client import deploy_dependencies_symbols, dependencies_order_of_build

from raiden import messages
from raiden.utils import (
    get_contract_path,
    isaddress,
    pex,
    privatekey_to_address,
    get_encoded_transfers
)
from raiden.blockchain.abi import (
    ASSETADDED_EVENTID,
    CHANNEL_MANAGER_ABI,
    CHANNELNEW_EVENTID,
    CHANNELNEWBALANCE_EVENTID,
    CHANNELSECRETREVEALED_EVENTID,
    CHANNELCLOSED_EVENTID,
    CHANNELSETTLED_EVENTID,
    ENDPOINT_REGISTRY_ABI,
    HUMAN_TOKEN_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
FILTER_ID_GENERATOR = count()

# NOTE: mine after each transaction to reset block.gas_used


def tester_deploy_contract(tester_state, private_key, contract_name,
                           contract_file, constructor_parameters=None):
    contract_path = get_contract_path(contract_file)
    all_contracts = _solidity.compile_file(contract_path, libraries=dict())

    contract = all_contracts[contract_name]
    contract_interface = contract['abi']

    log.info('Deploying "{}" contract'.format(contract_file))

    dependencies = deploy_dependencies_symbols(all_contracts)
    deployment_order = dependencies_order_of_build(contract_name, dependencies)

    log.info('Deploing dependencies: {}'.format(str(deployment_order)))
    deployment_order.pop()  # remove `contract_name` from the list
    libraries = dict()

    for deploy_contract in deployment_order:
        dependency_contract = all_contracts[deploy_contract]

        hex_bytecode = _solidity.solidity_resolve_symbols(
            dependency_contract['bin_hex'],
            libraries,
        )
        bytecode = decode_hex(hex_bytecode)

        dependency_contract['bin_hex'] = hex_bytecode
        dependency_contract['bin'] = bytecode

        log.info('Creating contract {}'.format(deploy_contract))
        contract_address = tester_state.evm(
            bytecode,
            private_key,
            endowment=0,
        )
        tester_state.mine(number_of_blocks=1)

        if len(tester_state.block.get_code(contract_address)) == 0:
            raise Exception('Contract code empty')

        libraries[deploy_contract] = encode_hex(contract_address)

    hex_bytecode = _solidity.solidity_resolve_symbols(contract['bin_hex'], libraries)
    bytecode = hex_bytecode.decode('hex')

    contract['bin_hex'] = hex_bytecode
    contract['bin'] = bytecode

    if constructor_parameters:
        translator = ContractTranslator(contract_interface)
        parameters = translator.encode_constructor_arguments(constructor_parameters)
        bytecode = contract['bin'] + parameters
    else:
        bytecode = contract['bin']

    log.info('Creating contract {}'.format(contract_name))
    contract_address = tester_state.evm(
        bytecode,
        private_key,
        endowment=0,
    )
    tester_state.mine(number_of_blocks=1)

    if len(tester_state.block.get_code(contract_address)) == 0:
        raise Exception('Contract code empty')

    return contract_address


class ChannelExternalStateTester(object):
    def __init__(self, tester_state, private_key, address):
        self.tester_state = tester_state
        self.proxy = NettingChannelTesterMock(
            tester_state,
            private_key,
            address,
        )

        self.callbacks_on_opened = list()
        self.callbacks_on_closed = list()
        self.callbacks_on_settled = list()
        self.hashlock_channel = defaultdict(list)

    def get_block_number(self):
        return self.tester_state.block.number

    @property
    def opened_block(self):
        return self.proxy.opened()

    def closed_block(self):
        return self.proxy.closed()

    def settled_block(self):
        return self.proxy.settled()

    def isopen(self):
        return self.proxy.isopen()

    def update_transfer(self, our_address, first_transfer, second_transfer=None):
        return self.proxy.update_transfer(our_address, first_transfer, second_transfer)

    def unlock(self, our_address, unlock_proofs):
        return self.proxy.unlock(our_address, unlock_proofs)

    def settle(self):
        return self.proxy.settle()

    def register_channel_for_hashlock(self, channel, hashlock):
        channels_registered = self.hashlock_channel[hashlock]

        if channel not in channels_registered:
            channels_registered.append(channel)

    def callback_on_opened(self, callback):
        self.callbacks_on_opened.append(callback)

    def callback_on_closed(self, callback):
        self.callbacks_on_closed.append(callback)

    def callback_on_settled(self, callback):
        self.callbacks_on_settled.append(callback)


class FilterTesterMock(object):
    def __init__(self, contract_address, topics, filter_id_raw):
        self.filter_id_raw = filter_id_raw
        self.contract_address = contract_address
        self.topics = topics
        self.events = list()

    def changes(self):
        events = self.events
        self.events = list()
        return events

    def event(self, event):
        # TODO: implement OR
        if event.topics == self.topics and event.address == self.contract_address:
            self.events.append({
                'topics': event.topics,
                'data': event.data,
                'address': event.address,
            })

            # TODO: update all event listeners to update the app's states.

    def uninstall(self):
        self.events = list()


class BlockChainServiceTesterMock(object):
    def __init__(self, private_key, tester_state, registry_address, **kwargs):
        self.tester_state = tester_state
        default_registry = RegistryTesterMock(tester_state, private_key, registry_address)

        self.address = privatekey_to_address(private_key)
        self.private_key = private_key
        self.default_registry = default_registry

        self.address_asset = dict()
        self.address_discovery = dict()
        self.address_manager = dict()
        self.address_contract = dict()
        self.address_registry = dict()
        self.asset_manager = dict()

    def set_verbosity(self, level):
        pass

    def block_number(self):
        return self.tester_state.block.number

    def next_block(self):
        self.tester_state.mine(number_of_blocks=1)
        return self.tester_state.block.number

    def asset(self, asset_address):
        """ Return a proxy to interact with an asset. """
        if asset_address not in self.address_asset:
            self.address_asset[asset_address] = AssetTesterMock(
                self.tester_state,
                self.private_key,
                asset_address,
            )

        return self.address_asset[asset_address]

    def discovery(self, discovery_address):
        if discovery_address not in self.address_discovery:
            self.address_discovery[discovery_address] = DiscoveryTesterMock(
                self.tester_state,
                self.private_key,
                discovery_address,
            )

        return self.address_discovery[discovery_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_contract:
            channel = NettingChannelTesterMock(
                self.tester_state,
                self.private_key,
                netting_channel_address,
            )
            self.address_contract[netting_channel_address] = channel

        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_manager:
            manager = ChannelManagerTesterMock(
                self.tester_state,
                self.private_key,
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
                self.private_key,
                manager_address,
            )

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.asset_manager[asset_address]

    def registry(self, registry_address):
        if registry_address not in self.address_registry:
            self.address_registry[registry_address] = RegistryTesterMock(
                self.tester_state,
                self.private_key,
                registry_address,
            )

        return self.address_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        pass

    def deploy_contract(self, contract_name, contract_file, constructor_parameters=None):
        return tester_deploy_contract(
            self.tester_state,
            self.private_key,
            contract_name,
            contract_file,
            constructor_parameters,
        )

    def deploy_and_register_asset(self, contract_name, contract_file, constructor_parameters=None):
        assert self.default_registry

        token_address = self.deploy_contract(
            contract_name,
            contract_file,
            constructor_parameters,
        )
        self.default_registry.add_asset(token_address)  # pylint: disable=no-member

        return token_address


class DiscoveryTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        if len(tester_state.block.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_state,
            ENDPOINT_REGISTRY_ABI,
            address,
            default_key=private_key,
        )

    def register_endpoint(self, node_address, endpoint):
        if node_address != privatekey_to_address(self.private_key):
            raise ValueError('node_address doesnt match this node address')

        self.proxy.registerEndpoint(endpoint)
        self.tester_state.mine(number_of_blocks=1)

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = node_address_bin.encode('hex')
        endpoint = self.proxy.findEndpointByAddress(node_address_hex)

        if endpoint is '':
            raise KeyError('Unknow address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')


class AssetTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        if len(tester_state.block.get_code(address)) == 0:
            raise Exception('Contract code empty')

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
        self.tester_state.mine(number_of_blocks=1)

    def balance_of(self, address):
        result = self.proxy.balanceOf(address)
        self.tester_state.mine(number_of_blocks=1)
        return result

    def transfer(self, address_to, amount):
        self.proxy.transfer(address_to, amount)
        self.tester_state.mine(number_of_blocks=1)


class RegistryTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        if len(tester_state.block.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_state = tester_state
        self.private_key = private_key

        self.registry_proxy = tester.ABIContract(
            self.tester_state,
            REGISTRY_ABI,
            self.address,
            default_key=private_key,
        )
        self.assetadded_filters = list()

    def manager_address_by_asset(self, asset_address):
        channel_manager_address_hex = self.registry_proxy.channelManagerByAsset(asset_address)
        self.tester_state.mine(number_of_blocks=1)
        return channel_manager_address_hex.decode('hex')

    def add_asset(self, asset_address):
        self.registry_proxy.addAsset(asset_address)
        self.tester_state.mine(number_of_blocks=1)

    def asset_addresses(self):
        result = [
            address.decode('hex')
            for address in self.registry_proxy.assetAddresses()
        ]
        self.tester_state.mine(number_of_blocks=1)
        return result

    def manager_addresses(self):
        result = [
            address.decode('hex')
            for address in self.registry_proxy.channelManagerAddresses()
        ]
        self.tester_state.mine(number_of_blocks=1)
        return result

    def assetadded_filter(self):
        topics = [ASSETADDED_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_


class ChannelManagerTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        if len(tester_state.block.get_code(address)) == 0:
            raise Exception('Contract code empty')

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
        self.tester_state.mine(number_of_blocks=1)
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

        if privatekey_to_address(self.private_key) == peer1:
            other = peer2
        else:
            other = peer1

        netting_channel_address_hex = self.proxy.newChannel(other, settle_timeout)
        self.tester_state.mine(number_of_blocks=1)

        channel = NettingChannelTesterMock(
            self.tester_state,
            self.private_key,
            netting_channel_address_hex,
        )

        return decode_hex(channel.address)

    def channels_addresses(self):
        channel_flat_encoded = self.proxy.getChannelsParticipants()
        self.tester_state.mine(number_of_blocks=1)

        channel_flat = [
            channel.decode('hex')
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def channels_by_participant(self, peer_address):
        result = [
            address_decoder(address)
            for address in self.proxy.nettingContractsByAddress(peer_address)
        ]
        self.tester_state.mine(number_of_blocks=1)
        return result

    def channelnew_filter(self):
        topics = [CHANNELNEW_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_


class NettingChannelTesterMock(object):
    def __init__(self, tester_state, private_key, address):
        if len(tester_state.block.get_code(address)) == 0:
            raise Exception('Contract code empty')

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

        # check we are a participant of the channel
        self.detail(privatekey_to_address(private_key))

    def asset_address(self):
        result = address_decoder(self.proxy.assetAddress())
        self.tester_state.mine(number_of_blocks=1)
        return result

    def settle_timeout(self):
        result = self.proxy.settleTimeout()
        self.tester_state.mine(number_of_blocks=1)
        return result

    def isopen(self):
        # do not mine in this method
        closed = self.proxy.closed()

        if closed != 0:
            return False

        opened = self.proxy.opened()

        return opened != 0

    def partner(self, our_address):
        result = address_decoder(self.proxy.partner(our_address))
        self.tester_state.mine(number_of_blocks=1)
        return result

    def deposit(self, our_address, amount):
        if privatekey_to_address(self.private_key) != our_address:
            raise ValueError('our_address doesnt match the privatekey')

        asset = AssetTesterMock(
            self.tester_state,
            self.private_key,
            self.asset_address(),
        )
        current_balance = asset.balance_of(privatekey_to_address(self.private_key))

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        self.proxy.deposit(amount)
        self.tester_state.mine(number_of_blocks=1)

    def opened(self):
        opened = self.proxy.opened()
        self.tester_state.mine(number_of_blocks=1)
        return opened

    def closed(self):
        closed = self.proxy.closed()
        self.tester_state.mine(number_of_blocks=1)
        return closed

    def settled(self):
        settled = self.proxy.settled()
        self.tester_state.mine(number_of_blocks=1)
        return settled

    def detail(self, our_address):
        data = self.proxy.addressAndBalance()
        self.tester_state.mine(number_of_blocks=1)

        settle_timeout = self.proxy.settleTimeout()
        self.tester_state.mine(number_of_blocks=1)

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

    def close(self, our_address, their_transfer, our_transfer):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        their_encoded, our_encoded = get_encoded_transfers(their_transfer, our_transfer)
        self.proxy.close(
            their_encoded,
            our_encoded,
        )
        self.tester_state.mine(number_of_blocks=1)
        log.info(
            'close called',
            contract=pex(self.address),
            their_transfer=their_transfer,
            our_transfer=our_transfer,
        )

    def update_transfer(self, our_address, first_transfer):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        if first_transfer is not None:
            first_encoded = first_transfer.encode()
            self.proxy.updateTransfer(first_encoded)
            self.tester_state.mine(number_of_blocks=1)

        log.info(
            'update_transfer called',
            contract=pex(self.address),
            first_transfer=first_transfer
        )

    def unlock(self, our_address, unlock_proofs):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)
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
            self.tester_state.mine(number_of_blocks=1)

            lock = messages.Lock.from_bytes(locked_encoded)
            log.info(
                'unlock called',
                contract=pex(self.address),
                lock=lock,
                secret=encode_hex(secret),
            )

    def settle(self):
        self.proxy.settle()
        self.tester_state.mine(number_of_blocks=1)

    def channelnewbalance_filter(self):
        topics = [CHANNELNEWBALANCE_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_

    def channelsecretrevealed_filter(self):
        topics = [CHANNELSECRETREVEALED_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_

    def channelclosed_filter(self):
        topics = [CHANNELCLOSED_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_

    def channelsettled_filter(self):
        topics = [CHANNELSETTLED_EVENTID]
        filter_ = FilterTesterMock(self.address, topics, next(FILTER_ID_GENERATOR))
        self.tester_state.block.log_listeners.append(filter_.event)
        return filter_
