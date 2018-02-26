# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify
import os
from collections import defaultdict
from itertools import count

from ethereum import slogging
from ethereum.tools import tester, _solidity
from ethereum.tools.tester import TransactionFailed
from ethereum.abi import ContractTranslator
from ethereum.utils import encode_hex
from ethereum.tools._solidity import solidity_get_contract_key

from raiden import messages
from raiden.exceptions import (
    AddressWithoutCode,
    UnknownAddress,
    DuplicatedChannelError,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    isaddress,
    pex,
    privatekey_to_address,
    sha3,
)
from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_HUMAN_STANDARD_TOKEN,
    CONTRACT_NETTING_CHANNEL,
    CONTRACT_REGISTRY,

    EVENT_CHANNEL_NEW,
    EVENT_TOKEN_ADDED,
)
from raiden.network.rpc.client import (
    deploy_dependencies_symbols,
    dependencies_order_of_build,
)
from raiden.exceptions import SamePeerAddress

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
FILTER_ID_GENERATOR = count()

# NOTE: mine after each transaction to reset block.gas_used


def tester_deploy_contract(
        tester_chain,
        private_key,
        contract_name,
        contract_path,
        constructor_parameters=None):

    all_contracts = _solidity.compile_file(contract_path, libraries=dict())

    contract_key = solidity_get_contract_key(all_contracts, contract_path, contract_name)
    contract = all_contracts[contract_key]
    contract_interface = contract['abi']

    log.info('Deploying "{}" contract'.format(os.path.basename(contract_path)))

    dependencies = deploy_dependencies_symbols(all_contracts)
    deployment_order = dependencies_order_of_build(contract_key, dependencies)

    log.info('Deploying dependencies: {}'.format(str(deployment_order)))
    deployment_order.pop()  # remove `contract_name` from the list
    libraries = dict()

    for deploy_contract in deployment_order:
        dependency_contract = all_contracts[deploy_contract]

        hex_bytecode = _solidity.solidity_resolve_symbols(
            dependency_contract['bin_hex'],
            libraries,
        )
        bytecode = unhexlify(hex_bytecode)

        dependency_contract['bin_hex'] = hex_bytecode
        dependency_contract['bin'] = bytecode

        log.info('Creating contract {}'.format(deploy_contract))
        contract_address = tester_chain.contract(bytecode, language='evm', sender=private_key)
        tester_chain.mine(number_of_blocks=1)

        if len(tester_chain.head_state.get_code(contract_address)) == 0:
            raise Exception('Contract code empty')

        libraries[deploy_contract] = encode_hex(contract_address)

    hex_bytecode = _solidity.solidity_resolve_symbols(contract['bin_hex'], libraries)
    bytecode = unhexlify(hex_bytecode)

    contract['bin_hex'] = hex_bytecode
    contract['bin'] = bytecode

    if constructor_parameters:
        translator = ContractTranslator(contract_interface)
        parameters = translator.encode_constructor_arguments(constructor_parameters)
        bytecode = contract['bin'] + parameters
    else:
        bytecode = contract['bin']

    log.info('Creating contract {}'.format(contract_name))
    contract_address = tester_chain.contract(bytecode, language='evm', sender=private_key)
    tester_chain.mine(number_of_blocks=1)

    if len(tester_chain.head_state.get_code(contract_address)) == 0:
        raise Exception('Contract code empty')

    return contract_address


class ChannelExternalStateTester:
    def __init__(self, tester_chain, private_key, address):
        self.tester_chain = tester_chain
        self.netting_channel = NettingChannelTesterMock(
            tester_chain,
            private_key,
            address,
        )
        self.settled_block = 0

        self.callbacks_on_opened = list()
        self.callbacks_on_closed = list()
        self.callbacks_on_settled = list()
        self.hashlocks_channels = defaultdict(list)

    def get_block_number(self):
        return self.tester_chain.block.number

    @property
    def opened_block(self):
        return self.netting_channel.opened()

    @property
    def closed_block(self):
        return self.netting_channel.closed()

    def can_transfer(self):
        return self.netting_channel.can_transfer()

    def update_transfer(self, partner_transfer):
        nonce = partner_transfer.nonce
        transferred_amount = partner_transfer.transferred_amount
        locksroot = partner_transfer.locksroot
        signature = partner_transfer.signature

        packed = partner_transfer.packed()
        message_hash = sha3(packed.data[:-65])

        return self.netting_channel.update_transfer(
            nonce,
            transferred_amount,
            locksroot,
            message_hash,
            signature,
        )

    def withdraw(self, unlock_proofs):
        return self.netting_channel.withdraw(unlock_proofs)

    def settle(self):
        return self.netting_channel.settle()

    def register_channel_for_hashlock(self, channel, hashlock):
        channels_registered = self.hashlocks_channels[hashlock]

        if channel not in channels_registered:
            channels_registered.append(channel)


class FilterTesterMock:
    def __init__(self, tester_chain, contract_address, topics, filter_id_raw):
        self.tester_chain = tester_chain
        self.filter_id_raw = filter_id_raw
        self.contract_address = contract_address
        self.topics = topics
        self.events = list()

    def changes(self):
        events = self.events
        self.events = list()
        return events

    def getall(self):
        events = self.events
        return events

    def event(self, event):
        # TODO: implement OR
        valid_address = event.address == self.contract_address
        valid_topics = (
            self.topics is None or
            event.topics == self.topics
        )

        if valid_topics and valid_address:
            block_number = getattr(event, 'block_number', None) or self.tester_chain.block.number
            self.events.append({
                'topics': event.topics,
                'data': event.data,
                'address': event.address,
                'block_number': block_number,
            })

            # TODO: update all event listeners to update the app's states.

    def uninstall(self):
        self.events = list()


class ClientMock:
    def __init__(self):
        self.stop_event = None

    def inject_stop_event(self, event):
        self.stop_event = event


class BlockChainServiceTesterMock:
    def __init__(self, private_key, tester_chain):
        self.tester_chain = tester_chain

        self.address = privatekey_to_address(private_key)
        self.private_key = private_key
        self.node_address = privatekey_to_address(private_key)

        self.address_to_token = dict()
        self.address_to_discovery = dict()
        self.address_to_nettingchannel = dict()
        self.address_to_registry = dict()
        self.client = ClientMock()

    def block_number(self):
        return self.tester_chain.block.number

    def is_synced(self):
        return True

    def next_block(self):
        self.tester_chain.mine(number_of_blocks=1)
        return self.tester_chain.block.number

    def estimate_blocktime(self, *args):  # pylint: disable=no-self-use
        return 1

    def token(self, token_address):
        """ Return a proxy to interact with an token. """
        if token_address not in self.address_to_token:
            self.address_to_token[token_address] = TokenTesterMock(
                self.tester_chain,
                self.private_key,
                token_address,
            )

        return self.address_to_token[token_address]

    def discovery(self, discovery_address):
        if discovery_address not in self.address_to_discovery:
            self.address_to_discovery[discovery_address] = DiscoveryTesterMock(
                self.tester_chain,
                self.private_key,
                discovery_address,
            )

        return self.address_to_discovery[discovery_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_to_nettingchannel:
            channel = NettingChannelTesterMock(
                self.tester_chain,
                self.private_key,
                netting_channel_address,
            )
            self.address_to_nettingchannel[netting_channel_address] = channel

        return self.address_to_nettingchannel[netting_channel_address]

    def registry(self, registry_address):
        if registry_address not in self.address_to_registry:
            self.address_to_registry[registry_address] = RegistryTesterMock(
                self.tester_chain,
                self.private_key,
                registry_address,
            )

        return self.address_to_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        pass

    def deploy_contract(self, contract_name, contract_path, constructor_parameters=None):
        return tester_deploy_contract(
            self.tester_chain,
            self.private_key,
            contract_name,
            contract_path,
            constructor_parameters,
        )

    def deploy_and_register_token(
            self,
            registry,
            contract_name,
            contract_path,
            constructor_parameters=None):
        token_address = self.deploy_contract(
            contract_name,
            contract_path,
            constructor_parameters,
        )
        registry.add_token(token_address)

        return token_address


class DiscoveryTesterMock:
    def __init__(self, tester_chain, private_key, address):
        if len(tester_chain.head_state.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_chain = tester_chain
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_chain,
            CONTRACT_MANAGER.get_abi(CONTRACT_ENDPOINT_REGISTRY),
            address
        )

    def register_endpoint(self, node_address, endpoint):
        if node_address != privatekey_to_address(self.private_key):
            raise ValueError('node_address doesnt match this node address')

        self.proxy.registerEndpoint(endpoint)
        self.tester_chain.mine(number_of_blocks=1)

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = hexlify(node_address_bin)
        endpoint = self.proxy.findEndpointByAddress(node_address_hex)

        if endpoint is b'':
            raise UnknownAddress('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')

    def version(self):
        return self.proxy.contract_version()


class TokenTesterMock:
    def __init__(self, tester_chain, private_key, address):
        if len(tester_chain.head_state.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_chain = tester_chain
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_chain,
            CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN),
            address
        )

    def approve(self, contract_address, allowance):
        self.proxy.approve(contract_address, allowance, sender=self.private_key)
        self.tester_chain.mine(number_of_blocks=1)

    def balance_of(self, address):
        return self.proxy.balanceOf(address)

    def transfer(self, address_to, amount):
        self.proxy.transfer(address_to, amount, sender=self.private_key)
        self.tester_chain.mine(number_of_blocks=1)


class RegistryTesterMock:
    def __init__(self, tester_chain, private_key, address):
        if len(tester_chain.head_state.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_chain = tester_chain
        self.private_key = private_key

        self.registry_proxy = tester.ABIContract(
            self.tester_chain,
            CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY),
            self.address
        )
        self.tokenadded_filters = list()

        self.address_to_channelmanager = dict()
        self.token_to_channelmanager = dict()

    def manager_address_by_token(self, token_address):
        channel_manager_address_hex = self.registry_proxy.channelManagerByToken(token_address)
        return channel_manager_address_hex

    def add_token(self, token_address):
        self.registry_proxy.addToken(token_address)
        self.tester_chain.mine(number_of_blocks=1)
        channel_manager_address_hex = self.registry_proxy.channelManagerByToken(token_address)
        return channel_manager_address_hex

    def token_addresses(self):
        result = [
            address_decoder(address)
            for address in self.registry_proxy.tokenAddresses()
        ]
        return result

    def manager_addresses(self):
        result = [
            address_decoder(address)
            for address in self.registry_proxy.channelManagerAddresses()
        ]
        return result

    def tokenadded_filter(self, **kwargs):
        """May also receive from_block, to_block but they are not used here"""
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_TOKEN_ADDED)]
        filter_ = FilterTesterMock(
            self.tester_chain,
            self.address,
            topics,
            next(FILTER_ID_GENERATOR)
        )
        self.tester_chain.head_state.log_listeners.append(filter_.event)
        return filter_

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_to_channelmanager:
            manager = ChannelManagerTesterMock(
                self.tester_chain,
                self.private_key,
                manager_address,
            )

            token_address = manager.token_address()

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.address_to_channelmanager[manager_address]

    def manager_by_token(self, token_address):
        """ Find the channel manager for `token_address` and return a proxy to
        interact with it.

        If the token is not already registered it raises `TransactionFailed` when
        we do `self.registry_proxy.channelManagerByToken(token_address)`
        """
        if token_address not in self.token_to_channelmanager:
            manager_address = self.manager_address_by_token(token_address)
            manager = ChannelManagerTesterMock(
                self.tester_chain,
                self.private_key,
                manager_address,
            )

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.token_to_channelmanager[token_address]


class ChannelManagerTesterMock:
    def __init__(self, tester_chain, private_key, address):
        if len(tester_chain.head_state.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_chain = tester_chain
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_chain,
            CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
            address
        )
        self.participant_filter = defaultdict(list)
        self.address_filter = defaultdict(list)

    def token_address(self):
        token_address_hex = self.proxy.tokenAddress()
        token_address = address_decoder(token_address_hex)
        return token_address

    def new_netting_channel(self, other_peer, settle_timeout):
        """ Creates a new netting contract between peer1 and peer2.

        Raises:
            ValueError: If other_peer is not a valid address.
        """
        if not isaddress(other_peer):
            raise ValueError('The other_peer must be a valid address')

        local_address = privatekey_to_address(self.private_key)
        if local_address == other_peer:
            raise SamePeerAddress('The other peer must not have the same address as the client.')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        try:
            netting_channel_address_hex = self.proxy.newChannel(
                other_peer,
                settle_timeout,
                sender=self.private_key
            )
        except TransactionFailed:
            raise DuplicatedChannelError('Duplicated channel')

        self.tester_chain.mine(number_of_blocks=1)

        channel = NettingChannelTesterMock(
            self.tester_chain,
            self.private_key,
            netting_channel_address_hex,
        )

        return address_decoder(channel.address)

    def channels_addresses(self):
        channel_flat_encoded = self.proxy.getChannelsParticipants()

        channel_flat = [
            channel.decode('hex')
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return list(zip(channel_iter, channel_iter))

    def channels_by_participant(self, peer_address):
        result = [
            address_decoder(address)
            for address in self.proxy.nettingContractsByAddress(peer_address)
        ]
        return result

    def channelnew_filter(self):
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]
        filter_ = FilterTesterMock(
            self.tester_chain,
            self.address,
            topics,
            next(FILTER_ID_GENERATOR)
        )
        self.tester_chain.head_state.log_listeners.append(filter_.event)
        return filter_


class NettingChannelTesterMock:
    def __init__(self, tester_chain, private_key, address):
        if len(tester_chain.head_state.get_code(address)) == 0:
            raise Exception('Contract code empty')

        self.address = address
        self.tester_chain = tester_chain
        self.private_key = private_key

        self.proxy = tester.ABIContract(
            tester_chain,
            CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL),
            address
        )

        self.newbalance_filters = list()
        self.secretrevealed_filters = list()
        self.channelclose_filters = list()
        self.channelsettle_filters = list()

        # check we are a participant of the channel
        self.detail()

    def token_address(self):
        result = address_decoder(self.proxy.tokenAddress())
        return result

    def settle_timeout(self):
        result = self.proxy.settleTimeout()
        return result

    def can_transfer(self):
        # do not mine in this method
        closed = self.closed()

        if closed != 0:
            return False

        return self.detail()['our_balance'] > 0

    def deposit(self, amount):
        self._check_exists()
        token = TokenTesterMock(
            self.tester_chain,
            self.private_key,
            self.token_address(),
        )
        current_balance = token.balance_of(privatekey_to_address(self.private_key))

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        self.proxy.deposit(amount, sender=self.private_key)
        self.tester_chain.mine(number_of_blocks=1)

    def _check_exists(self):
        if self.tester_chain.head_state.get_code(self.address) == b'':
            raise AddressWithoutCode('Netting channel address {} does not contain code'.format(
                address_encoder(self.address),
            ))

    def opened(self):
        self._check_exists()
        opened = self.proxy.opened()
        assert isinstance(opened, int), 'opened must not be None nor empty string'
        return opened

    def closed(self):
        self._check_exists()
        closed = self.proxy.closed()
        assert isinstance(closed, int), 'closed must not be None nor empty string'
        return closed

    def closing_address(self):
        """Returns the address of the participant that called close, or None if the channel is
        not closed.
        """
        self._check_exists()
        closing_address = self.proxy.closingAddress()
        if closing_address is not None:
            return address_decoder(closing_address)

    def detail(self):
        """ FIXME: 'our_address' is only needed for the pure python mock implementation """
        self._check_exists()

        data = self.proxy.addressAndBalance()
        settle_timeout = self.proxy.settleTimeout()
        our_address = privatekey_to_address(self.private_key)

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

    def close(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        # this transaction may fail if there is a race to close the channel
        self._check_exists()

        log.info(
            'closing channel',
            contract=pex(self.proxy.address),
            nonce=nonce,
            transferred_amount=transferred_amount,
            locksroot=locksroot,
            extra_hash=extra_hash,
            signature=signature,
        )

        self.proxy.close(
            nonce,
            transferred_amount,
            locksroot,
            extra_hash,
            signature,
        )
        self.tester_chain.mine(number_of_blocks=1)

        log.info(
            'close sucessfull',
            contract=pex(self.proxy.address),
            nonce=nonce,
            transferred_amount=transferred_amount,
            locksroot=pex(locksroot),
            extra_hash=pex(extra_hash),
            signature=pex(signature),
        )

    def update_transfer(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        self._check_exists()
        if signature:
            log.info(
                'update_transfer called',
                contract=pex(self.proxy.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=locksroot,
                extra_hash=extra_hash,
                signature=signature,
            )

            self.proxy.updateTransfer(
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature,
            )
            self.tester_chain.mine(number_of_blocks=1)

            log.info(
                'update_transfer sucessfull',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=locksroot,
                extra_hash=extra_hash,
                signature=signature,
            )

    def withdraw(self, unlock_proofs):
        self._check_exists()
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)
        log.info('{} locks to unlock'.format(len(unlock_proofs)), contract=pex(self.address))

        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

            merkleproof_encoded = ''.join(merkle_proof)

            self.proxy.withdraw(
                locked_encoded,
                merkleproof_encoded,
                secret,
            )
            self.tester_chain.mine(number_of_blocks=1)

            lock = messages.Lock.from_bytes(locked_encoded)
            log.info(
                'withdraw called',
                contract=pex(self.address),
                lock=lock,
                secret=encode_hex(secret),
            )

    def settle(self):
        self._check_exists()
        self.proxy.settle()
        self.tester_chain.mine(number_of_blocks=1)

    def all_events_filter(self):
        topics = None
        filter_ = FilterTesterMock(
            self.tester_chain,
            self.address,
            topics,
            next(FILTER_ID_GENERATOR)
        )
        self.tester_chain.head_state.log_listeners.append(filter_.event)
        return filter_
