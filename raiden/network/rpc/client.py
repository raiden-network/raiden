# -*- coding: utf-8 -*-
import os
import logging
from time import time as now

import rlp
import gevent
from gevent.lock import Semaphore
from ethereum import slogging
from ethereum import _solidity
from ethereum.transactions import Transaction
from ethereum.utils import encode_hex, normalize_address
from pyethapp.jsonrpc import (
    address_encoder,
    address_decoder,
    data_decoder,
    data_encoder,
    quantity_decoder,
    default_gasprice,
)
from pyethapp.rpc_client import topic_encoder, block_tag_encoder
import requests

from raiden import messages
from raiden.exceptions import (
    AddressWithoutCode,
    DuplicatedChannelError,
    NoTokenManager,
    TransactionThrew,
    UnknownAddress,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
    DISCOVERY_REGISTRATION_GAS,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
    GAS_LIMIT,
    GAS_PRICE,
)
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
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
from raiden.exceptions import SamePeerAddress

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
solidity = _solidity.get_solidity()  # pylint: disable=invalid-name

# Coding standard for this module:
#
# - Be sure to reflect changes to this module in the test
#   implementations. [tests/utils/*_client.py]
# - Expose a synchronous interface by default
#   - poll for the transaction hash
#   - check if the proper events were emited
#   - use `call` and `transact` to interact with pyethapp.rpc_client proxies
# - Check errors:
#   - `call` returns the empty string if the target smart contract does not
#   exist or the call throws, handle it accordingly (there is no way to
#   distinguish a function that returns the empty string from the error)
#   - the smart contract executed with a `transact` may fail with a throw, this
#   will spend all gas (there is no way to distinguish a transaction that used
#   exactly all the available gas). Note: There is a new opcode in draft that
#   wont use all gas https://github.com/ethereum/EIPs/pull/206


def check_transaction_threw(client, transaction_hash):
    """Check if the transaction threw or if it executed properly"""
    encoded_transaction = data_encoder(transaction_hash.decode('hex'))
    debug = client.call('debug_traceTransaction', encoded_transaction)

    # struct_logs will be empty if it's a call to a contract that previously
    # self destructed:
    # https://github.com/ethereum/go-ethereum/issues/2542
    struct_logs = debug['structLogs']
    if not struct_logs or struct_logs[-1]['op'] not in ('RETURN', 'STOP'):
        return debug


def check_address_has_code(client, address):
    result = client.call(
        'eth_getCode',
        address_encoder(address),
        'latest',
    )

    if result == '0x':
        raise AddressWithoutCode('Address {} does not contain code'.format(
            address_encoder(address),
        ))


def patch_send_transaction(client, nonce_offset=0):
    """Check if the remote supports pyethapp's extended jsonrpc spec for local tx signing.
    If not, replace the `send_transaction` method with a more generic one.
    """
    patch_necessary = False

    try:
        client.call('eth_nonce', encode_hex(client.sender), 'pending')
    except:
        patch_necessary = True
        client.last_nonce_update = 0
        client.current_nonce = None
        client.nonce_lock = Semaphore()

    def send_transaction(sender, to, value=0, data='', startgas=GAS_LIMIT,
                         gasprice=GAS_PRICE, nonce=None):
        """Custom implementation for `pyethapp.rpc_client.JSONRPCClient.send_transaction`.
        This is necessary to support other remotes that don't support pyethapp's extended specs.
        @see https://github.com/ethereum/pyethapp/blob/develop/pyethapp/rpc_client.py#L359
        """
        def get_nonce():
            """Eventually syncing nonce counter.
            This will keep a local nonce counter that is only syncing against
            the remote every `UPDATE_INTERVAL`.

            If the remote counter is lower than the current local counter,
            it will wait for the remote to catch up.
            """
            with client.nonce_lock:
                UPDATE_INTERVAL = 5.
                query_time = now()
                needs_update = abs(query_time - client.last_nonce_update) > UPDATE_INTERVAL
                not_initialized = client.current_nonce is None
                if needs_update or not_initialized:
                    nonce = _query_nonce()
                    # we may have hammered the server and not all tx are
                    # registered as `pending` yet
                    while nonce < client.current_nonce:
                        log.debug(
                            "nonce on server too low; retrying",
                            server=nonce,
                            local=client.current_nonce
                        )
                        nonce = _query_nonce()
                        query_time = now()
                    client.current_nonce = nonce
                    client.last_nonce_update = query_time
                else:
                    client.current_nonce += 1
                return client.current_nonce

        def _query_nonce():
            pending_transactions_hex = client.call(
                'eth_getTransactionCount',
                address_encoder(sender),
                'pending',
            )
            pending_transactions = int(pending_transactions_hex, 16)
            nonce = pending_transactions + nonce_offset
            return nonce

        nonce = get_nonce()

        tx = Transaction(nonce, gasprice, startgas, to, value, data)
        tx.sign(client.privkey)

        result = client.call(
            'eth_sendRawTransaction',
            data_encoder(rlp.encode(tx)),
        )
        return result[2 if result.startswith('0x') else 0:]

    if patch_necessary:
        client.send_transaction = send_transaction


def patch_send_message(client, pool_maxsize=50):
    """Monkey patch fix for issue #253. This makes the underlying `tinyrpc`
    transport class use a `requests.session` instead of regenerating sessions
    for each request.

    See also: https://github.com/mbr/tinyrpc/pull/31 for a proposed upstream
    fix.

    Args:
        client (pyethapp.rpc_client.JSONRPCClient): the instance to patch
        pool_maxsize: the maximum poolsize to be used by the `requests.Session()`
    """
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_maxsize=pool_maxsize)
    session.mount(client.transport.endpoint, adapter)

    def send_message(message, expect_reply=True):
        if not isinstance(message, str):
            raise TypeError('str expected')

        r = session.post(
            client.transport.endpoint,
            data=message,
            **client.transport.request_kwargs
        )

        if expect_reply:
            return r.content

    client.transport.send_message = send_message


def new_filter(jsonrpc_client, contract_address, topics, from_block=None, to_block=None):
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    if isinstance(from_block, int):
        from_block = hex(from_block)

    if isinstance(to_block, int):
        to_block = hex(to_block)

    json_data = {
        'fromBlock': from_block or hex(0),
        'toBlock': to_block or 'latest',
        'address': address_encoder(normalize_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    return jsonrpc_client.call('eth_newFilter', json_data)


def get_filter_events(jsonrpc_client, contract_address, topics, from_block=None, to_block=None):
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    if isinstance(from_block, int):
        from_block = hex(from_block)

    if isinstance(to_block, int):
        to_block = hex(to_block)

    json_data = {
        'fromBlock': from_block or hex(0),
        'toBlock': to_block or 'latest',
        'address': address_encoder(normalize_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    filter_changes = jsonrpc_client.call('eth_getLogs', json_data)

    # geth could return None
    if filter_changes is None:
        return []

    result = []
    for log_event in filter_changes:
        address = address_decoder(log_event['address'])
        data = data_decoder(log_event['data'])
        topics = [
            decode_topic(topic)
            for topic in log_event['topics']
        ]
        block_number = log_event.get('blockNumber')
        if not block_number:
            block_number = 0
        else:
            block_number = int(block_number, 0)

        result.append({
            'topics': topics,
            'data': data,
            'address': address,
            'block_number': block_number,
        })

    return result


def decode_topic(topic):
    return int(topic[2:], 16)


def estimate_and_transact(classobject, callobj, *args):
    """Estimate gas using eth_estimateGas. Multiply by 2 to make sure sufficient gas is provided
    Limit maximum gas to GAS_LIMIT to avoid exceeding blockgas limit
    """
    # XXX: From Byzantium and on estimate gas is not giving an accurate estimation
    #      and as such we not longer utilize its result but use the GAS_LIMIT in
    #      all transactions. With the revert() call not consumin all given gas that
    #      is not that bad
    #
    # estimated_gas = callobj.estimate_gas(
    #     *args,
    #     startgas=classobject.startgas,
    #     gasprice=classobject.gasprice
    # )
    estimated_gas = GAS_LIMIT
    transaction_hash = callobj.transact(
        *args,
        startgas=estimated_gas,
        gasprice=classobject.gasprice
    )
    return transaction_hash


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes

    def __init__(self, privatekey_bin, jsonrpc_client, poll_timeout=DEFAULT_POLL_TIMEOUT):
        self.address_to_token = dict()
        self.address_to_discovery = dict()
        self.address_to_nettingchannel = dict()
        self.address_to_registry = dict()

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)
        self.poll_timeout = poll_timeout

    def block_number(self):
        return self.client.blocknumber()

    def is_synced(self):
        result = self.client.call('eth_syncing')

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = quantity_decoder(result['highestBlock'])

        if highest_block - current_block > 2:
            return False

        return True

    def estimate_blocktime(self, oldest=256):
        """Calculate a blocktime estimate based on some past blocks.
        Args:
            oldest (int): delta in block numbers to go back.
        Return:
            average block time (int) in seconds
        """
        last_block_number = self.block_number()
        # around genesis block there is nothing to estimate
        if last_block_number < 1:
            return 15
        # if there are less than `oldest` blocks available, start at block 1
        if last_block_number < oldest:
            interval = (last_block_number - 1) or 1
        else:
            interval = last_block_number - oldest
        assert interval > 0
        last_timestamp = int(self.get_block_header(last_block_number)['timestamp'], 16)
        first_timestamp = int(self.get_block_header(last_block_number - interval)['timestamp'], 16)
        delta = last_timestamp - first_timestamp
        return float(delta) / interval

    def get_block_header(self, block_number):
        block_number = block_tag_encoder(block_number)
        return self.client.call('eth_getBlockByNumber', block_number, False)

    def next_block(self):
        target_block_number = self.block_number() + 1
        current_block = target_block_number

        while not current_block >= target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address):
        """ Return a proxy to interact with a token. """
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        if token_address not in self.address_to_token:
            self.address_to_token[token_address] = Token(
                self.client,
                token_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_to_token[token_address]

    def discovery(self, discovery_address):
        """ Return a proxy to interact with the discovery. """
        if not isaddress(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        if discovery_address not in self.address_to_discovery:
            self.address_to_discovery[discovery_address] = Discovery(
                self.client,
                discovery_address,
                poll_timeout=self.poll_timeout
            )

        return self.address_to_discovery[discovery_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if not isaddress(netting_channel_address):
            raise ValueError('netting_channel_address must be a valid address')

        if netting_channel_address not in self.address_to_nettingchannel:
            channel = NettingChannel(
                self.client,
                netting_channel_address,
                poll_timeout=self.poll_timeout,
            )
            self.address_to_nettingchannel[netting_channel_address] = channel

        return self.address_to_nettingchannel[netting_channel_address]

    def registry(self, registry_address):
        if not isaddress(registry_address):
            raise ValueError('registry_address must be a valid address')

        if registry_address not in self.address_to_registry:
            self.address_to_registry[registry_address] = Registry(
                self.client,
                registry_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_to_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        self.client.call('eth_uninstallFilter', filter_id_raw)

    def deploy_contract(self, contract_name, contract_path, constructor_parameters=None):
        contracts = _solidity.compile_file(contract_path, libraries=dict())

        log.info(
            'Deploying "%s" contract',
            os.path.basename(contract_path),
        )

        proxy = self.client.deploy_solidity_contract(
            self.node_address,
            contract_name,
            contracts,
            dict(),
            constructor_parameters,
            contract_path=contract_path,
            gasprice=default_gasprice,
            timeout=self.poll_timeout,
        )
        return proxy.address

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
        registry.add_token(token_address)  # pylint: disable=no-member

        return token_address


class Filter(object):
    def __init__(self, jsonrpc_client, filter_id_raw):
        self.filter_id_raw = filter_id_raw
        self.client = jsonrpc_client

    def _query_filter(self, function):
        filter_changes = self.client.call(function, self.filter_id_raw)

        # geth could return None
        if filter_changes is None:
            return []

        result = list()
        for log_event in filter_changes:
            address = address_decoder(log_event['address'])
            data = data_decoder(log_event['data'])
            topics = [
                decode_topic(topic)
                for topic in log_event['topics']
            ]
            block_number = log_event.get('blockNumber')
            if not block_number:
                block_number = 0
            else:
                block_number = int(block_number, 0)

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
                'block_number': block_number,
            })

        return result

    def changes(self):
        return self._query_filter('eth_getFilterChanges')

    def getall(self):
        return self._query_filter('eth_getFilterLogs')

    def uninstall(self):
        self.client.call(
            'eth_uninstallFilter',
            self.filter_id_raw,
        )


class Discovery(object):
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        if not isaddress(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(discovery_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Discovery address {} does not contain code'.format(
                address_encoder(discovery_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CONTRACT_MANAGER.get_abi(CONTRACT_ENDPOINT_REGISTRY),
            address_encoder(discovery_address),
        )

        self.address = discovery_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.sender:
            raise ValueError("node_address doesnt match this node's address")

        transaction_hash = self.proxy.registerEndpoint.transact(
            endpoint,
            gasprice=self.gasprice,
            startgas=DISCOVERY_REGISTRATION_GAS
        )

        self.client.poll(
            transaction_hash.decode('hex'),
            timeout=self.poll_timeout,
        )

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Register Endpoint', receipt_or_none)

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = node_address_bin.encode('hex')
        endpoint = self.proxy.findEndpointByAddress.call(node_address_hex)

        if endpoint == '':
            raise UnknownAddress('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint.call(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')

    def version(self):
        return self.proxy.contract_version.call()


class Token(object):
    def __init__(
            self,
            jsonrpc_client,
            token_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(token_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Token address {} does not contain code'.format(
                address_encoder(token_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN),
            address_encoder(token_address),
        )

        self.address = token_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def approve(self, contract_address, allowance):
        """ Aprove `contract_address` to transfer up to `deposit` amount of token. """
        # TODO: check that `contract_address` is a netting channel and that
        # `self.address` is one of the participants (maybe add this logic into
        # `NettingChannel` and keep this straight forward)

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.approve,
            contract_address,
            allowance,
        )

        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Approve', receipt_or_none)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.balanceOf.call(address)

    def transfer(self, to_address, amount):
        transaction_hash = estimate_and_transact(
            self,
            self.proxy.transfer,  # pylint: disable=no-member
            to_address,
            amount,
        )

        self.client.poll(transaction_hash.decode('hex'))
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Transfer', receipt_or_none)

        # TODO: check Transfer event


class Registry(object):
    def __init__(
            self,
            jsonrpc_client,
            registry_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(registry_address):
            raise ValueError('registry_address must be a valid address')

        check_address_has_code(jsonrpc_client, registry_address)

        proxy = jsonrpc_client.new_abi_contract(
            CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY),
            address_encoder(registry_address),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

        self.address_to_channelmanager = dict()
        self.token_to_channelmanager = dict()

    def manager_address_by_token(self, token_address):
        """ Return the channel manager address for the given token or None if
        there is no correspoding address.
        """
        address = self.proxy.channelManagerByToken.call(
            token_address,
            startgas=self.startgas,
        )

        if address == '':
            check_address_has_code(self.client, self.address)
            return None

        return address_decoder(address)

    def add_token(self, token_address):
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.addToken,
            token_address,
        )

        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
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
            for address in self.proxy.tokenAddresses.call(startgas=self.startgas)
        ]

    def manager_addresses(self):
        return [
            address_decoder(address)
            for address in self.proxy.channelManagerAddresses.call(startgas=self.startgas)
        ]

    def tokenadded_filter(self, from_block=None, to_block=None):
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_TOKEN_ADDED)]

        registry_address_bin = self.proxy.address
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
                poll_timeout=self.poll_timeout,
            )

            token_address = manager.token_address()

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.address_to_channelmanager[manager_address]

    def manager_by_token(self, token_address):
        """ Find the channel manager for `token_address` and return a proxy to
        interact with it.

        If the token is not already registered it raises `JSONRPCClientReplyError`,
        since we try to instantiate a Channel manager with an empty address.
        """
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        if token_address not in self.token_to_channelmanager:
            check_address_has_code(self.client, token_address)  # check that the token exists
            manager_address = self.manager_address_by_token(token_address)

            if manager_address is None:
                raise NoTokenManager(
                    'Manager for token 0x{} does not exist'.format(token_address.encode('hex'))
                )

            manager = ChannelManager(
                self.client,
                manager_address,
                poll_timeout=self.poll_timeout,
            )

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.token_to_channelmanager[token_address]


class ChannelManager(object):
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(manager_address):
            raise ValueError('manager_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(manager_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Channel manager address {} does not contain code'.format(
                address_encoder(manager_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
            address_encoder(manager_address),
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def token_address(self):
        """ Return the token of this manager. """
        return address_decoder(self.proxy.tokenAddress.call())

    def new_netting_channel(self, peer1, peer2, settle_timeout):
        if not isaddress(peer1):
            raise ValueError('The peer1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        if peer1 == peer2:
            raise SamePeerAddress('Peer1 and peer2 must not be equal')

        if privatekey_to_address(self.client.privkey) == peer1:
            other = peer2
        else:
            other = peer1

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.newChannel,
            other,
            settle_timeout,
        )

        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        netting_channel_results_encoded = self.proxy.getChannelWith.call(
            other,
            startgas=self.startgas,
        )

        # address is at index 0
        netting_channel_address_encoded = netting_channel_results_encoded

        if not netting_channel_address_encoded:
            log.error('netting_channel_address failed', peer1=pex(peer1), peer2=pex(peer2))
            raise RuntimeError('netting_channel_address failed')

        netting_channel_address_bin = address_decoder(netting_channel_address_encoded)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'new_netting_channel called',
                peer1=pex(peer1),
                peer2=pex(peer2),
                netting_channel=pex(netting_channel_address_bin),
            )

        return netting_channel_address_bin

    def channels_addresses(self):
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.getChannelsParticipants.call(startgas=self.startgas)

        channel_flat = [
            address_decoder(channel)
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
            address_decoder(address)
            for address in address_list
        ]

    def channelnew_filter(self, from_block=None, to_block=None):
        """ Install a new filter for ChannelNew events.

        Return:
            Filter: The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]

        channel_manager_address_bin = self.proxy.address
        filter_id_raw = new_filter(
            self.client,
            channel_manager_address_bin,
            topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )


class NettingChannel(object):
    def __init__(
            self,
            jsonrpc_client,
            channel_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        self.address = channel_address
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.proxy = jsonrpc_client.new_abi_contract(
            CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL),
            address_encoder(channel_address),
        )

        # check we are a participant of the given channel
        self.detail()
        self._check_exists()

    def _check_exists(self):
        result = self.client.call(
            'eth_getCode',
            address_encoder(self.address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Netting channel address {} does not contain code'.format(
                address_encoder(self.address),
            ))

    def token_address(self):
        """ Returns the type of token that can be transferred by the channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        address = self.proxy.tokenAddress.call()

        if address == '':
            self._check_exists()
            raise RuntimeError('token address returned empty')

        return address_decoder(address)

    def detail(self):
        """ Returns a dictionary with the details of the netting channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        our_address = privatekey_to_address(self.client.privkey)

        data = self.proxy.addressAndBalance.call(startgas=self.startgas)

        if data == '':
            self._check_exists()
            raise RuntimeError('address and balance returned empty')

        settle_timeout = self.settle_timeout()

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

    def settle_timeout(self):
        """ Returns the netting channel settle_timeout.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        settle_timeout = self.proxy.settleTimeout.call()

        if settle_timeout == '':
            self._check_exists()
            raise RuntimeError('settle_timeout returned empty')

        return settle_timeout

    def opened(self):
        """ Returns the block in which the channel was created.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        opened = self.proxy.opened.call()

        if opened == '':
            self._check_exists()
            raise RuntimeError('opened returned empty')

        return opened

    def closed(self):
        """ Returns the block in which the channel was closed or 0.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closed = self.proxy.closed.call()

        if closed == '':
            self._check_exists()
            raise RuntimeError('closed returned empty')

        return closed

    def closing_address(self):
        """ Returns the address of the closer, if the channel is closed, None
        otherwise.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closer = self.proxy.closingAddress()

        if closer:
            return address_decoder(closer)

        return None

    def can_transfer(self):
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply in having a balance for off-chain
        transfers.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closed = self.closed()

        if closed != 0:
            return False

        return self.detail()['our_balance'] > 0

    def deposit(self, amount):
        """ Deposit amount token in the channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
            RuntimeError: If the netting channel token address is empty.
        """
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        token_address = self.token_address()

        token = Token(
            self.client,
            token_address,
            poll_timeout=self.poll_timeout,
        )
        current_balance = token.balance_of(self.node_address)

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        if log.isEnabledFor(logging.INFO):
            log.info('deposit called', contract=pex(self.address), amount=amount)

        transaction_hash = estimate_and_transact(self, self.proxy.deposit, amount)

        self.client.poll(
            transaction_hash.decode('hex'),
            timeout=self.poll_timeout,
        )

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical('deposit failed', contract=pex(self.address))
            self._check_exists()
            raise TransactionThrew('Deposit', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info('deposit sucessfull', contract=pex(self.address), amount=amount)

    def close(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        """ Close the channel using the provided balance proof.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        if log.isEnabledFor(logging.INFO):
            log.info(
                'close called',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.close,
            nonce,
            transferred_amount,
            locksroot,
            extra_hash,
            signature,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical(
                'close failed',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )
            self._check_exists()
            raise TransactionThrew('Close', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'close sucessfull',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

    def update_transfer(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        if signature:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'updateTransfer called',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )

            transaction_hash = estimate_and_transact(
                self,
                self.proxy.updateTransfer,
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature,
            )

            self.client.poll(
                transaction_hash.decode('hex'),
                timeout=self.poll_timeout,
            )

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'updateTransfer failed',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )
                self._check_exists()
                raise TransactionThrew('Update Transfer', receipt_or_none)

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'updateTransfer sucessfull',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )

    def withdraw(self, unlock_proofs):
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)

        if log.isEnabledFor(logging.INFO):
            log.info('withdraw called', contract=pex(self.address))

        failed = False
        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

            merkleproof_encoded = ''.join(merkle_proof)

            transaction_hash = estimate_and_transact(
                self,
                self.proxy.withdraw,
                locked_encoded,
                merkleproof_encoded,
                secret,
            )

            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            lock = messages.Lock.from_bytes(locked_encoded)
            if receipt_or_none:
                lock = messages.Lock.from_bytes(locked_encoded)
                log.critical(
                    'withdraw failed',
                    contract=pex(self.address),
                    lock=lock,
                )
                self._check_exists()
                failed = True

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'withdraw sucessfull',
                    contract=pex(self.address),
                    lock=lock,
                )

        if failed:
            raise TransactionThrew('Withdraw', receipt_or_none)

    def settle(self):
        if log.isEnabledFor(logging.INFO):
            log.info('settle called')

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.settle,
        )

        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.info('settle failed', contract=pex(self.address))
            self._check_exists()
            raise TransactionThrew('Settle', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info('settle sucessfull', contract=pex(self.address))

    def events_filter(self, topics, from_block=None, to_block=None):
        """ Install a new filter for an array of topics emitted by the netting contract.
        Args:
            topics (list): A list of event ids to filter for. Can also be None,
                           in which case all events are queried.

        Return:
            Filter: The filter instance.
        """
        netting_channel_address_bin = self.proxy.address
        filter_id_raw = new_filter(
            self.client,
            netting_channel_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )

    def all_events_filter(self, from_block=None, to_block=None):
        """ Install a new filter for all the events emitted by the current netting channel contract

        Return:
            Filter: The filter instance.
        """
        return self.events_filter(None, from_block, to_block)
