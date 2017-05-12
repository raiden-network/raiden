# -*- coding: utf-8 -*-
import gevent
from gevent.lock import Semaphore
from time import time as now
import rlp
from ethereum import slogging
from ethereum import _solidity
from ethereum.exceptions import InvalidTransaction
from ethereum.transactions import Transaction
from ethereum.utils import encode_hex, normalize_address
from pyethapp.jsonrpc import (
    address_encoder,
    address_decoder,
    data_decoder,
    data_encoder,
    default_gasprice,
)
from pyethapp.rpc_client import topic_encoder, JSONRPCClient
import requests

from raiden import messages
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
    GAS_LIMIT,
    GAS_PRICE,
)
from raiden.utils import (
    get_contract_path,
    isaddress,
    pex,
    privatekey_to_address,
)
from raiden.blockchain.abi import (
    TOKENADDED_EVENTID,
    CHANNEL_MANAGER_ABI,
    CHANNELNEW_EVENTID,
    ENDPOINT_REGISTRY_ABI,
    HUMAN_TOKEN_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)

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


class JSONRPCPollTimeoutException(Exception):
    # FIXME import this from pyethapp.rpc_client once it is implemented
    pass


def check_transaction_threw(client, transaction_hash):
    """Check if the transaction threw or if it executed properly"""
    encoded_transaction = data_encoder(transaction_hash.decode('hex'))
    transaction = client.call('eth_getTransactionByHash', encoded_transaction)
    receipt = client.call('eth_getTransactionReceipt', encoded_transaction)
    return int(transaction['gas'], 0) == int(receipt['gasUsed'], 0)


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
        assert hasattr(client, 'privkey') and client.privkey
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
        'fromBlock': from_block if from_block is not None else 'latest',
        'toBlock': to_block if to_block is not None else 'latest',
        'address': address_encoder(normalize_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    return jsonrpc_client.call('eth_newFilter', json_data)


def decode_topic(topic):
    return int(topic[2:], 16)


def estimate_and_transact(classobject, callobj, *args):
    """Estimate gas using eth_estimateGas. Multiply by 2 to make sure sufficient gas is provided
    Limit maximum gas to GAS_LIMIT to avoid exceeding blockgas limit
    """
    estimated_gas = callobj.estimate_gas(
        *args,
        startgas=classobject.startgas,
        gasprice=classobject.gasprice
    )
    estimated_gas = min(estimated_gas * 2, GAS_LIMIT)
    transaction_hash = callobj.transact(
        *args,
        startgas=estimated_gas,
        gasprice=classobject.gasprice
    )
    return transaction_hash


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes,unused-argument

    def __init__(
            self,
            privatekey_bin,
            registry_address,
            host,
            port,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
            **kwargs):

        self.address_token = dict()
        self.address_discovery = dict()
        self.address_manager = dict()
        self.address_contract = dict()
        self.address_registry = dict()
        self.token_manager = dict()

        # if this object becomes a problem for testing consider using one of
        # the mock blockchains
        jsonrpc_client = JSONRPCClient(
            privkey=privatekey_bin,
            host=host,
            port=port,
            print_communication=kwargs.get('print_communication', False),
        )
        patch_send_transaction(jsonrpc_client)
        patch_send_message(jsonrpc_client)

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)
        self.poll_timeout = poll_timeout
        self.default_registry = self.registry(registry_address)

    def set_verbosity(self, level):
        if level:
            self.client.print_communication = True

    def block_number(self):
        return self.client.blocknumber()

    def next_block(self):
        target_block_number = self.block_number() + 1
        current_block = target_block_number

        while not current_block >= target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address):
        """ Return a proxy to interact with a token. """
        if token_address not in self.address_token:
            self.address_token[token_address] = Token(
                self.client,
                token_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_token[token_address]

    def discovery(self, discovery_address):
        """ Return a proxy to interact with the discovery. """
        if discovery_address not in self.address_discovery:
            self.address_discovery[discovery_address] = Discovery(
                self.client,
                discovery_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_discovery[discovery_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_contract:
            channel = NettingChannel(
                self.client,
                netting_channel_address,
                poll_timeout=self.poll_timeout,
            )
            self.address_contract[netting_channel_address] = channel

        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_manager:
            manager = ChannelManager(
                self.client,
                manager_address,
                poll_timeout=self.poll_timeout,
            )

            token_address = manager.token_address()

            self.token_manager[token_address] = manager
            self.address_manager[manager_address] = manager

        return self.address_manager[manager_address]

    def manager_by_token(self, token_address):
        """ Find the channel manager for `token_address` and return a proxy to
        interact with it.
        """
        if token_address not in self.token_manager:
            token = self.token(token_address)  # check that the token exists
            manager_address = self.default_registry.manager_address_by_token(token.address)
            manager = ChannelManager(
                self.client,
                address_decoder(manager_address),
                poll_timeout=self.poll_timeout,
            )

            self.token_manager[token_address] = manager
            self.address_manager[manager_address] = manager

        return self.token_manager[token_address]

    def registry(self, registry_address):
        if registry_address not in self.address_registry:
            self.address_registry[registry_address] = Registry(
                self.client,
                registry_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        self.client.call('eth_uninstallFilter', filter_id_raw)

    def deploy_contract(self, contract_name, contract_file, constructor_parameters=None):
        contract_path = get_contract_path(contract_file)
        contracts = _solidity.compile_file(contract_path, libraries=dict())

        log.info(
            'Deploying "%s" contract',
            contract_file,
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

    def deploy_and_register_token(self, contract_name, contract_file, constructor_parameters=None):
        assert self.default_registry

        token_address = self.deploy_contract(
            contract_name,
            contract_file,
            constructor_parameters,
        )
        self.default_registry.add_token(token_address)  # pylint: disable=no-member

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

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
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

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(discovery_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Discovery address {} does not contain code'.format(
                address_encoder(discovery_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            ENDPOINT_REGISTRY_ABI,
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

        transaction_hash = self.proxy.registerEndpoint.transact(endpoint)

        try:
            self.client.poll(
                transaction_hash.decode('hex'),
                timeout=self.poll_timeout,
            )
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = node_address_bin.encode('hex')
        endpoint = self.proxy.findEndpointByAddress.call(node_address_hex)

        if endpoint is '':
            raise KeyError('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint.call(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')


class Token(object):
    def __init__(
            self,
            jsonrpc_client,
            token_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(token_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Token address {} does not contain code'.format(
                address_encoder(token_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            HUMAN_TOKEN_ABI,
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

        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

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

        try:
            self.client.poll(transaction_hash.decode('hex'))
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

        # TODO: check Transfer event


class Registry(object):
    def __init__(self, jsonrpc_client, registry_address, startgas=GAS_LIMIT,
                 gasprice=GAS_PRICE, poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(registry_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Registry address {} does not contain code'.format(
                address_encoder(registry_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            REGISTRY_ABI,
            address_encoder(registry_address),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def manager_address_by_token(self, token_address):
        """ Return the channel manager address for the given token. """
        return self.proxy.channelManagerByToken.call(token_address)

    def add_token(self, token_address):
        transaction_hash = estimate_and_transact(
            self,
            self.proxy.addToken,
            token_address,
        )

        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

        channel_manager_address_encoded = self.proxy.channelManagerByToken.call(
            token_address,
            startgas=self.startgas,
        )

        if not channel_manager_address_encoded:
            log.error('add_token failed', token_address=pex(token_address))
            raise RuntimeError('add_token failed')

        channel_manager_address_bin = address_decoder(channel_manager_address_encoded)

        log.info(
            'add_token called',
            token_address=pex(token_address),
            registry_address=pex(self.address),
            channel_manager_address=pex(channel_manager_address_bin),
        )

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
        topics = [TOKENADDED_EVENTID]

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


class ChannelManager(object):
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(manager_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Channel manager address {} does not contain code'.format(
                address_encoder(manager_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CHANNEL_MANAGER_ABI,
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

        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

        # TODO: raise if the transaction failed because there is an existing
        # channel in place

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

    def channelnew_filter(self, from_block=None, to_block=None):  # pylint: disable=unused-argument
        """ Install a new filter for ChannelNew events.

        Return:
            Filter: The filter instance.
        """
        # participant_address_hex = address_encoder(privatekey_to_address(self.client.privkey))
        # topics = [
        #     CHANNELNEW_EVENTID, [node_address_hex, None], [None, node_address_hex],
        # ]
        topics = [CHANNELNEW_EVENTID]

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
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(channel_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Netting channel address {} does not contain code'.format(
                address_encoder(channel_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            NETTING_CHANNEL_ABI,
            address_encoder(channel_address),
        )

        self.address = channel_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

        # check we are a participant of the given channel
        self.node_address = privatekey_to_address(self.client.privkey)
        self.detail(self.node_address)

    def token_address(self):
        return address_decoder(self.proxy.tokenAddress.call())

    def detail(self, our_address):
        data = self.proxy.addressAndBalance.call(startgas=self.startgas)
        settle_timeout = self.proxy.settleTimeout.call(startgas=self.startgas)

        if data == '':
            raise RuntimeError('addressAndBalance call failed.')

        if settle_timeout == '':
            raise RuntimeError('settleTimeout call failed.')

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
        settle_timeout = self.proxy.settleTimeout.call()
        return settle_timeout

    def isopen(self):
        if self.proxy.closed.call() != 0:
            return False

        return self.proxy.opened.call() != 0

    def deposit(self, our_address, amount):  # pylint: disable=unused-argument
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        token = Token(
            self.client,
            self.token_address(),
            poll_timeout=self.poll_timeout,
        )
        current_balance = token.balance_of(self.node_address)

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.deposit,
            amount,
        )

        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

        log.info('deposit called', contract=pex(self.address), amount=amount)

    def opened(self):
        return self.proxy.opened.call()

    def closed(self):
        return self.proxy.closed.call()

    def closing_address(self):
        return address_decoder(self.proxy.closingAddress())

    def settled(self):
        return self.proxy.settled.call()

    def close(self, our_address, their_transfer):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""

        if their_transfer:
            their_encoded = their_transfer.encode()
        else:
            their_encoded = ''

        transaction_hash = estimate_and_transact(
            self,
            self.proxy.close,
            their_encoded,
        )
        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e
        log.info(
            'close called',
            contract=pex(self.address),
            their_transfer=their_transfer,
        )

    def update_transfer(self, our_address, their_transfer):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        if their_transfer is not None:
            their_transfer_encoded = their_transfer.encode()

            transaction_hash = estimate_and_transact(
                self,
                self.proxy.updateTransfer,
                their_transfer_encoded,
            )

            try:
                self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
            except JSONRPCPollTimeoutException as e:
                raise e
            except InvalidTransaction as e:
                raise e

            log.info(
                'update_transfer called',
                contract=pex(self.address),
                their_transfer=their_transfer,
            )
            # TODO: check if the ChannelSecretRevealed event was emitted and if
            # it wasn't raise an error

    def withdraw(self, our_address, unlock_proofs):
        """`our_address` is an argument used only in mock_client.py but is also
        kept here to maintain a consistent interface"""
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)
        log.info(
            '%s locks to unlock',
            len(unlock_proofs),
            contract=pex(self.address),
        )

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

            try:
                self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
            except JSONRPCPollTimeoutException as e:
                raise e
            except InvalidTransaction as e:
                raise e

            # TODO: check if the ChannelSecretRevealed event was emitted and if
            # it wasn't raise an error

            # if log.getEffectiveLevel() >= logging.INFO:  # only decode the lock if need to
            lock = messages.Lock.from_bytes(locked_encoded)
            log.info(
                'unlock called',
                contract=pex(self.address),
                lock=lock,
                secret=encode_hex(secret),
            )

    def settle(self):
        transaction_hash = estimate_and_transact(
            self,
            self.proxy.settle,
        )

        try:
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        except JSONRPCPollTimeoutException as e:
            raise e
        except InvalidTransaction as e:
            raise e

        # TODO: check if the ChannelSettled event was emitted and if it wasn't raise an error
        log.info('settle called', contract=pex(self.address))

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
