# -*- coding: utf-8 -*-
import os
import warnings
from time import time as now
from binascii import hexlify, unhexlify
from typing import Optional, List, Dict, Union

import rlp
import gevent
import cachetools
from gevent.lock import Semaphore
from ethereum import slogging
from ethereum.tools import _solidity
from ethereum.abi import ContractTranslator
from ethereum.transactions import Transaction
from ethereum.tools._solidity import (
    solidity_unresolved_symbols,
    solidity_library_symbol,
    solidity_resolve_symbols
)
from tinyrpc.protocols.jsonrpc import (
    JSONRPCErrorResponse,
    JSONRPCProtocol,
    JSONRPCSuccessResponse,
)
from tinyrpc.transports.http import HttpPostClientTransport
from tinyrpc.exc import InvalidReplyError
import requests

from raiden.exceptions import (
    AddressWithoutCode,
    EthNodeCommunicationError,
    RaidenShuttingDown,
)
from raiden.network.protocol import timeout_two_stage
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.settings import GAS_PRICE, GAS_LIMIT, RPC_CACHE_TTL
from raiden.utils import (
    address_decoder,
    address_encoder,
    block_tag_encoder,
    data_decoder,
    data_encoder,
    privatekey_to_address,
    quantity_decoder,
    quantity_encoder,
    topic_decoder,
    topic_encoder,
)
from raiden.utils.typing import address

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
solidity = _solidity.get_solidity()  # pylint: disable=invalid-name


def check_address_has_code(
        client,
        address: address,
        contract_name: str = ''):
    """ Checks that the given address contains code. """
    result = client.eth_getCode(address, 'latest')

    if len(result) == 0:
        raise AddressWithoutCode('{}Address {} does not contain code'.format(
            '[{}]: '.format(contract_name) if contract_name else '',
            address_encoder(address),
        ))


def deploy_dependencies_symbols(all_contract):
    dependencies = {}

    symbols_to_contract = dict()
    for contract_name in all_contract:
        symbol = solidity_library_symbol(contract_name)

        if symbol in symbols_to_contract:
            raise ValueError('Conflicting library names.')

        symbols_to_contract[symbol] = contract_name

    for contract_name, contract in all_contract.items():
        unresolved_symbols = solidity_unresolved_symbols(contract['bin_hex'])
        dependencies[contract_name] = [
            symbols_to_contract[unresolved]
            for unresolved in unresolved_symbols
        ]

    return dependencies


def dependencies_order_of_build(target_contract, dependencies_map):
    """ Return an ordered list of contracts that is sufficient to sucessfully
    deploy the target contract.

    Note:
        This function assumes that the `dependencies_map` is an acyclic graph.
    """
    if not dependencies_map:
        return [target_contract]

    if target_contract not in dependencies_map:
        raise ValueError('no dependencies defined for {}'.format(target_contract))

    order = [target_contract]
    todo = list(dependencies_map[target_contract])

    while todo:
        target_contract = todo.pop(0)
        target_pos = len(order)

        for dependency in dependencies_map[target_contract]:
            # we need to add the current contract before all its depedencies
            if dependency in order:
                target_pos = order.index(dependency)
            else:
                todo.append(dependency)

        order.insert(target_pos, target_contract)

    order.reverse()
    return order


def format_data_for_call(
        sender: address = b'',
        to: address = b'',
        value: int = 0,
        data: bytes = b'',
        startgas: int = GAS_LIMIT,
        gasprice: int = GAS_PRICE):
    """ Helper to format the transaction data. """

    return {
        'from': address_encoder(sender),
        'to': data_encoder(to),
        'value': quantity_encoder(value),
        'gasPrice': quantity_encoder(gasprice),
        'gas': quantity_encoder(startgas),
        'data': data_encoder(data)
    }


def check_node_connection(func):
    """ A decorator to reconnect if the connection to the node is lost.
    Decorator should only wrap methods of the JSONRPCClient class"""
    def retry_on_disconnect(self, *args, **kwargs):
        for i, timeout in enumerate(timeout_two_stage(10, 3, 10)):

            if self.stop_event and self.stop_event.is_set():
                raise RaidenShuttingDown()

            try:
                result = func(self, *args, **kwargs)
                if i > 0:
                    log.info('Client reconnected')
                return result

            except (requests.exceptions.ConnectionError, InvalidReplyError):
                log.info(
                    'Timeout in eth client connection to {}. Is the client offline? Trying '
                    'again in {}s.'.format(self.transport.endpoint, timeout)
                )
            gevent.sleep(timeout)

    return retry_on_disconnect


class JSONRPCClient:
    """ Ethereum JSON RPC client.

    Args:
        host: Ethereum node host address.
        port: Ethereum node port number.
        privkey: Local user private key, used to sign transactions.
        nonce_update_interval: Update the account nonce every
            `nonce_update_interval` seconds.
        nonce_offset: Network's default base nonce number.
    """

    def __init__(
            self,
            host: str,
            port: int,
            privkey: bytes,
            gasprice: int = None,
            nonce_update_interval: float = 5.0,
            nonce_offset: int = 0):

        endpoint = 'http://{}:{}'.format(host, port)
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=50)
        self.session.mount(endpoint, adapter)

        self.transport = HttpPostClientTransport(
            endpoint,
            post_method=self.session.post,
            headers={'content-type': 'application/json'},
        )

        self.port = port
        self.privkey = privkey
        self.protocol = JSONRPCProtocol()
        self.sender = privatekey_to_address(privkey)
        # Needs to be initialized to None in the beginning since JSONRPCClient
        # gets constructed before the RaidenService Object.
        self.stop_event = None

        self.nonce_last_update = 0
        self.nonce_current_value = None
        self.nonce_lock = Semaphore()
        self.nonce_update_interval = nonce_update_interval
        self.nonce_offset = nonce_offset
        self.given_gas_price = gasprice

        cache = cachetools.TTLCache(
            maxsize=1,
            ttl=RPC_CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.gaslimit = cache_wrapper(self._gaslimit)
        cache = cachetools.TTLCache(
            maxsize=1,
            ttl=RPC_CACHE_TTL,
        )
        cache_wrapper = cachetools.cached(cache=cache)
        self.gasprice = cache_wrapper(self._gasprice)

    def __del__(self):
        self.session.close()

    def __repr__(self):
        return '<JSONRPCClient @%d>' % self.port

    def block_number(self):
        """ Return the most recent block. """
        return quantity_decoder(self.call('eth_blockNumber'))

    def nonce(self, address):
        if len(address) == 40:
            address = unhexlify(address)

        with self.nonce_lock:
            initialized = self.nonce_current_value is not None
            query_time = now()

            if self.nonce_last_update > query_time:
                # Python's 2.7 time is not monotonic and it's affected by clock
                # resets, force an update.
                self.nonce_update_interval = query_time - self.nonce_update_interval
                needs_update = True

            else:
                last_update_interval = query_time - self.nonce_last_update
                needs_update = last_update_interval > self.nonce_update_interval

            if initialized and not needs_update:
                self.nonce_current_value += 1
                return self.nonce_current_value

            pending_transactions_hex = self.call(
                'eth_getTransactionCount',
                address_encoder(address),
                'pending',
            )
            pending_transactions = quantity_decoder(pending_transactions_hex)
            nonce = pending_transactions + self.nonce_offset

            # we may have hammered the server and not all tx are
            # registered as `pending` yet
            if initialized:
                while nonce < self.nonce_current_value:
                    log.debug(
                        'nonce on server too low; retrying',
                        server=nonce,
                        local=self.nonce_current_value,
                    )

                    query_time = now()
                    pending_transactions_hex = self.call(
                        'eth_getTransactionCount',
                        address_encoder(address),
                        'pending',
                    )
                    pending_transactions = quantity_decoder(pending_transactions_hex)
                    nonce = pending_transactions + self.nonce_offset

            self.nonce_current_value = nonce
            self.nonce_last_update = query_time

            return self.nonce_current_value

    def inject_stop_event(self, event):
        self.stop_event = event

    def balance(self, account: address):
        """ Return the balance of the account of given address. """
        res = self.call('eth_getBalance', address_encoder(account), 'pending')
        return quantity_decoder(res)

    def _gaslimit(self, location='pending') -> int:
        last_block = self.call('eth_getBlockByNumber', location, True)
        gas_limit = quantity_decoder(last_block['gasLimit'])
        return gas_limit * 8 // 10

    def _gasprice(self) -> int:
        if self.given_gas_price:
            return self.given_gas_price

        gas_price = self.call('eth_gasPrice')
        return quantity_decoder(gas_price)

    def check_startgas(self, startgas):
        if not startgas:
            return self.gaslimit()
        return startgas

    def new_contract_proxy(self, contract_interface, contract_address: address):
        """ Return a proxy for interacting with a smart contract.

        Args:
            contract_interface: The contract interface as defined by the json.
            address: The contract's address.
        """
        return ContractProxy(
            self.sender,
            contract_interface,
            contract_address,
            self.eth_call,
            self.send_transaction,
            self.eth_estimateGas,
        )

    def deploy_solidity_contract(
            self,  # pylint: disable=too-many-locals
            sender,
            contract_name,
            all_contracts,
            libraries,
            constructor_parameters,
            contract_path=None,
            timeout=None):
        """
        Deploy a solidity contract.
        Args:
            sender (address): the sender address
            contract_name (str): the name of the contract to compile
            all_contracts (dict): the json dictionary containing the result of compiling a file
            libraries (list): A list of libraries to use in deployment
            constructor_parameters (tuple): A tuple of arguments to pass to the constructor
            contract_path (str): If we are dealing with solc >= v0.4.9 then the path
                                 to the contract is a required argument to extract
                                 the contract data from the `all_contracts` dict.
            timeout (int): Amount of time to poll the chain to confirm deployment
        """

        if contract_name in all_contracts:
            contract_key = contract_name

        elif contract_path is not None:
            _, filename = os.path.split(contract_path)
            contract_key = filename + ':' + contract_name

            if contract_key not in all_contracts:
                raise ValueError('Unknown contract {}'.format(contract_name))
        else:
            raise ValueError(
                'Unknown contract {} and no contract_path given'.format(contract_name)
            )

        libraries = dict(libraries)
        contract = all_contracts[contract_key]
        contract_interface = contract['abi']
        symbols = solidity_unresolved_symbols(contract['bin_hex'])

        if symbols:
            available_symbols = list(map(solidity_library_symbol, all_contracts.keys()))

            unknown_symbols = set(symbols) - set(available_symbols)
            if unknown_symbols:
                msg = 'Cannot deploy contract, known symbols {}, unresolved symbols {}.'.format(
                    available_symbols,
                    unknown_symbols,
                )
                raise Exception(msg)

            dependencies = deploy_dependencies_symbols(all_contracts)
            deployment_order = dependencies_order_of_build(contract_key, dependencies)

            deployment_order.pop()  # remove `contract_name` from the list

            log.debug('Deploying dependencies: {}'.format(str(deployment_order)))

            for deploy_contract in deployment_order:
                dependency_contract = all_contracts[deploy_contract]

                hex_bytecode = solidity_resolve_symbols(dependency_contract['bin_hex'], libraries)
                bytecode = unhexlify(hex_bytecode)

                dependency_contract['bin_hex'] = hex_bytecode
                dependency_contract['bin'] = bytecode

                transaction_hash_hex = self.send_transaction(
                    sender,
                    to=b'',
                    data=bytecode,
                )
                transaction_hash = unhexlify(transaction_hash_hex)

                self.poll(transaction_hash, timeout=timeout)
                receipt = self.eth_getTransactionReceipt(transaction_hash)

                contract_address = receipt['contractAddress']
                # remove the hexadecimal prefix 0x from the address
                contract_address = contract_address[2:]

                libraries[deploy_contract] = contract_address

                deployed_code = self.eth_getCode(address_decoder(contract_address))

                if len(deployed_code) == 0:
                    raise RuntimeError('Contract address has no code, check gas usage.')

            hex_bytecode = solidity_resolve_symbols(contract['bin_hex'], libraries)
            bytecode = unhexlify(hex_bytecode)

            contract['bin_hex'] = hex_bytecode
            contract['bin'] = bytecode

        if constructor_parameters:
            translator = ContractTranslator(contract_interface)
            parameters = translator.encode_constructor_arguments(constructor_parameters)
            bytecode = contract['bin'] + parameters
        else:
            bytecode = contract['bin']

        transaction_hash_hex = self.send_transaction(
            sender,
            to=b'',
            data=bytecode,
        )
        transaction_hash = unhexlify(transaction_hash_hex)

        self.poll(transaction_hash, timeout=timeout)
        receipt = self.eth_getTransactionReceipt(transaction_hash)
        contract_address = receipt['contractAddress']

        deployed_code = self.eth_getCode(address_decoder(contract_address))

        if len(deployed_code) == 0:
            raise RuntimeError(
                'Deployment of {} failed. Contract address has no code, check gas usage.'.format(
                    contract_name,
                )
            )

        return self.new_contract_proxy(
            contract_interface,
            contract_address,
        )

    def new_filter(self, fromBlock=None, toBlock=None, address=None, topics=None):
        """ Creates a filter object, based on filter options, to notify when
        the state changes (logs). To check if the state has changed, call
        eth_getFilterChanges.
        """

        json_data = {
            'fromBlock': block_tag_encoder(fromBlock or ''),
            'toBlock': block_tag_encoder(toBlock or ''),
        }

        if address is not None:
            json_data['address'] = address_encoder(address)

        if topics is not None:
            if not isinstance(topics, list):
                raise ValueError('topics must be a list')

            json_data['topics'] = [topic_encoder(topic) for topic in topics]

        filter_id = self.call('eth_newFilter', json_data)
        return quantity_decoder(filter_id)

    def filter_changes(self, fid: int) -> List:
        changes = self.call('eth_getFilterChanges', quantity_encoder(fid))

        if not changes:
            return list()

        assert isinstance(changes, list)
        decoders = {
            'blockHash': data_decoder,
            'transactionHash': data_decoder,
            'data': data_decoder,
            'address': address_decoder,
            'topics': lambda x: [topic_decoder(t) for t in x],
            'blockNumber': quantity_decoder,
            'logIndex': quantity_decoder,
            'transactionIndex': quantity_decoder
        }
        return [
            {k: decoders[k](v) for k, v in c.items() if v is not None}
            for c in changes
        ]

    @check_node_connection
    def call(self, method: str, *args):
        """ Do the request and return the result.

        Args:
            method: The RPC method.
            args: The encoded arguments expected by the method.
                - Object arguments must be supplied as a dictionary.
                - Quantity arguments must be hex encoded starting with '0x' and
                without left zeros.
                - Data arguments must be hex encoded starting with '0x'
        """
        request = self.protocol.create_request(method, args)
        reply = self.transport.send_message(request.serialize().encode())

        jsonrpc_reply = self.protocol.parse_reply(reply)
        if isinstance(jsonrpc_reply, JSONRPCSuccessResponse):
            return jsonrpc_reply.result
        elif isinstance(jsonrpc_reply, JSONRPCErrorResponse):
            raise EthNodeCommunicationError(jsonrpc_reply.error, jsonrpc_reply._jsonrpc_error_code)
        else:
            raise EthNodeCommunicationError('Unknown type of JSONRPC reply')

    def send_transaction(
            self,
            sender: address,
            to: address,
            value: int = 0,
            data: bytes = b'',
            startgas: int = None,
            nonce: int = None):
        """ Helper to send signed messages.

        This method will use the `privkey` provided in the constructor to
        locally sign the transaction. This requires an extended server
        implementation that accepts the variables v, r, and s.
        """

        if not self.privkey and not sender:
            raise ValueError('Either privkey or sender needs to be supplied.')

        if self.privkey:
            privkey_address = privatekey_to_address(self.privkey)
            sender = sender or privkey_address

            if sender != privkey_address:
                raise ValueError('sender for a different privkey.')

            if nonce is None:
                nonce = self.nonce(sender)
        else:
            if nonce is None:
                nonce = 0

        startgas = self.check_startgas(startgas)

        tx = Transaction(nonce, self.gasprice(), startgas, to=to, value=value, data=data)

        if self.privkey:
            tx.sign(self.privkey)
            result = self.call(
                'eth_sendRawTransaction',
                data_encoder(rlp.encode(tx)),
            )
            return result[2 if result.startswith('0x') else 0:]

        else:

            # rename the fields to match the eth_sendTransaction signature
            tx_dict = tx.to_dict()
            tx_dict.pop('hash')
            tx_dict['sender'] = sender
            tx_dict['gasPrice'] = tx_dict.pop('gasprice')
            tx_dict['gas'] = tx_dict.pop('startgas')

            res = self.eth_sendTransaction(**tx_dict)

        assert len(res) in (20, 32)
        return hexlify(res)

    def eth_sendTransaction(
            self,
            sender: address = b'',
            to: address = b'',
            value: int = 0,
            data: bytes = b'',
            gas: int = GAS_LIMIT,
            nonce: int = None
    ) -> bytes:
        """ Creates new message call transaction or a contract creation, if the
        data field contains code.

        Args:
            sender: The address the transaction is sent from.
            to: The address the transaction is directed to.
                (optional when creating new contract)
            gas: Gas provided for the transaction execution. It will
                return unused gas.
            gasPrice: gasPrice used for each unit of gas paid.
            value: Value sent with this transaction.
            data: The compiled code of a contract OR the hash of the
                invoked method signature and encoded parameters.
            nonce: This allows to overwrite your own pending transactions
                that use the same nonce.
        """

        if to == b'' and data.isalnum():
            warnings.warn(
                'Verify that the data parameter is _not_ hex encoded, if this is the case '
                'the data will be double encoded and result in unexpected '
                'behavior.'
            )

        if to == b'0' * 40:
            warnings.warn('For contract creation the empty string must be used.')

        if sender is None:
            raise ValueError('sender needs to be provided.')

        json_data = format_data_for_call(
            sender,
            to,
            value,
            data,
            gas,
            self.gasprice()
        )

        if nonce is not None:
            json_data['nonce'] = quantity_encoder(nonce)

        res = self.call('eth_sendTransaction', json_data)

        return data_decoder(res)

    def eth_call(
            self,
            sender: address = b'',
            to: address = b'',
            value: int = 0,
            data: bytes = b'',
            startgas: int = None,
            block_number: Union[str, int] = 'latest'
    ) -> bytes:
        """ Executes a new message call immediately without creating a
        transaction on the blockchain.

        Args:
            sender: The address the transaction is sent from.
            to: The address the transaction is directed to.
            gas: Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            gasPrice: gasPrice used for unit of gas paid.
            value: Integer of the value sent with this transaction.
            data: Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """
        startgas = self.check_startgas(startgas)
        json_data = format_data_for_call(
            sender,
            to,
            value,
            data,
            startgas,
            self.gasprice(),
        )
        res = self.call('eth_call', json_data, block_number)

        return data_decoder(res)

    def eth_estimateGas(
            self,
            sender: address = b'',
            to: address = b'',
            value: int = 0,
            data: bytes = b'',
            startgas: int = None
    ) -> Optional[int]:
        """ Makes a call or transaction, which won't be added to the blockchain
        and returns the used gas, which can be used for estimating the used
        gas.

        Args:
            sender: The address the transaction is sent from.
            to: The address the transaction is directed to.
            gas: Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            value: Integer of the value sent with this transaction.
            data: Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """
        startgas = self.check_startgas(startgas)
        json_data = format_data_for_call(
            sender,
            to,
            value,
            data,
            startgas
        )
        try:
            res = self.call('eth_estimateGas', json_data)
        except EthNodeCommunicationError as e:
            tx_would_fail = e.error_code and e.error_code in (-32015, -32000)
            if tx_would_fail:  # -32015 is parity and -32000 is geth
                return None
            else:
                raise e

        return quantity_decoder(res)

    def eth_getTransactionReceipt(self, transaction_hash: bytes) -> Dict:
        """ Returns the receipt of a transaction by transaction hash.

        Args:
            transaction_hash: Hash of a transaction.

        Returns:
            A dict representing the transaction receipt object, or null when no
            receipt was found.
        """
        if transaction_hash.startswith(b'0x'):
            warnings.warn(
                'transaction_hash seems to be already encoded, this will'
                ' result in unexpected behavior'
            )

        if len(transaction_hash) != 32:
            raise ValueError(
                'transaction_hash length must be 32 (it might be hex encoded)'
            )

        transaction_hash = data_encoder(transaction_hash)
        return self.call('eth_getTransactionReceipt', transaction_hash)

    def eth_getCode(self, code_address: address, block: Union[int, str] = 'latest') -> bytes:
        """ Returns code at a given address.

        Args:
            code_address: An address.
            block: Integer block number, or the string 'latest',
                'earliest' or 'pending'. Default is 'latest'.
        """
        if code_address.startswith(b'0x'):
            warnings.warn(
                'address seems to be already encoded, this will result '
                'in unexpected behavior'
            )

        if len(code_address) != 20:
            raise ValueError(
                'address length must be 20 (it might be hex encoded)'
            )

        result = self.call('eth_getCode', address_encoder(code_address), block)
        return data_decoder(result)

    def eth_getTransactionByHash(self, transaction_hash: bytes):
        """ Returns the information about a transaction requested by
        transaction hash.
        """

        if transaction_hash.startswith(b'0x'):
            warnings.warn(
                'transaction_hash seems to be already encoded, this will'
                ' result in unexpected behavior'
            )

        if len(transaction_hash) != 32:
            raise ValueError(
                'transaction_hash length must be 32 (it might be hex encoded)'
            )

        transaction_hash = data_encoder(transaction_hash)
        return self.call('eth_getTransactionByHash', transaction_hash)

    def poll(
            self,
            transaction_hash: bytes,
            confirmations: int = None,
            timeout: float = None):
        """ Wait until the `transaction_hash` is applied or rejected.
        If timeout is None, this could wait indefinitely!

        Args:
            transaction_hash: Transaction hash that we are waiting for.
            confirmations: Number of block confirmations that we will
                wait for.
            timeout: Timeout in seconds, raise an Excpetion on timeout.
        """
        if transaction_hash.startswith(b'0x'):
            warnings.warn(
                'transaction_hash seems to be already encoded, this will'
                ' result in unexpected behavior'
            )

        if len(transaction_hash) != 32:
            raise ValueError(
                'transaction_hash length must be 32 (it might be hex encoded)'
            )

        transaction_hash = data_encoder(transaction_hash)

        deadline = None
        if timeout:
            deadline = gevent.Timeout(timeout)
            deadline.start()

        try:
            # used to check if the transaction was removed, this could happen
            # if gas price is too low:
            #
            # > Transaction (acbca3d6) below gas price (tx=1 Wei ask=18
            # > Shannon). All sequential txs from this address(7d0eae79)
            # > will be ignored
            #
            last_result = None

            while True:
                # Could return None for a short period of time, until the
                # transaction is added to the pool
                transaction = self.call('eth_getTransactionByHash', transaction_hash)

                # if the transaction was added to the pool and then removed
                if transaction is None and last_result is not None:
                    raise Exception('invalid transaction, check gas price')

                # the transaction was added to the pool and mined
                if transaction and transaction['blockNumber'] is not None:
                    break

                last_result = transaction

                gevent.sleep(.5)

            if confirmations:
                # this will wait for both APPLIED and REVERTED transactions
                transaction_block = quantity_decoder(transaction['blockNumber'])
                confirmation_block = transaction_block + confirmations

                block_number = self.block_number()

                while block_number < confirmation_block:
                    gevent.sleep(.5)
                    block_number = self.block_number()

        except gevent.Timeout:
            raise Exception('timeout when polling for transaction')

        finally:
            if deadline:
                deadline.cancel()
