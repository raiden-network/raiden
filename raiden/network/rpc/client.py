# -*- coding: utf-8 -*-
import os
import warnings
from time import time as now
from binascii import unhexlify

import rlp
import gevent
from gevent.lock import Semaphore
from ethereum import slogging
from ethereum import _solidity
from ethereum.abi import ContractTranslator
from ethereum.transactions import Transaction
from ethereum.utils import normalize_address
from ethereum._solidity import (
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
)
from raiden.network.protocol import timeout_two_stage
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.settings import (
    GAS_PRICE,
)
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

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
solidity = _solidity.get_solidity()  # pylint: disable=invalid-name


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
        sender='',
        to='',
        value=0,
        data='',
        startgas=GAS_PRICE,
        gasprice=GAS_PRICE):
    """ Helper to format the transaction data. """

    json_data = {}

    if sender is not None:
        json_data['from'] = address_encoder(sender)

    if to is not None:
        json_data['to'] = data_encoder(to)

    if value is not None:
        json_data['value'] = quantity_encoder(value)

    if gasprice is not None:
        json_data['gasPrice'] = quantity_encoder(gasprice)

    if startgas is not None:
        json_data['gas'] = quantity_encoder(startgas)

    if data is not None:
        json_data['data'] = data_encoder(data)

    return json_data


def check_node_connection(func):
    """ A decorator to reconnect if the connection to the node is lost """
    def retry_on_disconnect(self, *args, **kwargs):
        for i, timeout in enumerate(timeout_two_stage(10, 3, 10)):
            try:
                result = func(self, *args, **kwargs)
                if i > 0:
                    log.info('Client reconnected')
                return result

            except (requests.exceptions.ConnectionError, InvalidReplyError):
                log.info(
                    'Timeout in eth client connection. Is the client offline? Trying '
                    'again in {}s.'.format(timeout)
                )
            gevent.sleep(timeout)

    return retry_on_disconnect


class JSONRPCClient(object):
    """ Ethereum JSON RPC client.

    Args:
        host (str): Ethereum node host address.
        port (int): Ethereum node port number.
        privkey (bin): Local user private key, used to sign transactions.
        nonce_update_interval (float): Update the account nonce every
            `nonce_update_interval` seconds.
        nonce_offset (int): Network's default base nonce number.
    """

    def __init__(self, host, port, privkey, nonce_update_interval=5.0, nonce_offset=0):
        endpoint = 'http://{}:{}'.format(host, port)
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=50)
        session.mount(endpoint, adapter)

        self.transport = HttpPostClientTransport(
            endpoint,
            post_method=session.post,
            headers={'content-type': 'application/json'},
        )

        self.port = port
        self.privkey = privkey
        self.protocol = JSONRPCProtocol()
        self.sender = privatekey_to_address(privkey)

        self.nonce_last_update = 0
        self.nonce_current_value = None
        self.nonce_lock = Semaphore()
        self.nonce_update_interval = nonce_update_interval
        self.nonce_offset = nonce_offset

    def __repr__(self):
        return '<JSONRPCClient @%d>' % self.port

    def blocknumber(self):
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

    def balance(self, account):
        """ Return the balance of the account of given address. """
        res = self.call('eth_getBalance', address_encoder(account), 'pending')
        return quantity_decoder(res)

    def gaslimit(self):
        last_block = self.call('eth_getBlockByNumber', 'latest', True)
        gas_limit = quantity_decoder(last_block['gasLimit'])
        return gas_limit

    def new_contract_proxy(self, contract_interface, address):
        """ Return a proxy for interacting with a smart contract.

        Args:
            contract_interface: The contract interface as defined by the json.
            address: The contract's address.
        """
        return ContractProxy(
            self.sender,
            contract_interface,
            address,
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
            timeout=None,
            gasprice=GAS_PRICE):
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
            gasprice: The gasprice to provide for the transaction
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
            available_symbols = map(solidity_library_symbol, all_contracts.keys())

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
                    to='',
                    data=bytecode,
                    gasprice=gasprice,
                )
                transaction_hash = unhexlify(transaction_hash_hex)

                self.poll(transaction_hash, timeout=timeout)
                receipt = self.eth_getTransactionReceipt(transaction_hash)

                contract_address = receipt['contractAddress']
                # remove the hexadecimal prefix 0x from the address
                contract_address = contract_address[2:]

                libraries[deploy_contract] = contract_address

                deployed_code = self.eth_getCode(unhexlify(contract_address))

                if deployed_code == '0x':
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
            to='',
            data=bytecode,
            gasprice=gasprice,
        )
        transaction_hash = unhexlify(transaction_hash_hex)

        self.poll(transaction_hash, timeout=timeout)
        receipt = self.eth_getTransactionReceipt(transaction_hash)
        contract_address = receipt['contractAddress']

        deployed_code = self.eth_getCode(unhexlify(contract_address[2:]))

        if deployed_code == '0x':
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

    def filter_changes(self, fid):
        changes = self.call('eth_getFilterChanges', quantity_encoder(fid))

        if not changes:
            return None

        if isinstance(changes, bytes):
            return data_decoder(changes)

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
    def call(self, method, *args):
        """ Do the request and return the result.

        Args:
            method (str): The RPC method.
            args: The encoded arguments expected by the method.
                - Object arguments must be supplied as a dictionary.
                - Quantity arguments must be hex encoded starting with '0x' and
                without left zeros.
                - Data arguments must be hex encoded starting with '0x'
        """
        request = self.protocol.create_request(method, args)
        reply = self.transport.send_message(request.serialize())

        jsonrpc_reply = self.protocol.parse_reply(reply)
        if isinstance(jsonrpc_reply, JSONRPCSuccessResponse):
            return jsonrpc_reply.result
        elif isinstance(jsonrpc_reply, JSONRPCErrorResponse):
            raise EthNodeCommunicationError(jsonrpc_reply.error)
        else:
            raise EthNodeCommunicationError('Unknown type of JSONRPC reply')

    def send_transaction(
            self,
            sender,
            to,
            value=0,
            data='',
            startgas=0,
            gasprice=GAS_PRICE,
            nonce=None):
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

        if not startgas:
            startgas = self.gaslimit() - 1

        tx = Transaction(nonce, gasprice, startgas, to=to, value=value, data=data)

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
        return res.encode('hex')

    def eth_sendTransaction(
            self,
            nonce=None,
            sender='',
            to='',
            value=0,
            data='',
            gasPrice=GAS_PRICE,
            gas=GAS_PRICE):
        """ Creates new message call transaction or a contract creation, if the
        data field contains code.

        Args:
            sender (address): The 20 bytes address the transaction is sent from.
            to (address): DATA, 20 Bytes - (optional when creating new
                contract) The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. It will
                return unused gas.
            gasPrice (int): gasPrice used for each unit of gas paid.
            value (int): Value sent with this transaction.
            data (bin): The compiled code of a contract OR the hash of the
                invoked method signature and encoded parameters.
            nonce (int): This allows to overwrite your own pending transactions
                that use the same nonce.
        """

        if to == '' and data.isalnum():
            warnings.warn(
                'Verify that the data parameter is _not_ hex encoded, if this is the case '
                'the data will be double encoded and result in unexpected '
                'behavior.'
            )

        if to == '0' * 40:
            warnings.warn('For contract creation the empty string must be used.')

        if sender is None:
            raise ValueError('sender needs to be provided.')

        json_data = {
            'to': data_encoder(normalize_address(to, allow_blank=True)),
            'value': quantity_encoder(value),
            'gasPrice': quantity_encoder(gasPrice),
            'gas': quantity_encoder(gas),
            'data': data_encoder(data),
            'from': address_encoder(sender),
        }

        if nonce is not None:
            json_data['nonce'] = quantity_encoder(nonce)

        res = self.call('eth_sendTransaction', json_data)

        return data_decoder(res)

    def eth_call(
            self,
            sender='',
            to='',
            value=0,
            data='',
            startgas=GAS_PRICE,
            gasprice=GAS_PRICE,
            block_number='latest'):
        """ Executes a new message call immediately without creating a
        transaction on the blockchain.

        Args:
            sender: The address the transaction is sent from.
            to: The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            gasPrice (int): gasPrice used for unit of gas paid.
            value (int): Integer of the value sent with this transaction.
            data (bin): Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """

        json_data = format_data_for_call(
            sender,
            to,
            value,
            data,
            startgas,
            gasprice,
        )
        res = self.call('eth_call', json_data, block_number)

        return data_decoder(res)

    def eth_estimateGas(
            self,
            sender='',
            to='',
            value=0,
            data='',
            startgas=GAS_PRICE,
            gasprice=GAS_PRICE):
        """ Makes a call or transaction, which won't be added to the blockchain
        and returns the used gas, which can be used for estimating the used
        gas.

        Args:
            sender: The address the transaction is sent from.
            to: The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            gasPrice (int): gasPrice used for unit of gas paid.
            value (int): Integer of the value sent with this transaction.
            data (bin): Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """

        json_data = format_data_for_call(
            sender,
            to,
            value,
            data,
            startgas,
            gasprice,
        )
        res = self.call('eth_estimateGas', json_data)

        return quantity_decoder(res)

    def eth_getTransactionReceipt(self, transaction_hash):
        """ Returns the receipt of a transaction by transaction hash.

        Args:
            transaction_hash: Hash of a transaction.

        Returns:
            A dict representing the transaction receipt object, or null when no
            receipt was found.
        """
        if transaction_hash.startswith('0x'):
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

    def eth_getCode(self, address, block='latest'):
        """ Returns code at a given address.

        Args:
            address: An address.
            block: Integer block number, or the string 'latest',
                'earliest' or 'pending'.
        """
        if address.startswith('0x'):
            warnings.warn(
                'address seems to be already encoded, this will result '
                'in unexpected behavior'
            )

        if len(address) != 20:
            raise ValueError(
                'address length must be 20 (it might be hex encoded)'
            )

        return self.call(
            'eth_getCode',
            address_encoder(address),
            block,
        )

    def eth_getTransactionByHash(self, transaction_hash):
        """ Returns the information about a transaction requested by
        transaction hash.
        """

        if transaction_hash.startswith('0x'):
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

    def poll(self, transaction_hash, confirmations=None, timeout=None):
        """ Wait until the `transaction_hash` is applied or rejected.
        If timeout is None, this could wait indefinitely!

        Args:
            transaction_hash (hash): Transaction hash that we are waiting for.
            confirmations (int): Number of block confirmations that we will
                wait for.
            timeout (float): Timeout in seconds, raise an Excpetion on
                timeout.
        """
        if transaction_hash.startswith('0x'):
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

                block_number = self.blocknumber()

                while block_number < confirmation_block:
                    gevent.sleep(.5)
                    block_number = self.blocknumber()

        except gevent.Timeout:
            raise Exception('timeout when polling for transaction')

        finally:
            if deadline:
                deadline.cancel()
