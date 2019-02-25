import copy
import os
import warnings
from typing import Any, Callable, Dict, List, Optional, Tuple

import gevent
import structlog
from eth_utils import (
    decode_hex,
    encode_hex,
    is_checksum_address,
    remove_0x_prefix,
    to_canonical_address,
    to_checksum_address,
)
from gevent.lock import Semaphore
from requests import ConnectTimeout
from web3 import Web3
from web3.contract import ContractFunction
from web3.eth import Eth
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.middleware import geth_poa_middleware
from web3.utils.contracts import prepare_transaction
from web3.utils.empty import empty
from web3.utils.toolz import assoc

from raiden import constants
from raiden.exceptions import (
    AddressWithoutCode,
    EthNodeCommunicationError,
    EthNodeInterfaceError,
    InsufficientFunds,
)
from raiden.network.rpc.middleware import block_hash_cache_middleware, connection_test_middleware
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import is_supported_client, pex, privatekey_to_address
from raiden.utils.filters import StatelessFilter
from raiden.utils.solc import (
    solidity_library_symbol,
    solidity_resolve_symbols,
    solidity_unresolved_symbols,
)
from raiden.utils.typing import (
    ABI,
    Address,
    AddressHex,
    BlockHash,
    BlockSpecification,
    Nonce,
    TransactionHash,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def logs_blocks_sanity_check(from_block: BlockSpecification, to_block: BlockSpecification) -> None:
    """Checks that the from/to blocks passed onto log calls contain only appropriate types"""
    is_valid_from = isinstance(from_block, int) or isinstance(from_block, str)
    assert is_valid_from, 'event log from block can be integer or latest,pending, earliest'
    is_valid_to = isinstance(to_block, int) or isinstance(to_block, str)
    assert is_valid_to, 'event log to block can be integer or latest,pending, earliest'


def geth_assert_rpc_interfaces(web3: Web3):

    try:
        web3.version.node
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying geth node does not have the web3 rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool',
        )

    try:
        web3.eth.blockNumber
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying geth node does not have the eth rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool',
        )

    try:
        web3.net.version
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying geth node does not have the net rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool',
        )

    try:
        web3.txpool.inspect
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying geth node does not have the txpool rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool',
        )


def parity_assert_rpc_interfaces(web3: Web3):

    try:
        web3.version.node
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying parity node does not have the web3 rpc interface '
            'enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity',
        )

    try:
        web3.eth.blockNumber
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying parity node does not have the eth rpc interface '
            'enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity',
        )

    try:
        web3.net.version
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying parity node does not have the net rpc interface '
            'enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity',
        )

    try:
        web3.manager.request_blocking(
            'parity_nextNonce',
            ['0x0000000000000000000000000000000000000000'],
        )
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying parity node does not have the parity rpc interface '
            'enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity',
        )


def parity_discover_next_available_nonce(
        web3: Web3,
        address: AddressHex,
) -> Nonce:
    """Returns the next available nonce for `address`."""
    next_nonce_encoded = web3.manager.request_blocking('parity_nextNonce', [address])
    return int(next_nonce_encoded, 16)


def geth_discover_next_available_nonce(
        web3: Web3,
        address: AddressHex,
) -> Nonce:
    """Returns the next available nonce for `address`."""

    # The nonces of the mempool transactions are considered used, and it's
    # assumed these transactions are different from the ones currently pending
    # in the client. This is a simplification, otherwise it would be necessary
    # to filter the local pending transactions based on the mempool.
    pool = web3.txpool.inspect or {}

    # pool is roughly:
    #
    # {'queued': {'account1': {nonce1: ... nonce2: ...}, 'account2': ...}, 'pending': ...}
    #
    # Pending refers to the current block and if it contains transactions from
    # the user, these will be the younger transactions. Because this needs the
    # largest nonce, queued is checked first.

    queued = pool.get('queued', {}).get(address)
    if queued:
        return max(queued.keys()) + 1

    pending = pool.get('pending', {}).get(address)
    if pending:
        return max(pending.keys()) + 1

    # The first valid nonce is 0, therefore the count is already the next
    # available nonce
    return web3.eth.getTransactionCount(address, 'latest')


def check_address_has_code(
        client: 'JSONRPCClient',
        address: Address,
        contract_name: str = '',
):
    """ Checks that the given address contains code. """
    result = client.web3.eth.getCode(to_checksum_address(address), 'latest')

    if not result:
        if contract_name:
            formated_contract_name = '[{}]: '.format(contract_name)
        else:
            formated_contract_name = ''

        raise AddressWithoutCode('{}Address {} does not contain code'.format(
            formated_contract_name,
            to_checksum_address(address),
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
        unresolved_symbols = solidity_unresolved_symbols(contract['bin'])
        dependencies[contract_name] = [
            symbols_to_contract[unresolved]
            for unresolved in unresolved_symbols
        ]

    return dependencies


def dependencies_order_of_build(target_contract, dependencies_map):
    """ Return an ordered list of contracts that is sufficient to successfully
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


def patched_web3_eth_estimate_gas(self, transaction, block_identifier=None):
    """ Temporary workaround until next web3.py release (5.X.X)

    Current master of web3.py has this implementation already:
    https://github.com/ethereum/web3.py/blob/2a67ea9f0ab40bb80af2b803dce742d6cad5943e/web3/eth.py#L311
    """
    if 'from' not in transaction and is_checksum_address(self.defaultAccount):
        transaction = assoc(transaction, 'from', self.defaultAccount)

    if block_identifier is None:
        params = [transaction]
    else:
        params = [transaction, block_identifier]

    return self.web3.manager.request_blocking(
        'eth_estimateGas',
        params,
    )


def estimate_gas_for_function(
        address,
        web3,
        fn_identifier=None,
        transaction=None,
        contract_abi=None,
        fn_abi=None,
        block_identifier=None,
        *args,
        **kwargs,
):
    """Temporary workaround until next web3.py release (5.X.X)"""
    estimate_transaction = prepare_transaction(
        address,
        web3,
        fn_identifier=fn_identifier,
        contract_abi=contract_abi,
        fn_abi=fn_abi,
        transaction=transaction,
        fn_args=args,
        fn_kwargs=kwargs,
    )

    gas_estimate = web3.eth.estimateGas(estimate_transaction, block_identifier)
    return gas_estimate


def patched_contractfunction_estimateGas(self, transaction=None, block_identifier=None):
    """Temporary workaround until next web3.py release (5.X.X)"""
    if transaction is None:
        estimate_gas_transaction = {}
    else:
        estimate_gas_transaction = dict(**transaction)

    if 'data' in estimate_gas_transaction:
        raise ValueError('Cannot set data in estimateGas transaction')
    if 'to' in estimate_gas_transaction:
        raise ValueError('Cannot set to in estimateGas transaction')

    if self.address:
        estimate_gas_transaction.setdefault('to', self.address)
    if self.web3.eth.defaultAccount is not empty:
        estimate_gas_transaction.setdefault('from', self.web3.eth.defaultAccount)

    if 'to' not in estimate_gas_transaction:
        if isinstance(self, type):
            raise ValueError(
                'When using `Contract.estimateGas` from a contract factory '
                'you must provide a `to` address with the transaction',
            )
        else:
            raise ValueError(
                'Please ensure that this contract instance has an address.',
            )

    return estimate_gas_for_function(
        self.address,
        self.web3,
        self.function_identifier,
        estimate_gas_transaction,
        self.contract_abi,
        self.abi,
        block_identifier,
        *self.args,
        **self.kwargs,
    )


def monkey_patch_web3(web3, gas_price_strategy):
    try:
        # install caching middleware
        web3.middleware_stack.add(block_hash_cache_middleware)

        # set gas price strategy
        web3.eth.setGasPriceStrategy(gas_price_strategy)

        # we use a PoA chain for smoketest, use this middleware to fix this
        web3.middleware_stack.inject(geth_poa_middleware, layer=0)
    except ValueError:
        # `middleware_stack.inject()` raises a value error if the same middleware is
        # injected twice. This happens with `eth-tester` setup where a single session
        # scoped web3 instance is used for all clients
        pass

    # create the connection test middleware (but only for non-tester chain)
    if not hasattr(web3, 'testing'):
        web3.middleware_stack.inject(connection_test_middleware, layer=0)

    # Temporary until next web3.py release (5.X.X)
    ContractFunction.estimateGas = patched_contractfunction_estimateGas
    Eth.estimateGas = patched_web3_eth_estimate_gas


class JSONRPCClient:
    """ Ethereum JSON RPC client.

    Args:
        host: Ethereum node host address.
        port: Ethereum node port number.
        privkey: Local user private key, used to sign transactions.
    """

    def __init__(
            self,
            web3: Web3,
            privkey: bytes,
            gas_price_strategy: Callable = rpc_gas_price_strategy,
            gas_estimate_correction: Callable = lambda gas: gas,
            block_num_confirmations: int = 0,
            uses_infura=False,
    ):
        if privkey is None or len(privkey) != 32:
            raise ValueError('Invalid private key')

        if block_num_confirmations < 0:
            raise ValueError(
                'Number of confirmations has to be positive',
            )

        monkey_patch_web3(web3, gas_price_strategy)

        try:
            version = web3.version.node
        except ConnectTimeout:
            raise EthNodeCommunicationError('couldnt reach the ethereum node')

        _, eth_node = is_supported_client(version)

        address = privatekey_to_address(privkey)
        address_checksumed = to_checksum_address(address)

        if uses_infura:
            warnings.warn(
                'Infura does not provide an API to '
                'recover the latest used nonce. This may cause the Raiden node '
                'to error on restarts.\n'
                'The error will manifest while there is a pending transaction '
                'from a previous execution in the Ethereum\'s client pool. When '
                'Raiden restarts the same transaction with the same nonce will '
                'be retried and *rejected*, because the nonce is already used.',
            )
            # The first valid nonce is 0, therefore the count is already the next
            # available nonce
            available_nonce = web3.eth.getTransactionCount(address_checksumed, 'pending')

        elif eth_node == constants.EthClient.PARITY:
            parity_assert_rpc_interfaces(web3)
            available_nonce = parity_discover_next_available_nonce(
                web3,
                address_checksumed,
            )

        elif eth_node == constants.EthClient.GETH:
            geth_assert_rpc_interfaces(web3)
            available_nonce = geth_discover_next_available_nonce(
                web3,
                address_checksumed,
            )

        else:
            raise EthNodeInterfaceError(f'Unsupported Ethereum client {version}')

        self.eth_node = eth_node
        self.privkey = privkey
        self.address = address
        self.web3 = web3
        self.default_block_num_confirmations = block_num_confirmations

        self._available_nonce = available_nonce
        self._nonce_lock = Semaphore()
        self._gas_estimate_correction = gas_estimate_correction

        log.debug(
            'JSONRPCClient created',
            node=pex(self.address),
            available_nonce=available_nonce,
            client=version,
        )

    def __repr__(self):
        return f'<JSONRPCClient node:{pex(self.address)} nonce:{self._available_nonce}>'

    def block_number(self):
        """ Return the most recent block. """
        return self.web3.eth.blockNumber

    def blockhash_from_blocknumber(self, block_number: BlockSpecification) -> BlockHash:
        """Given a block number, query the chain to get its corresponding block hash"""
        return bytes(self.web3.eth.getBlock(block_number)['hash'])

    def balance(self, account: Address):
        """ Return the balance of the account of the given address. """
        return self.web3.eth.getBalance(to_checksum_address(account), 'pending')

    def parity_get_pending_transaction_hash_by_nonce(
            self,
            address: AddressHex,
            nonce: Nonce,
    ) -> Optional[TransactionHash]:
        """Queries the local parity transaction pool and searches for a transaction.

        Checks the local tx pool for a transaction from a particular address and for
        a given nonce. If it exists it returns the transaction hash.
        """
        assert self.eth_node == constants.EthClient.PARITY
        # https://wiki.parity.io/JSONRPC-parity-module.html?q=traceTransaction#parity_alltransactions
        transactions = self.web3.manager.request_blocking('parity_allTransactions', [])
        log.debug('RETURNED TRANSACTIONS', transactions=transactions)
        for tx in transactions:
            address_match = to_checksum_address(tx['from']) == address
            if address_match and int(tx['nonce'], 16) == nonce:
                return tx['hash']
        return None

    def gas_price(self) -> int:
        try:
            # generateGasPrice takes the transaction to be send as an optional argument
            # but both strategies that we are using (time-based and rpc-based) don't make
            # use of this argument. It is therefore safe to not provide it at the moment.
            # This needs to be reevaluated if we use different gas price strategies
            price = int(self.web3.eth.generateGasPrice())
        except AttributeError:  # workaround for Infura gas strategy key error
            # As per https://github.com/raiden-network/raiden/issues/3201
            # we can sporadically get an AtttributeError here. If that happens
            # use latest gas price
            price = int(self.web3.eth.gasPrice)

        return price

    def new_contract_proxy(self, contract_interface, contract_address: Address):
        """ Return a proxy for interacting with a smart contract.

        Args:
            contract_interface: The contract interface as defined by the json.
            address: The contract's address.
        """
        return ContractProxy(
            self,
            contract=self.new_contract(contract_interface, contract_address),
        )

    def new_contract(self, contract_interface: Dict, contract_address: Address):
        return self.web3.eth.contract(
            abi=contract_interface,
            address=to_checksum_address(contract_address),
        )

    def get_transaction_receipt(self, tx_hash: bytes):
        return self.web3.eth.getTransactionReceipt(encode_hex(tx_hash))

    def deploy_solidity_contract(
            self,  # pylint: disable=too-many-locals
            contract_name: str,
            all_contracts: Dict[str, ABI],
            libraries: Dict[str, Address] = None,
            constructor_parameters: Tuple[Any] = None,
            contract_path: str = None,
    ):
        """
        Deploy a solidity contract.

        Args:
            contract_name: The name of the contract to compile.
            all_contracts: The json dictionary containing the result of compiling a file.
            libraries: A list of libraries to use in deployment.
            constructor_parameters: A tuple of arguments to pass to the constructor.
            contract_path: If we are dealing with solc >= v0.4.9 then the path
                           to the contract is a required argument to extract
                           the contract data from the `all_contracts` dict.
        """
        if libraries:
            libraries = dict(libraries)
        else:
            libraries = dict()

        constructor_parameters = constructor_parameters or list()
        all_contracts = copy.deepcopy(all_contracts)

        if contract_name in all_contracts:
            contract_key = contract_name

        elif contract_path is not None:
            contract_key = os.path.basename(contract_path) + ':' + contract_name

            if contract_key not in all_contracts:
                raise ValueError('Unknown contract {}'.format(contract_name))
        else:
            raise ValueError(
                'Unknown contract {} and no contract_path given'.format(contract_name),
            )

        contract = all_contracts[contract_key]
        contract_interface = contract['abi']
        symbols = solidity_unresolved_symbols(contract['bin'])

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

            log.debug(
                'Deploying dependencies: {}'.format(str(deployment_order)),
                node=pex(self.address),
            )

            for deploy_contract in deployment_order:
                dependency_contract = all_contracts[deploy_contract]

                hex_bytecode = solidity_resolve_symbols(dependency_contract['bin'], libraries)
                bytecode = decode_hex(hex_bytecode)

                dependency_contract['bin'] = bytecode

                gas_limit = self.web3.eth.getBlock('latest')['gasLimit'] * 8 // 10
                transaction_hash = self.send_transaction(
                    to=Address(b''),
                    startgas=gas_limit,
                    data=bytecode,
                )

                self.poll(transaction_hash)
                receipt = self.get_transaction_receipt(transaction_hash)

                contract_address = receipt['contractAddress']
                # remove the hexadecimal prefix 0x from the address
                contract_address = remove_0x_prefix(contract_address)

                libraries[deploy_contract] = contract_address

                deployed_code = self.web3.eth.getCode(to_checksum_address(contract_address))

                if not deployed_code:
                    raise RuntimeError('Contract address has no code, check gas usage.')

            hex_bytecode = solidity_resolve_symbols(contract['bin'], libraries)
            bytecode = decode_hex(hex_bytecode)

            contract['bin'] = bytecode

        if isinstance(contract['bin'], str):
            contract['bin'] = decode_hex(contract['bin'])

        if not constructor_parameters:
            constructor_parameters = ()

        contract = self.web3.eth.contract(abi=contract['abi'], bytecode=contract['bin'])
        contract_transaction = contract.constructor(*constructor_parameters).buildTransaction()
        transaction_hash = self.send_transaction(
            to=Address(b''),
            data=contract_transaction['data'],
            startgas=self._gas_estimate_correction(contract_transaction['gas']),
        )

        self.poll(transaction_hash)
        receipt = self.get_transaction_receipt(transaction_hash)
        contract_address = receipt['contractAddress']

        deployed_code = self.web3.eth.getCode(to_checksum_address(contract_address))

        if not deployed_code:
            raise RuntimeError(
                'Deployment of {} failed. Contract address has no code, check gas usage.'.format(
                    contract_name,
                ),
            )

        return self.new_contract_proxy(contract_interface, contract_address), receipt

    def send_transaction(
            self,
            to: Address,
            startgas: int,
            value: int = 0,
            data: bytes = b'',
    ) -> bytes:
        """ Helper to send signed messages.

        This method will use the `privkey` provided in the constructor to
        locally sign the transaction. This requires an extended server
        implementation that accepts the variables v, r, and s.
        """
        if to == to_canonical_address(constants.NULL_ADDRESS):
            warnings.warn('For contract creation the empty string must be used.')

        with self._nonce_lock:
            nonce = self._available_nonce
            gas_price = self.gas_price()

            transaction = {
                'data': data,
                'gas': startgas,
                'nonce': nonce,
                'value': value,
                'gasPrice': gas_price,
            }
            node_gas_price = self.web3.eth.gasPrice
            log.debug(
                'Calculated gas price for transaction',
                node=pex(self.address),
                calculated_gas_price=gas_price,
                node_gas_price=node_gas_price,
            )

            # add the to address if not deploying a contract
            if to != b'':
                transaction['to'] = to_checksum_address(to)

            signed_txn = self.web3.eth.account.signTransaction(transaction, self.privkey)

            log_details = {
                'node': pex(self.address),
                'nonce': transaction['nonce'],
                'gasLimit': transaction['gas'],
                'gasPrice': transaction['gasPrice'],
            }
            log.debug('send_raw_transaction called', **log_details)

            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            self._available_nonce += 1

            log.debug('send_raw_transaction returned', tx_hash=encode_hex(tx_hash), **log_details)
            return tx_hash

    def poll(
            self,
            transaction_hash: bytes,
    ):
        """ Wait until the `transaction_hash` is applied or rejected.

        Args:
            transaction_hash: Transaction hash that we are waiting for.
        """
        if len(transaction_hash) != 32:
            raise ValueError(
                'transaction_hash must be a 32 byte hash',
            )

        transaction_hash = encode_hex(transaction_hash)

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
            transaction = self.web3.eth.getTransaction(transaction_hash)

            # if the transaction was added to the pool and then removed
            if transaction is None and last_result is not None:
                raise Exception('invalid transaction, check gas price')

            # the transaction was added to the pool and mined
            if transaction and transaction['blockNumber'] is not None:
                last_result = transaction

                # this will wait for both APPLIED and REVERTED transactions
                transaction_block = transaction['blockNumber']
                confirmation_block = transaction_block + self.default_block_num_confirmations

                block_number = self.block_number()

                if block_number >= confirmation_block:
                    return transaction

            gevent.sleep(1.0)

    def new_filter(
            self,
            contract_address: Address,
            topics: List[str] = None,
            from_block: BlockSpecification = 0,
            to_block: BlockSpecification = 'latest',
    ) -> StatelessFilter:
        """ Create a filter in the ethereum node. """
        logs_blocks_sanity_check(from_block, to_block)
        return StatelessFilter(
            self.web3,
            {
                'fromBlock': from_block,
                'toBlock': to_block,
                'address': to_checksum_address(contract_address),
                'topics': topics,
            },
        )

    def get_filter_events(
            self,
            contract_address: Address,
            topics: List[str] = None,
            from_block: BlockSpecification = 0,
            to_block: BlockSpecification = 'latest',
    ) -> List[Dict]:
        """ Get events for the given query. """
        logs_blocks_sanity_check(from_block, to_block)
        return self.web3.eth.getLogs({
            'fromBlock': from_block,
            'toBlock': to_block,
            'address': to_checksum_address(contract_address),
            'topics': topics,
        })

    def check_for_insufficient_eth(
            self,
            transaction_name: str,
            transaction_executed: bool,
            required_gas: int,
            block_identifier: BlockSpecification,
    ):
        """ After estimate gas failure checks if our address has enough balance.

        If the account did not have enough ETH balance to execute the,
        transaction then it raises an `InsufficientFunds` error
        """
        if transaction_executed:
            return

        our_address = to_checksum_address(self.address)
        balance = self.web3.eth.getBalance(our_address, block_identifier)
        required_balance = required_gas * self.gas_price()
        if balance < required_balance:
            msg = f'Failed to execute {transaction_name} due to insufficient ETH'
            log.critical(msg, required_wei=required_balance, actual_wei=balance)
            raise InsufficientFunds(msg)

    def get_checking_block(self):
        """Workaround for parity https://github.com/paritytech/parity-ethereum/issues/9707
        In parity doing any call() with the 'pending' block no longer falls back
        to the latest if no pending block is found but throws a mistaken error.
        Until that bug is fixed we need to enforce special behaviour for parity
        and use the latest block for checking.
        """
        checking_block = 'pending'
        if self.eth_node == constants.EthClient.PARITY:
            checking_block = 'latest'
        return checking_block
