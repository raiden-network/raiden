import copy
import os
import sys
import warnings
from binascii import unhexlify
from json.decoder import JSONDecodeError
from itertools import count

from pkg_resources import DistributionNotFound
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from web3.utils.filters import Filter
from eth_utils import (
    encode_hex,
    to_checksum_address,
    to_canonical_address,
    to_normalized_address,
)
import gevent
from gevent.lock import Semaphore
from cachetools import TTLCache, cachedmethod
from operator import attrgetter
import structlog

from raiden.exceptions import (
    AddressWithoutCode,
    EthNodeCommunicationError,
    RaidenShuttingDown,
)
from raiden.settings import RPC_CACHE_TTL
from raiden.utils import (
    is_supported_client,
    privatekey_to_address,
)
from raiden.utils.typing import List, Dict, Iterable, Address, BlockSpecification
from raiden.utils.filters import StatelessFilter
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils.solc import (
    solidity_unresolved_symbols,
    solidity_library_symbol,
    solidity_resolve_symbols,
)
from raiden.constants import (
    NULL_ADDRESS,
    TESTNET_GASPRICE_MULTIPLIER,
)

try:
    from eth_tester.exceptions import BlockNotFound
except (ModuleNotFoundError, DistributionNotFound):
    class BlockNotFound(Exception):
        pass


log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def make_connection_test_middleware(client):
    def connection_test_middleware(make_request, web3):
        """ Creates middleware that checks if the provider is connected. """

        def middleware(method, params):
            # raise exception when shutting down
            if client.stop_event and client.stop_event.is_set():
                raise RaidenShuttingDown()

            try:
                if web3.isConnected():
                    return make_request(method, params)
                else:
                    raise EthNodeCommunicationError('Web3 provider not connected')

            # the isConnected check doesn't currently catch JSON errors
            # see https://github.com/ethereum/web3.py/issues/866
            except JSONDecodeError:
                raise EthNodeCommunicationError('Web3 provider not connected')

        return middleware
    return connection_test_middleware


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
            to_normalized_address(address),
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
            nonce_offset: int = 0,
            web3: Web3 = None,
    ):

        if privkey is None or len(privkey) != 32:
            raise ValueError('Invalid private key')

        endpoint = 'http://{}:{}'.format(host, port)

        self.port = port
        self.privkey = privkey
        self.sender = privatekey_to_address(privkey)
        # Needs to be initialized to None in the beginning since JSONRPCClient
        # gets constructed before the RaidenService Object.
        self.stop_event = None

        self._nonce_offset = nonce_offset
        self._nonce_lock = Semaphore()
        self.given_gas_price = gasprice

        self._gaslimit_cache = TTLCache(maxsize=16, ttl=RPC_CACHE_TTL)
        self._gasprice_cache = TTLCache(maxsize=16, ttl=RPC_CACHE_TTL)
        self._nonce_cache = TTLCache(maxsize=16, ttl=nonce_update_interval)

        # web3
        if web3 is None:
            self.web3: Web3 = Web3(HTTPProvider(endpoint))
        else:
            self.web3 = web3
        try:
            # we use a PoA chain for smoketest, use this middleware to fix this
            self.web3.middleware_stack.inject(geth_poa_middleware, layer=0)
        except ValueError:
            # `middleware_stack.inject()` raises a value error if the same middleware is
            # injected twice. This happens with `eth-tester` setup where a single session
            # scoped web3 instance is used for all clients
            pass

        # create the connection test middleware (but only for non-tester chain)
        if not hasattr(web3, 'testing'):
            connection_test = make_connection_test_middleware(self)
            self.web3.middleware_stack.inject(connection_test, layer=0)

        supported, self.eth_node = is_supported_client(self.web3.version.node)

        if not supported:
            print('You need a Byzantium enabled ethereum node. Parity >= 1.7.6 or Geth >= 1.7.2')
            sys.exit(1)

    def __repr__(self):
        return '<JSONRPCClient @%d>' % self.port

    def block_number(self):
        """ Return the most recent block. """
        return self.web3.eth.blockNumber

    @cachedmethod(attrgetter('_nonce_cache'))
    def _node_nonce_it(self) -> Iterable[int]:
        """Returns counter iterator from the account's nonce

        As this method is backed by a TTLCache and _nonce_lock-protected,
        it may be used as iterable-cache of the node's nonce, and refreshed every
        nonce_update_inverval seconds, to ensure it's always in-sync.
        """
        transaction_count = self.web3.eth.getTransactionCount(
            to_checksum_address(self.sender),
            'pending',
        )
        nonce = transaction_count + self._nonce_offset

        return count(nonce)

    def _nonce(self) -> int:
        """Returns and increments the nonce on every call"""
        return next(self._node_nonce_it())

    def inject_stop_event(self, event):
        self.stop_event = event

    def balance(self, account: Address):
        """ Return the balance of the account of given address. """
        return self.web3.eth.getBalance(to_checksum_address(account), 'pending')

    @cachedmethod(attrgetter('_gaslimit_cache'))
    def gaslimit(self, location='latest') -> int:
        gas_limit = self.web3.eth.getBlock(location)['gasLimit']
        return gas_limit * 8 // 10

    @cachedmethod(attrgetter('_gasprice_cache'))
    def gasprice(self) -> int:
        if self.given_gas_price:
            return self.given_gas_price

        return round(TESTNET_GASPRICE_MULTIPLIER * self.web3.eth.gasPrice)

    def check_startgas(self, startgas):
        if not startgas:
            return self.gaslimit()
        return startgas

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
            contract_name,
            all_contracts,
            libraries=None,
            constructor_parameters=None,
            contract_path=None,
            confirmations=None,
    ):
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
        """
        if libraries is None:
            libraries = dict()
        if constructor_parameters is None:
            constructor_parameters = []
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

        libraries = dict(libraries)
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

            log.debug('Deploying dependencies: {}'.format(str(deployment_order)))

            for deploy_contract in deployment_order:
                dependency_contract = all_contracts[deploy_contract]

                hex_bytecode = solidity_resolve_symbols(dependency_contract['bin'], libraries)
                bytecode = unhexlify(hex_bytecode)

                dependency_contract['bin'] = bytecode

                transaction_hash = self.send_transaction(
                    to=Address(b''),
                    data=bytecode,
                )

                self.poll(transaction_hash)
                receipt = self.get_transaction_receipt(transaction_hash)

                contract_address = receipt['contractAddress']
                # remove the hexadecimal prefix 0x from the address
                contract_address = contract_address[2:]

                libraries[deploy_contract] = contract_address

                deployed_code = self.web3.eth.getCode(to_checksum_address(contract_address))

                if not deployed_code:
                    raise RuntimeError('Contract address has no code, check gas usage.')

            hex_bytecode = solidity_resolve_symbols(contract['bin'], libraries)
            bytecode = unhexlify(hex_bytecode)

            contract['bin'] = bytecode

        if isinstance(contract['bin'], str):
            contract['bin'] = unhexlify(contract['bin'])

        if not constructor_parameters:
            constructor_parameters = ()

        contract = self.web3.eth.contract(abi=contract['abi'], bytecode=contract['bin'])
        contract_transaction = contract.constructor(*constructor_parameters).buildTransaction()
        transaction_hash = self.send_transaction(
            to=Address(b''),
            data=contract_transaction['data'],
            startgas=contract_transaction['gas'],
        )

        self.poll(transaction_hash, confirmations)
        receipt = self.get_transaction_receipt(transaction_hash)
        contract_address = receipt['contractAddress']

        deployed_code = self.web3.eth.getCode(to_checksum_address(contract_address))

        if not deployed_code:
            raise RuntimeError(
                'Deployment of {} failed. Contract address has no code, check gas usage.'.format(
                    contract_name,
                ),
            )

        return self.new_contract_proxy(
            contract_interface,
            contract_address,
        )

    def send_transaction(
            self,
            to: Address,
            value: int = 0,
            data: bytes = b'',
            startgas: int = None,
            gasprice: int = None,
    ) -> bytes:
        """ Helper to send signed messages.

        This method will use the `privkey` provided in the constructor to
        locally sign the transaction. This requires an extended server
        implementation that accepts the variables v, r, and s.
        """
        if to == to_canonical_address(NULL_ADDRESS):
            warnings.warn('For contract creation the empty string must be used.')

        with self._nonce_lock:
            transaction = dict(
                nonce=self._nonce(),
                gasPrice=gasprice or self.gasprice(),
                gas=self.check_startgas(startgas),
                value=value,
                data=data,
            )

            # add the to address if not deploying a contract
            if to != b'':
                transaction['to'] = to_checksum_address(to)

            signed_txn = self.web3.eth.account.signTransaction(transaction, self.privkey)

            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            log.debug(
                'send_raw_transaction',
                account=to_checksum_address(self.sender),
                nonce=transaction['nonce'],
                gasLimit=transaction['gas'],
                gasPrice=transaction['gasPrice'],
                tx_hash=tx_hash,
            )
            return tx_hash

    def poll(self, transaction_hash: bytes, confirmations: int = None):
        """ Wait until the `transaction_hash` is applied or rejected.

        Args:
            transaction_hash: Transaction hash that we are waiting for.
            confirmations: Number of block confirmations that we will
                wait for.
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
                break

            last_result = transaction
            gevent.sleep(.5)

        if confirmations:
            # this will wait for both APPLIED and REVERTED transactions
            transaction_block = transaction['blockNumber']
            confirmation_block = transaction_block + confirmations

            block_number = self.block_number()

            while block_number < confirmation_block:
                gevent.sleep(.5)
                block_number = self.block_number()

    def new_filter(
            self,
            contract_address: Address,
            topics: List[str] = None,
            from_block: BlockSpecification = 0,
            to_block: BlockSpecification = 'latest',
    ) -> Filter:
        """ Create a filter in the ethereum node. """
        return StatelessFilter(
            self.web3,
            {
                'fromBlock': from_block,
                'toBlock': to_block,
                'address': to_normalized_address(contract_address),
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
        try:
            return self.web3.eth.getLogs({
                'fromBlock': from_block,
                'toBlock': to_block,
                'address': to_normalized_address(contract_address),
                'topics': topics,
            })
        except BlockNotFound:
            return []
