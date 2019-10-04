import json
import warnings
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import gevent
import structlog
from eth_utils import encode_hex, is_checksum_address, to_canonical_address, to_checksum_address
from gevent.lock import Semaphore
from hexbytes import HexBytes
from requests.exceptions import ReadTimeout
from web3 import Web3
from web3.contract import ContractFunction
from web3.eth import Eth
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.middleware import geth_poa_middleware
from web3.utils.contracts import prepare_transaction
from web3.utils.empty import empty
from web3.utils.toolz import assoc

from raiden import constants
from raiden.blockchain.filters import StatelessFilter
from raiden.exceptions import (
    AddressWithoutCode,
    ContractCodeMismatch,
    EthNodeInterfaceError,
    InsufficientFunds,
)
from raiden.network.rpc.middleware import block_hash_cache_middleware
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import privatekey_to_address
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.typing import (
    ABI,
    Address,
    AddressHex,
    BlockHash,
    BlockSpecification,
    CompiledContract,
    Nonce,
    PrivateKey,
    TransactionHash,
)
from raiden_contracts.utils.type_aliases import ChainID

log = structlog.get_logger(__name__)


def logs_blocks_sanity_check(from_block: BlockSpecification, to_block: BlockSpecification) -> None:
    """Checks that the from/to blocks passed onto log calls contain only appropriate types"""
    is_valid_from = isinstance(from_block, int) or isinstance(from_block, str)
    assert is_valid_from, "event log from block can be integer or latest,pending, earliest"
    is_valid_to = isinstance(to_block, int) or isinstance(to_block, str)
    assert is_valid_to, "event log to block can be integer or latest,pending, earliest"


def geth_assert_rpc_interfaces(web3: Web3):

    try:
        web3.version.node
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying geth node does not have the web3 rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3"
        )

    try:
        web3.eth.blockNumber
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying geth node does not have the eth rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3"
        )

    try:
        web3.net.version
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying geth node does not have the net rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3"
        )


def parity_assert_rpc_interfaces(web3: Web3):

    try:
        web3.version.node
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying parity node does not have the web3 rpc interface "
            "enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity"
        )

    try:
        web3.eth.blockNumber
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying parity node does not have the eth rpc interface "
            "enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity"
        )

    try:
        web3.net.version
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying parity node does not have the net rpc interface "
            "enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity"
        )

    try:
        web3.manager.request_blocking(
            "parity_nextNonce", ["0x0000000000000000000000000000000000000000"]
        )
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying parity node does not have the parity rpc interface "
            "enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity"
        )


def parity_discover_next_available_nonce(web3: Web3, address: AddressHex) -> Nonce:
    """Returns the next available nonce for `address`."""
    next_nonce_encoded = web3.manager.request_blocking("parity_nextNonce", [address])
    return Nonce(int(next_nonce_encoded, 16))


def geth_discover_next_available_nonce(web3: Web3, address: AddressHex) -> Nonce:
    """Returns the next available nonce for `address`."""
    return web3.eth.getTransactionCount(address, "pending")


def check_address_has_code(
    client: "JSONRPCClient", address: Address, contract_name: str = "", expected_code: bytes = None
):
    """ Checks that the given address contains code. """
    result = client.web3.eth.getCode(to_checksum_address(address), "latest")

    if not result:
        raise AddressWithoutCode(
            "[{}]Address {} does not contain code".format(
                contract_name, to_checksum_address(address)
            )
        )

    if expected_code is not None and result != expected_code:
        raise ContractCodeMismatch(
            f"[{contract_name}]Address {to_checksum_address(address)} has wrong code."
        )


class ParityCallType(Enum):
    ESTIMATE_GAS = 1
    CALL = 2


def check_value_error_for_parity(value_error: ValueError, call_type: ParityCallType) -> bool:
    """
    For parity failing calls and functions do not return None if the transaction
    will fail but instead throw a ValueError exception.

    This function checks the thrown exception to see if it's the correct one and
    if yes returns True, if not returns False
    """
    try:
        error_data = json.loads(str(value_error).replace("'", '"'))
    except json.JSONDecodeError:
        return False

    if call_type == ParityCallType.ESTIMATE_GAS:
        code_checks_out = error_data["code"] == -32016
        message_checks_out = "The execution failed due to an exception" in error_data["message"]
    elif call_type == ParityCallType.CALL:
        code_checks_out = error_data["code"] == -32015
        message_checks_out = "VM execution error" in error_data["message"]
    else:
        raise ValueError("Called check_value_error_for_parity() with illegal call type")

    if code_checks_out and message_checks_out:
        return True

    return False


def patched_web3_eth_estimate_gas(self, transaction, block_identifier=None):
    """ Temporary workaround until next web3.py release (5.X.X)

    Current master of web3.py has this implementation already:
    https://github.com/ethereum/web3.py/blob/2a67ea9f0ab40bb80af2b803dce742d6cad5943e/web3/eth.py#L311
    """
    if "from" not in transaction and is_checksum_address(self.defaultAccount):
        transaction = assoc(transaction, "from", self.defaultAccount)

    if block_identifier is None:
        params = [transaction]
    else:
        params = [transaction, block_identifier]

    try:
        result = self.web3.manager.request_blocking("eth_estimateGas", params)
    except ValueError as e:
        if check_value_error_for_parity(e, ParityCallType.ESTIMATE_GAS):
            result = None
        else:
            # else the error is not denoting estimate gas failure and is something else
            raise e
    except ReadTimeout:
        result = None

    return result


def patched_web3_eth_call(self, transaction, block_identifier=None):
    if "from" not in transaction and is_checksum_address(self.defaultAccount):
        transaction = assoc(transaction, "from", self.defaultAccount)

    if block_identifier is None:
        block_identifier = self.defaultBlock

    try:
        result = self.web3.manager.request_blocking("eth_call", [transaction, block_identifier])
    except ValueError as e:
        if check_value_error_for_parity(e, ParityCallType.CALL):
            result = ""
        else:
            # else the error is not denoting a revert, something is wrong
            raise e

    return HexBytes(result)


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

    try:
        gas_estimate = web3.eth.estimateGas(estimate_transaction, block_identifier)
    except ValueError as e:
        if check_value_error_for_parity(e, ParityCallType.ESTIMATE_GAS):
            gas_estimate = None
        else:
            # else the error is not denoting estimate gas failure and is something else
            raise e

    return gas_estimate


def patched_contractfunction_estimateGas(self, transaction=None, block_identifier=None):
    """Temporary workaround until next web3.py release (5.X.X)"""
    if transaction is None:
        estimate_gas_transaction: Dict[str, Any] = {}
    else:
        estimate_gas_transaction = dict(**transaction)

    if "data" in estimate_gas_transaction:
        raise ValueError("Cannot set data in estimateGas transaction")
    if "to" in estimate_gas_transaction:
        raise ValueError("Cannot set to in estimateGas transaction")

    if self.address:
        estimate_gas_transaction.setdefault("to", self.address)
    if self.web3.eth.defaultAccount is not empty:
        estimate_gas_transaction.setdefault("from", self.web3.eth.defaultAccount)

    if "to" not in estimate_gas_transaction:
        if isinstance(self, type):
            raise ValueError(
                "When using `Contract.estimateGas` from a contract factory "
                "you must provide a `to` address with the transaction"
            )
        else:
            raise ValueError("Please ensure that this contract instance has an address.")

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

    # Temporary until next web3.py release (5.X.X)
    ContractFunction.estimateGas = patched_contractfunction_estimateGas
    Eth.estimateGas = patched_web3_eth_estimate_gas

    # Patch call() to achieve same behaviour between parity and geth
    # At the moment geth returns '' for reverted/thrown transactions.
    # Parity raises a value error. Raiden assumes the return of an empty
    # string so we have to make parity behave like geth
    Eth.call = patched_web3_eth_call


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
        privkey: Optional[PrivateKey],
        gas_price_strategy: Callable = rpc_gas_price_strategy,
        gas_estimate_correction: Callable = lambda gas: gas,
        block_num_confirmations: int = 0,
        uses_infura=False,
    ):
        if privkey is None or len(privkey) != 32:
            raise ValueError("Invalid private key")

        if block_num_confirmations < 0:
            raise ValueError("Number of confirmations has to be positive")

        monkey_patch_web3(web3, gas_price_strategy)

        version = web3.version.node
        supported, eth_node, _ = is_supported_client(version)

        if not supported:
            raise EthNodeInterfaceError(f"Unsupported Ethereum client {version}")

        address = privatekey_to_address(privkey)
        address_checksumed = to_checksum_address(address)

        if uses_infura:
            warnings.warn(
                "Infura does not provide an API to "
                "recover the latest used nonce. This may cause the Raiden node "
                "to error on restarts.\n"
                "The error will manifest while there is a pending transaction "
                "from a previous execution in the Ethereum's client pool. When "
                "Raiden restarts the same transaction with the same nonce will "
                "be retried and *rejected*, because the nonce is already used."
            )
            # The first valid nonce is 0, therefore the count is already the next
            # available nonce
            available_nonce = web3.eth.getTransactionCount(address_checksumed, "pending")

        elif eth_node is constants.EthClient.PARITY:
            parity_assert_rpc_interfaces(web3)
            available_nonce = parity_discover_next_available_nonce(web3, address_checksumed)

        elif eth_node is constants.EthClient.GETH:
            geth_assert_rpc_interfaces(web3)
            available_nonce = geth_discover_next_available_nonce(web3, address_checksumed)

        self.eth_node = eth_node
        self.privkey = privkey
        self.address = address
        self.web3 = web3
        self.default_block_num_confirmations = block_num_confirmations

        # Ask for the chain id only once and store it here
        self.chain_id = ChainID(int(self.web3.version.network))

        self._available_nonce = available_nonce
        self._nonce_lock = Semaphore()
        self._gas_estimate_correction = gas_estimate_correction

        log.debug(
            "JSONRPCClient created",
            node=to_checksum_address(self.address),
            available_nonce=available_nonce,
            client=version,
        )

    def __repr__(self):
        return (
            f"<JSONRPCClient "
            f"node:{to_checksum_address(self.address)} nonce:{self._available_nonce}"
            f">"
        )

    def block_number(self):
        """ Return the most recent block. """
        return self.web3.eth.blockNumber

    def get_block(self, block_identifier: BlockSpecification) -> Dict:
        """Given a block number, query the chain to get its corresponding block hash"""
        return self.web3.eth.getBlock(block_identifier)

    def get_confirmed_blockhash(self):
        """ Gets the block CONFIRMATION_BLOCKS in the past and returns its block hash """
        confirmed_block_number = self.web3.eth.blockNumber - self.default_block_num_confirmations
        if confirmed_block_number < 0:
            confirmed_block_number = 0

        return self.blockhash_from_blocknumber(confirmed_block_number)

    def blockhash_from_blocknumber(self, block_number: BlockSpecification) -> BlockHash:
        """Given a block number, query the chain to get its corresponding block hash"""
        block = self.get_block(block_number)
        return BlockHash(bytes(block["hash"]))

    def can_query_state_for_block(self, block_identifier: BlockSpecification) -> bool:
        """
        Returns if the provided block identifier is safe enough to query chain
        state for. If it's close to the state pruning blocks then state should
        not be queried.
        More info: https://github.com/raiden-network/raiden/issues/3566.
        """
        latest_block_number = self.block_number()
        preconditions_block = self.web3.eth.getBlock(block_identifier)
        preconditions_block_number = int(preconditions_block["number"])
        difference = latest_block_number - preconditions_block_number
        return difference < constants.NO_STATE_QUERY_AFTER_BLOCKS

    def balance(self, account: Address):
        """ Return the balance of the account of the given address. """
        return self.web3.eth.getBalance(to_checksum_address(account), "pending")

    def parity_get_pending_transaction_hash_by_nonce(
        self, address: AddressHex, nonce: Nonce
    ) -> Optional[TransactionHash]:
        """Queries the local parity transaction pool and searches for a transaction.

        Checks the local tx pool for a transaction from a particular address and for
        a given nonce. If it exists it returns the transaction hash.
        """
        assert self.eth_node is constants.EthClient.PARITY
        # https://wiki.parity.io/JSONRPC-parity-module.html?q=traceTransaction#parity_alltransactions
        transactions = self.web3.manager.request_blocking("parity_allTransactions", [])
        log.debug("RETURNED TRANSACTIONS", transactions=transactions)
        for tx in transactions:
            address_match = to_checksum_address(tx["from"]) == address
            if address_match and int(tx["nonce"], 16) == nonce:
                return tx["hash"]
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
        except IndexError:  # work around for a web3.py exception when
            # the blockchain is somewhat empty.
            # https://github.com/ethereum/web3.py/issues/1149
            price = int(self.web3.eth.gasPrice)

        return price

    def new_contract_proxy(
        self, abi: List[Dict[str, Any]], contract_address: Address
    ) -> ContractProxy:
        """ Return a proxy for interacting with a smart contract.

        Args:
            abi: The contract interface as defined by the json.
            contract_address: The contract's address.
        """
        return ContractProxy(self, contract=self.new_contract(abi, contract_address))

    def new_contract(self, contract_interface: ABI, contract_address: Address):
        return self.web3.eth.contract(
            abi=contract_interface, address=to_checksum_address(contract_address)
        )

    def get_transaction_receipt(self, tx_hash: bytes):
        return self.web3.eth.getTransactionReceipt(encode_hex(tx_hash))

    def deploy_single_contract(
        self,
        contract_name: str,
        contract: CompiledContract,
        constructor_parameters: Sequence = None,
    ) -> Tuple[ContractProxy, Dict]:
        """
        Deploy a single solidity contract without dependencies.

        Args:
            contract_name: The name of the contract to compile.
            contract: The dictionary containing the contract information (like ABI and BIN)
            constructor_parameters: A tuple of arguments to pass to the constructor.
        """

        ctor_parameters = constructor_parameters or ()

        contract_object = self.web3.eth.contract(abi=contract["abi"], bytecode=contract["bin"])
        contract_transaction = contract_object.constructor(*ctor_parameters).buildTransaction()
        transaction_hash = self.send_transaction(
            to=Address(b""),
            data=contract_transaction["data"],
            startgas=self._gas_estimate_correction(contract_transaction["gas"]),
        )

        receipt = self.poll(transaction_hash)
        contract_address = receipt["contractAddress"]

        deployed_code = self.web3.eth.getCode(to_checksum_address(contract_address))

        if not deployed_code:
            raise RuntimeError(
                "Deployment of {} failed. Contract address has no code, check gas usage.".format(
                    contract_name
                )
            )

        return (
            self.new_contract_proxy(abi=contract["abi"], contract_address=contract_address),
            receipt,
        )

    def send_transaction(
        self, to: Address, startgas: int, value: int = 0, data: bytes = b""
    ) -> TransactionHash:
        """ Helper to send signed messages.

        This method will use the `privkey` provided in the constructor to
        locally sign the transaction. This requires an extended server
        implementation that accepts the variables v, r, and s.
        """
        if to == to_canonical_address(constants.NULL_ADDRESS):
            warnings.warn("For contract creation the empty string must be used.")

        with self._nonce_lock:
            nonce = self._available_nonce
            gas_price = self.gas_price()

            transaction = {
                "data": data,
                "gas": startgas,
                "nonce": nonce,
                "value": value,
                "gasPrice": gas_price,
            }
            node_gas_price = self.web3.eth.gasPrice
            log.debug(
                "Calculated gas price for transaction",
                node=to_checksum_address(self.address),
                calculated_gas_price=gas_price,
                node_gas_price=node_gas_price,
            )

            # add the to address if not deploying a contract
            if to != b"":
                transaction["to"] = to_checksum_address(to)

            signed_txn = self.web3.eth.account.signTransaction(transaction, self.privkey)

            log_details = {
                "node": to_checksum_address(self.address),
                "nonce": transaction["nonce"],
                "gasLimit": transaction["gas"],
                "gasPrice": transaction["gasPrice"],
            }
            log.debug("send_raw_transaction called", **log_details)

            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            self._available_nonce += 1

            log.debug("send_raw_transaction returned", tx_hash=encode_hex(tx_hash), **log_details)
            return TransactionHash(tx_hash)

    def poll(self, transaction_hash: TransactionHash) -> Dict[str, Any]:
        """ Wait until the `transaction_hash` is mined, confirmed, handling
        reorgs.

        Consider the following reorg, were a transaction is mined at block B,
        but it is not mined in the canonical chain A-C-D:

             A -> B   D
             *--> C --^

        When the Ethereum node looks at block B, from its perspective the
        transaction is mined and it has a receipt. After the reorg it does not
        have a receipt. This can happen on PoW and PoA based chains.

        Args:
            transaction_hash: Transaction hash that we are waiting for.
        """
        if len(transaction_hash) != 32:
            raise ValueError("transaction_hash must be a 32 byte hash")

        transaction_hash_hex = encode_hex(transaction_hash)

        while True:
            tx_receipt = self.web3.eth.getTransactionReceipt(transaction_hash_hex)

            # Parity (as of 2.5.7) always returns a receipt. When the
            # transaction is not mined in the canonical chain, the receipt will
            # not have meaningful values. Example of receipt for a transaction
            # that is not mined:
            #
            #   blockHash: None
            #   blockNumber: None
            #   contractAddress: None
            #   cumulativeGasUsed: The transaction's gas
            #   from: None
            #   gasUsed: The transaction's gas
            #   logs: []
            #   logsBloom: Zero is hex
            #   root: None
            #   status: 1
            #   to: None
            #   transactionHash: The transaction's hash
            #   transactionIndex: 0
            #
            # Geth only returns a receipt if the transaction was mined on the
            # canonical chain. https://github.com/raiden-network/raiden/issues/4529
            is_transaction_mined = tx_receipt and tx_receipt.get("blockNumber") is not None

            if is_transaction_mined:
                confirmation_block = (
                    tx_receipt["blockNumber"] + self.default_block_num_confirmations
                )
                block_number = self.block_number()

                is_transaction_confirmed = block_number >= confirmation_block
                if is_transaction_confirmed:
                    return tx_receipt

            gevent.sleep(1.0)

    def new_filter(
        self,
        contract_address: Address,
        topics: Optional[List[Optional[str]]],
        from_block: BlockSpecification,
        to_block: BlockSpecification,
    ) -> StatelessFilter:
        """ Create a filter in the ethereum node. """
        logs_blocks_sanity_check(from_block, to_block)
        return StatelessFilter(
            self.web3,
            {
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": to_checksum_address(contract_address),
                "topics": topics,
            },
        )

    def get_filter_events(
        self,
        contract_address: Address,
        topics: List[str] = None,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = "latest",
    ) -> List[Dict]:
        """ Get events for the given query. """
        logs_blocks_sanity_check(from_block, to_block)
        return self.web3.eth.getLogs(
            {
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": to_checksum_address(contract_address),
                "topics": topics,
            }
        )

    def check_for_insufficient_eth(
        self,
        transaction_name: str,
        transaction_executed: bool,
        required_gas: int,
        block_identifier: BlockSpecification,
    ):
        """ After estimate gas failure checks if our address has enough balance.

        If the account did not have enough ETH balance to execute the,
        transaction then it raises an `InsufficientFunds` error.

        Note:
            This check contains a race condition, it could be the case that a
            new block is mined changing the account's balance.
            https://github.com/raiden-network/raiden/issues/3890#issuecomment-485857726
        """
        if transaction_executed:
            return

        our_address = to_checksum_address(self.address)
        balance = self.web3.eth.getBalance(our_address, block_identifier)
        required_balance = required_gas * self.gas_price()
        if balance < required_balance:
            msg = f"Failed to execute {transaction_name} due to insufficient ETH"
            log.critical(msg, required_wei=required_balance, actual_wei=balance)
            raise InsufficientFunds(msg)

    def get_checking_block(self):
        """Workaround for parity https://github.com/paritytech/parity-ethereum/issues/9707
        In parity doing any call() with the 'pending' block no longer falls back
        to the latest if no pending block is found but throws a mistaken error.
        Until that bug is fixed we need to enforce special behaviour for parity
        and use the latest block for checking.
        """
        checking_block = "pending"
        if self.eth_node is constants.EthClient.PARITY:
            checking_block = "latest"
        return checking_block

    def is_synced(self) -> bool:
        result = self.web3.eth.syncing

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = result["highestBlock"]

        if highest_block - current_block > 2:
            return False

        return True
