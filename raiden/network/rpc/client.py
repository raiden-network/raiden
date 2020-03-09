import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from uuid import uuid4

import gevent
import structlog
from eth_utils import decode_hex, encode_hex, is_bytes, is_checksum_address, to_canonical_address
from eth_utils.toolz import assoc
from gevent.lock import Semaphore
from hexbytes import HexBytes
from requests.exceptions import ReadTimeout
from web3 import Web3
from web3._utils.contracts import (
    encode_transaction_data,
    find_matching_fn_abi,
    prepare_transaction,
)
from web3._utils.empty import empty
from web3.contract import Contract, ContractFunction
from web3.eth import Eth
from web3.exceptions import TransactionNotFound
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.middleware import geth_poa_middleware
from web3.types import TxReceipt

from raiden.constants import (
    NO_STATE_QUERY_AFTER_BLOCKS,
    NULL_ADDRESS_CHECKSUM,
    TRANSACTION_INTRINSIC_GAS,
    EthClient,
)
from raiden.exceptions import (
    AddressWithoutCode,
    ContractCodeMismatch,
    EthereumNonceTooLow,
    EthNodeInterfaceError,
    InsufficientEth,
    RaidenUnrecoverableError,
    ReplacementTransactionUnderpriced,
)
from raiden.network.rpc.middleware import block_hash_cache_middleware
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.formatting import to_checksum_address
from raiden.utils.keys import privatekey_to_address
from raiden.utils.smart_contracts import safe_gas_limit
from raiden.utils.typing import (
    ABI,
    Address,
    AddressHex,
    BlockHash,
    BlockNumber,
    BlockSpecification,
    CompiledContract,
    Nonce,
    PrivateKey,
    T_Address,
    T_Nonce,
    TokenAmount,
    TransactionHash,
    typecheck,
)
from raiden_contracts.utils.type_aliases import ChainID

log = structlog.get_logger(__name__)


def logs_blocks_sanity_check(from_block: BlockSpecification, to_block: BlockSpecification) -> None:
    """Checks that the from/to blocks passed onto log calls contain only appropriate types"""
    is_valid_from = isinstance(from_block, int) or isinstance(from_block, str)
    assert is_valid_from, "event log from block can be integer or latest,pending, earliest"
    is_valid_to = isinstance(to_block, int) or isinstance(to_block, str)
    assert is_valid_to, "event log to block can be integer or latest,pending, earliest"


def geth_assert_rpc_interfaces(web3: Web3) -> None:
    try:
        web3.clientVersion
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


def parity_assert_rpc_interfaces(web3: Web3) -> None:
    try:
        web3.clientVersion
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
        web3.manager.request_blocking("parity_nextNonce", [NULL_ADDRESS_CHECKSUM])
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying parity node does not have the parity rpc interface "
            "enabled. Please run it with --jsonrpc-apis=eth,net,web3,parity"
        )


def parity_discover_next_available_nonce(web3: Web3, address: Address) -> Nonce:
    """Returns the next available nonce for `address`."""
    next_nonce_encoded = web3.manager.request_blocking(
        "parity_nextNonce", [to_checksum_address(address)]
    )
    return Nonce(int(next_nonce_encoded, 16))


def geth_discover_next_available_nonce(web3: Web3, address: Address) -> Nonce:
    """Returns the next available nonce for `address`."""
    return web3.eth.getTransactionCount(address, "pending")


def check_address_has_code(
    client: "JSONRPCClient",
    address: Address,
    contract_name: str,
    given_block_identifier: BlockSpecification,
    expected_code: bytes = None,
) -> None:
    """ Checks that the given address contains code. """
    if is_bytes(given_block_identifier):
        assert isinstance(given_block_identifier, bytes)
        block_hash = encode_hex(given_block_identifier)
        given_block_identifier = client.web3.eth.getBlock(block_hash).number

    result = client.web3.eth.getCode(address, given_block_identifier)

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


def get_transaction_data(
    web3: Web3, abi: Dict, function_name: str, args: Any = None, kwargs: Any = None
) -> str:
    """Get encoded transaction data"""
    args = args or list()
    fn_abi = find_matching_fn_abi(
        abi=abi, abi_codec=web3.codec, fn_identifier=function_name, args=args, kwargs=kwargs
    )
    return encode_transaction_data(
        web3=web3,
        fn_identifier=function_name,
        contract_abi=abi,
        fn_abi=fn_abi,
        args=args,
        kwargs=kwargs,
    )


def gas_price_for_fast_transaction(web3: Web3) -> int:
    try:
        # generateGasPrice takes the transaction to be send as an optional argument
        # but both strategies that we are using (time-based and rpc-based) don't make
        # use of this argument. It is therefore safe to not provide it at the moment.
        # This needs to be reevaluated if we use different gas price strategies
        price = int(web3.eth.generateGasPrice())
    except AttributeError:  # workaround for Infura gas strategy key error
        # As per https://github.com/raiden-network/raiden/issues/3201
        # we can sporadically get an AtttributeError here. If that happens
        # use latest gas price
        price = int(web3.eth.gasPrice)
    except IndexError:  # work around for a web3.py exception when
        # the blockchain is somewhat empty.
        # https://github.com/ethereum/web3.py/issues/1149
        price = int(web3.eth.gasPrice)

    return price


class TransactionSlotState(Enum):
    allocated = "allocated"
    sent = "sent"
    rejected = "rejected"


class ClientErrorInspectResult(Enum):
    """Represents the action to follow after inspecting a client exception"""

    PROPAGATE_ERROR = 1
    INSUFFICIENT_FUNDS = 2
    TRANSACTION_UNDERPRICED = 3
    TRANSACTION_PENDING = 4
    ALWAYS_FAIL = 5
    TRANSACTION_ALREADY_IMPORTED = 7
    TRANSACTION_PENDING_OR_ALREADY_IMPORTED = 8


# Geth has one error message for resending a transaction from the transaction
# pool, and another for reusing a nonce of a mined transaction. Parity on the
# other hand has just a single error message, so these errors have to be
# grouped. (Tested with Geth 1.9.6 and Parity 2.5.9).
THE_NONCE_WAS_REUSED = (
    ClientErrorInspectResult.TRANSACTION_PENDING,
    ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED,
    ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED,
)


def inspect_client_error(
    val_err: ValueError, eth_node: Optional[EthClient]
) -> ClientErrorInspectResult:
    # both clients return invalid json. They use single quotes while json needs double ones.
    # Also parity may return something like: 'data': 'Internal("Error message")' which needs
    # special processing
    json_response = str(val_err).replace("'", '"').replace('("', "(").replace('")', ")")
    try:
        error = json.loads(json_response)
    except json.JSONDecodeError:
        return ClientErrorInspectResult.PROPAGATE_ERROR

    if eth_node is EthClient.GETH:
        if error["code"] == -32000:
            if "insufficient funds" in error["message"]:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS

            if "always failing transaction" in error["message"]:
                return ClientErrorInspectResult.ALWAYS_FAIL

            if "replacement transaction underpriced" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED

            if "known transaction:" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING

            # Seems to be a new message in geth 1.9.11
            if "already know" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING

            if "nonce too low" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED

    elif eth_node is EthClient.PARITY:
        if error["code"] == -32010:
            if "Insufficient funds" in error["message"]:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS

            if "another transaction with same nonce in the queue" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED

            # This error code is known to be used for pending transactions, it
            # may also be used for reusing the nonce of mined transactions.
            if "Transaction nonce is too low. Try incrementing the nonce." in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED

            # This error code is used for both resending pending transactions
            # and reusing nonce of mined transactions.
            if "Transaction with the same hash was already imported" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED

        elif error["code"] == -32015 and "Transaction execution error" in error["message"]:
            return ClientErrorInspectResult.ALWAYS_FAIL

    return ClientErrorInspectResult.PROPAGATE_ERROR


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


def patched_web3_eth_estimate_gas(
    self: Any, transaction: Dict[str, Any], block_identifier: BlockSpecification = None
) -> int:
    """ Temporary workaround until next web3.py release (5.X.X)

    Current master of web3.py has this implementation already:
    https://github.com/ethereum/web3.py/blob/2a67ea9f0ab40bb80af2b803dce742d6cad5943e/web3/eth.py#L311
    """
    if "from" not in transaction and is_checksum_address(self.defaultAccount):
        transaction = assoc(transaction, "from", self.defaultAccount)

    if block_identifier is None:
        params: List[Any] = [transaction]
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


def patched_web3_eth_call(
    self: Any, transaction: Dict[str, Any], block_identifier: BlockSpecification = None
) -> HexBytes:
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
    address: Address,
    web3: Web3,
    fn_identifier: str = None,
    transaction: Dict[str, Any] = None,
    contract_abi: Dict[str, Any] = None,
    fn_abi: Dict[str, Any] = None,
    block_identifier: BlockSpecification = None,
    *args: Any,
    **kwargs: Any,
) -> int:
    """Temporary workaround until next web3.py release (5.X.X)"""
    estimate_transaction = prepare_transaction(
        address=address,
        web3=web3,
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


def patched_contractfunction_estimateGas(
    self: Any, transaction: Dict[str, Any] = None, block_identifier: BlockSpecification = None
) -> int:
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


def monkey_patch_web3(web3: Web3, gas_price_strategy: Callable) -> None:
    try:
        # install caching middleware
        web3.middleware_onion.add(block_hash_cache_middleware)

        # set gas price strategy
        web3.eth.setGasPriceStrategy(gas_price_strategy)

        # we use a PoA chain for smoketest, use this middleware to fix this
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    except ValueError:
        # `middleware_onion.inject()` raises a value error if the same middleware is
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


@dataclass
class EthTransfer:
    to_address: Address
    value: int
    gas_price: int

    def __post_init__(self) -> None:
        typecheck(self.to_address, T_Address)
        typecheck(self.gas_price, int)
        typecheck(self.value, int)

    def to_log_details(self) -> Dict[str, Any]:
        return {"to_address": to_checksum_address(self.to_address), "value": self.value}


@dataclass
class SmartContractCall:
    contract: Contract
    function: str
    args: Iterable[Any]
    kwargs: Dict[str, Any]
    value: int

    def __post_init__(self) -> None:
        typecheck(self.contract, Contract)
        typecheck(self.function, str)
        typecheck(self.value, int)

    def to_log_details(self) -> Dict[str, Any]:
        return {
            "function_name": self.function,
            "to_address": to_checksum_address(self.contract.address),
            "args": self.args,
            "kwargs": self.kwargs,
            "value": self.value,
        }


@dataclass
class ByteCode:
    contract_name: str
    bytecode: bytes

    def to_log_details(self) -> Dict[str, Any]:
        return {"contract_name": self.contract_name}


@dataclass
class TransactionPending:
    from_address: Address
    data: SmartContractCall
    eth_node: Optional[EthClient]
    extra_log_details: Dict[str, Any]

    def __post_init__(self) -> None:
        log.debug("Transaction created", **self.to_log_details())
        self.extra_log_details.setdefault("token", str(uuid4()))

        typecheck(self.from_address, T_Address)
        typecheck(self.data, SmartContractCall)

    def to_log_details(self) -> Dict[str, Any]:
        log_details = self.data.to_log_details()
        log_details.update(self.extra_log_details)
        log_details.update(
            {"from_address": to_checksum_address(self.from_address), "eth_node": self.eth_node}
        )
        return log_details

    def estimate_gas(
        self, block_identifier: Optional[BlockSpecification]
    ) -> Optional["TransactionEstimated"]:
        """Estimate the gas and price necessary to run the transaction.

        Returns `None` transaction would fail because it hit an assert/require,
        or if the amount of gas required is larger than the block gas limit.
        """

        fn = getattr(self.data.contract.functions, self.data.function)
        from_address = to_checksum_address(self.from_address)

        if self.eth_node is EthClient.GETH:
            # Unfortunately geth does not follow the ethereum JSON-RPC spec and
            # does not accept a block identifier argument for eth_estimateGas
            # parity and py-evm (trinity) do.
            #
            # Geth only runs estimateGas on the pending block and that's why we
            # should also enforce parity, py-evm and others to do the same since
            # we can't customize geth.
            #
            # Spec: https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_estimategas
            # Geth Issue: https://github.com/ethereum/go-ethereum/issues/2586
            # Relevant web3 PR: https://github.com/ethereum/web3.py/pull/1046
            block_identifier = None

        try:
            estimated_gas = fn(*self.data.args, **self.data.kwargs).estimateGas(
                transaction={"from": from_address}, block_identifier=block_identifier
            )
        except ValueError as err:
            estimated_gas = None
            inspected_error = inspect_client_error(err, self.eth_node)

            # These errors are expected to happen. For these errors instead of
            # propagating the `ValueError` raised by web3 `None` is returned,
            # this forces the caller to handle the error.
            expected_error = inspected_error in (
                ClientErrorInspectResult.INSUFFICIENT_FUNDS,
                ClientErrorInspectResult.ALWAYS_FAIL,
            )
            if not expected_error:
                raise err

        if estimated_gas is not None:
            block = self.data.contract.web3.eth.getBlock("latest")
            gas_price = gas_price_for_fast_transaction(self.data.contract.web3)

            transaction_estimated = TransactionEstimated(
                from_address=self.from_address,
                eth_node=self.eth_node,
                data=self.data,
                extra_log_details=self.extra_log_details,
                estimated_gas=safe_gas_limit(estimated_gas),
                gas_price=gas_price,
                approximate_block=(block["hash"], block["number"]),
            )

            log.debug(
                "Transaction gas estimated",
                **transaction_estimated.to_log_details(),
                node_gas_price=self.data.contract.web3.eth.gasPrice,
            )

            return transaction_estimated
        else:
            log.debug("Transaction gas estimation failed", **self.to_log_details())

            return None


@dataclass
class TransactionEstimated:
    from_address: Address
    data: Union[SmartContractCall, ByteCode]
    eth_node: Optional[EthClient]
    extra_log_details: Dict[str, Any]
    estimated_gas: int
    gas_price: int
    approximate_block: Tuple[BlockHash, BlockNumber]

    def __post_init__(self) -> None:
        self.extra_log_details.setdefault("token", str(uuid4()))

        typecheck(self.from_address, T_Address)
        typecheck(self.data, (SmartContractCall, ByteCode))
        typecheck(self.estimated_gas, int)
        typecheck(self.gas_price, int)

    def to_log_details(self) -> Dict[str, Any]:
        log_details = self.data.to_log_details()
        log_details.update(self.extra_log_details)
        log_details.update(
            {
                "from_address": to_checksum_address(self.from_address),
                "eth_node": self.eth_node,
                "estimated_gas": self.estimated_gas,
                "gas_price": self.gas_price,
            }
        )
        return log_details


# Type used to expose the attributes for type checking, the actual
# implementation is hidden and can only be instantiated through the
# JSONRPCClient, which ensures the nonces are used sequentially.
class TransactionSlot(ABC):
    from_address: Address
    data: Union[SmartContractCall, ByteCode, EthTransfer]
    eth_node: Optional[EthClient]
    startgas: int
    gas_price: int
    nonce: Nonce

    @abstractmethod
    def send_transaction(self) -> TransactionHash:
        pass


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
    ) -> None:
        if privkey is None or len(privkey) != 32:
            raise ValueError("Invalid private key")

        if block_num_confirmations < 0:
            raise ValueError("Number of confirmations has to be positive")

        monkey_patch_web3(web3, gas_price_strategy)

        version = web3.clientVersion
        supported, eth_node, _ = is_supported_client(version)

        if not supported:
            raise EthNodeInterfaceError(f"Unsupported Ethereum client {version}")

        address = privatekey_to_address(privkey)

        if eth_node is EthClient.PARITY:
            parity_assert_rpc_interfaces(web3)
            available_nonce = parity_discover_next_available_nonce(web3, address)

        elif eth_node is EthClient.GETH:
            geth_assert_rpc_interfaces(web3)
            available_nonce = geth_discover_next_available_nonce(web3, address)

        self.eth_node = eth_node
        self.privkey = privkey
        self.address = address
        self.web3 = web3
        self.default_block_num_confirmations = block_num_confirmations

        # Ask for the chain id only once and store it here
        self.chain_id = ChainID(self.web3.eth.chainId)

        self._available_nonce = available_nonce
        self._nonce_lock = Semaphore()
        self._gas_estimate_correction = gas_estimate_correction

        log.debug(
            "JSONRPCClient created",
            node=to_checksum_address(self.address),
            available_nonce=available_nonce,
            client=version,
        )

    def __repr__(self) -> str:
        return (
            f"<JSONRPCClient "
            f"node:{to_checksum_address(self.address)} nonce:{self._available_nonce}"
            f">"
        )

    def block_number(self) -> BlockNumber:
        """ Return the most recent block. """
        return self.web3.eth.blockNumber

    def get_block(self, block_identifier: BlockSpecification) -> Dict[str, Any]:
        """Given a block number, query the chain to get its corresponding block hash"""
        return self.web3.eth.getBlock(block_identifier)

    def get_confirmed_blockhash(self) -> BlockHash:
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
        return difference < NO_STATE_QUERY_AFTER_BLOCKS

    def balance(self, account: Address) -> TokenAmount:
        """ Return the balance of the account of the given address. """
        return self.web3.eth.getBalance(account, "pending")

    def parity_get_pending_transaction_hash_by_nonce(
        self, address: AddressHex, nonce: Nonce
    ) -> Optional[TransactionHash]:
        """Queries the local parity transaction pool and searches for a transaction.

        Checks the local tx pool for a transaction from a particular address and for
        a given nonce. If it exists it returns the transaction hash.
        """
        assert self.eth_node is EthClient.PARITY
        # https://wiki.parity.io/JSONRPC-parity-module.html?q=traceTransaction#parity_alltransactions
        transactions = self.web3.manager.request_blocking("parity_allTransactions", [])
        log.debug("RETURNED TRANSACTIONS", transactions=transactions)
        for tx in transactions:
            address_match = tx["from"] == address
            if address_match and int(tx["nonce"], 16) == nonce:
                return tx["hash"]
        return None

    def estimate_gas(
        self,
        contract: Contract,
        function: str,
        extra_log_details: Dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> Optional[TransactionEstimated]:
        pending = TransactionPending(
            from_address=self.address,
            data=SmartContractCall(contract, function, args, kwargs, value=0),
            eth_node=self.eth_node,
            extra_log_details=extra_log_details,
        )
        return pending.estimate_gas(self.get_checking_block())

    def transact(self, transaction: Union[TransactionEstimated, EthTransfer]) -> TransactionHash:
        # Exposing the JSONRPCClient with a nice name for the instance closure.
        client = self

        # The class is hidden in the method to force this method to be called,
        # this is necesary to enforce the monotonicity of the `nonce`.
        @dataclass
        class TransactionSlotImplementation(TransactionSlot):
            """A poor's man linear type that will check at the runtime that a nonce is
            used only once.

            This is necessary to avoid problems with nonce synchronization. If a nonce
            is not used then all subsequent transactions won't be mined, or if a nonce
            is used more than once, only one transaction will succeed while all others
            will fail, which is currently not supported by the Raiden node.
            """

            from_address: Address
            data: Union[SmartContractCall, ByteCode, EthTransfer]
            eth_node: Optional[EthClient]
            extra_log_details: Dict[str, Any]
            startgas: int
            gas_price: int
            nonce: Nonce

            # Lock to protect the `_sent` attribute. This is necessary otherwise the
            # check for a duplicate transaction with the same nonce won't work due to
            # race conditions.
            _sent_lock: Semaphore = field(init=False, default_factory=Semaphore)
            _sent: TransactionSlotState = field(init=False, default=TransactionSlotState.allocated)

            def __post_init__(self) -> None:
                self.extra_log_details.setdefault("token", str(uuid4()))

                typecheck(self.from_address, T_Address)
                typecheck(self.data, (SmartContractCall, ByteCode, EthTransfer))
                typecheck(self.startgas, int)
                typecheck(self.gas_price, int)
                typecheck(self.nonce, T_Nonce)

            def to_log_details(self) -> Dict[str, Any]:
                log_details = self.data.to_log_details()
                log_details.update(self.extra_log_details)
                log_details.update(
                    {
                        "node": to_checksum_address(client.address),
                        "from_address": to_checksum_address(self.from_address),
                        "eth_node": self.eth_node,
                        "startgas": self.startgas,
                        "gas_price": self.gas_price,
                        "nonce": self.nonce,
                    }
                )
                return log_details

            def send_transaction(self) -> TransactionHash:
                """ Locally sign the transaction and send it to the network. """

                with self._sent_lock:
                    if self._sent is not TransactionSlotState.allocated:
                        raise RaidenUnrecoverableError(
                            f"A transaction for this slot has been already sent "
                            f"or tried! Reusing the nonce is a synchronization "
                            f"problem."
                        )

                    log_details = self.to_log_details()

                    if isinstance(self.data, SmartContractCall):
                        function_call = self.data
                        data = get_transaction_data(
                            web3=function_call.contract.web3,
                            abi=function_call.contract.abi,
                            function_name=function_call.function,
                            args=function_call.args,
                            kwargs=function_call.kwargs,
                        )
                        transaction = {
                            "data": decode_hex(data),
                            "gas": self.startgas,
                            "nonce": self.nonce,
                            "value": self.data.value,
                            "to": to_checksum_address(function_call.contract.address),
                            "gasPrice": self.gas_price,
                        }

                        error_msg = "Transaction to call smart contract function failed"
                        log.debug(
                            "Transaction to call smart contract function will be sent",
                            **log_details,
                        )
                    elif isinstance(self.data, EthTransfer):
                        transaction = {
                            "to": to_checksum_address(self.data.to_address),
                            "gas": self.startgas,
                            "nonce": self.nonce,
                            "value": self.data.value,
                            "gasPrice": self.gas_price,
                        }

                        error_msg = "Transaction to transfer ether failed"
                        log.debug("Transaction to transfer ether", **log_details)
                    else:
                        transaction = {
                            "data": self.data.bytecode,
                            "gas": self.startgas,
                            "nonce": self.nonce,
                            "value": 0,
                            "gasPrice": self.gas_price,
                        }

                        error_msg = "Transaction to deploy smart contract failed"
                        log.debug(
                            "Transaction to deploy smart contract will be sent", **log_details
                        )

                    signed_txn = client.web3.eth.account.sign_transaction(
                        transaction, client.privkey
                    )

                    try:
                        tx_hash = client.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
                        self._sent = TransactionSlotState.sent
                    except ValueError as e:
                        self._sent = TransactionSlotState.rejected

                        action = inspect_client_error(e, self.eth_node)

                        if action == ClientErrorInspectResult.INSUFFICIENT_FUNDS:
                            reason = (
                                "Transaction failed due to insufficient ETH balance. "
                                "Please top up your ETH account."
                            )
                            log.critical(error_msg, **log_details, reason=reason)
                            raise InsufficientEth(reason)

                        if action == ClientErrorInspectResult.TRANSACTION_UNDERPRICED:
                            reason = (
                                "Transaction was rejected. This is potentially "
                                "caused by the reuse of the previous transaction "
                                "nonce as well as paying an amount of gas less than or "
                                "equal to the previous transaction's gas amount"
                            )
                            log.critical(error_msg, **log_details, reason=reason)
                            raise ReplacementTransactionUnderpriced(reason)

                        if action in THE_NONCE_WAS_REUSED:
                            # XXX: Add logic to check that it is the same transaction
                            # (instead of relying on the error message), and instead of
                            # raising an unrecoverable error proceed as normal with the
                            # polling.
                            #
                            # This was previously done, but removed by #4909, and for it to
                            # be finished #2088 has to be implemented.
                            reason = (
                                "Transaction rejected because the nonce has been already mined."
                            )
                            log.critical(error_msg, **log_details, reason=reason)
                            raise EthereumNonceTooLow(reason)

                        reason = f"Unexpected error in underlying Ethereum node: {str(e)}"
                        log.critical(error_msg, **log_details, reason=reason)
                        raise RaidenUnrecoverableError(reason)

                    log.debug("Transaction sent", **log_details, tx_hash=encode_hex(tx_hash))

                    return TransactionHash(tx_hash)

            def __del__(self) -> None:
                if self._sent is TransactionSlotState.sent:
                    return

                if self._sent is TransactionSlotState.rejected:
                    msg = f"Transaction with nonce {self.nonce} was rejected!"
                else:
                    msg = f"Transaction with nonce {self.nonce} was sent!"

                log_details = self.to_log_details()
                log.critical(msg, **log_details)

                raise RaidenUnrecoverableError(
                    f"{msg} This will result in nonce synchronization " f"problems. {log_details}."
                )

        with self._nonce_lock:
            if isinstance(transaction, EthTransfer):
                slot = TransactionSlotImplementation(
                    from_address=self.address,
                    eth_node=self.eth_node,
                    data=transaction,
                    extra_log_details={},
                    startgas=TRANSACTION_INTRINSIC_GAS,
                    gas_price=transaction.gas_price,
                    nonce=self._available_nonce,
                )
            else:
                slot = TransactionSlotImplementation(
                    from_address=transaction.from_address,
                    eth_node=transaction.eth_node,
                    data=transaction.data,
                    extra_log_details=transaction.extra_log_details,
                    startgas=transaction.estimated_gas,
                    gas_price=transaction.gas_price,
                    nonce=self._available_nonce,
                )

            tx_hash = slot.send_transaction()

            # Increase the `nonce` only after sending the transaction. This is
            # necessary because the send itself can fail, e.g. because of an
            # invalid value which leads to a `ValueError` or if the received
            # node rejects the transaction. When this happens, the
            # `_available_nonce` must not be incremented, since that may lead
            # to holes in the account's transactions, effectivelly stalling all
            # transactions until the spare nonce is used.
            self._available_nonce = Nonce(self._available_nonce + 1)

            return tx_hash

    def new_contract_proxy(self, abi: ABI, contract_address: Address) -> Contract:
        return self.web3.eth.contract(abi=abi, address=contract_address)

    def deploy_single_contract(
        self,
        contract_name: str,
        contract: CompiledContract,
        constructor_parameters: Sequence = None,
    ) -> Tuple[Contract, Dict]:
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
        constructor_call = ByteCode(contract_name, contract_transaction["data"])

        block = self.get_block("latest")

        gas_price = gas_price_for_fast_transaction(self.web3)
        transaction = TransactionEstimated(
            from_address=self.address,
            data=constructor_call,
            eth_node=self.eth_node,
            extra_log_details={},
            estimated_gas=self._gas_estimate_correction(contract_transaction["gas"]),
            gas_price=gas_price,
            approximate_block=(block["hash"], block["number"]),
        )

        transaction_hash = self.transact(transaction)
        receipt = self.poll_transaction(transaction_hash)
        contract_address = to_canonical_address(receipt["contractAddress"])

        deployed_code = self.web3.eth.getCode(contract_address)

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

    def poll_transaction(self, transaction_hash: TransactionHash) -> TxReceipt:
        """ Wait until the `transaction_hash` is mined, confirmed, handling
        reorgs.

        Consider the following reorg, where a transaction is mined at block B,
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
            tx_receipt: Optional[TxReceipt] = None
            try:
                tx_receipt = self.web3.eth.getTransactionReceipt(transaction_hash_hex)
            except TransactionNotFound:
                pass

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
                assert tx_receipt is not None
                confirmation_block = (
                    tx_receipt["blockNumber"] + self.default_block_num_confirmations
                )
                block_number = self.block_number()

                is_transaction_confirmed = block_number >= confirmation_block
                if is_transaction_confirmed:
                    return tx_receipt

            gevent.sleep(1.0)

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
                "address": contract_address,
                "topics": topics,
            }
        )

    def check_for_insufficient_eth(
        self,
        transaction_name: str,
        transaction_executed: bool,
        required_gas: int,
        block_identifier: BlockSpecification,
    ) -> None:
        """ After estimate gas failure checks if our address has enough balance.

        If the account did not have enough ETH balance to execute the
        transaction, it raises an `InsufficientEth` error.

        Note:
            This check contains a race condition, it could be the case that a
            new block is mined changing the account's balance.
            https://github.com/raiden-network/raiden/issues/3890#issuecomment-485857726
        """
        if transaction_executed:
            return

        our_address = to_checksum_address(self.address)
        balance = self.web3.eth.getBalance(our_address, block_identifier)
        required_balance = required_gas * gas_price_for_fast_transaction(self.web3)
        if balance < required_balance:
            msg = f"Failed to execute {transaction_name} due to insufficient ETH"
            log.critical(msg, required_wei=required_balance, actual_wei=balance)
            raise InsufficientEth(msg)

    def get_checking_block(self) -> BlockSpecification:
        """Workaround for parity https://github.com/paritytech/parity-ethereum/issues/9707
        In parity doing any call() with the 'pending' block no longer falls back
        to the latest if no pending block is found but throws a mistaken error.
        Until that bug is fixed we need to enforce special behaviour for parity
        and use the latest block for checking.
        """
        checking_block = "pending"
        if self.eth_node is EthClient.PARITY:
            checking_block = "latest"
        return checking_block

    def wait_until_block(
        self, target_block_number: BlockNumber, retry_timeout: float = 0.5
    ) -> BlockNumber:
        current_block = self.block_number()

        while current_block < target_block_number:
            current_block = self.block_number()
            gevent.sleep(retry_timeout)

        return current_block
