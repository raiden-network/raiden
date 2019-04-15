import json
from enum import Enum
from typing import Dict, List

from eth_utils import decode_hex, to_canonical_address, to_checksum_address
from web3.contract import Contract
from web3.utils.contracts import encode_transaction_data, find_matching_fn_abi

from raiden import constants
from raiden.constants import EthClient
from raiden.exceptions import (
    InsufficientFunds,
    ReplacementTransactionUnderpriced,
    TransactionAlreadyPending,
)
from raiden.utils import typing
from raiden.utils.filters import decode_event


class ClientErrorInspectResult(Enum):
    """Represents the action to follow after inspecting a client exception"""
    PROPAGATE_ERROR = 1
    INSUFFICIENT_FUNDS = 2
    TRANSACTION_UNDERPRICED = 3
    TRANSACTION_PENDING = 4
    ALWAYS_FAIL = 5
    TRANSACTION_ALREADY_IMPORTED = 7


def inspect_client_error(val_err: ValueError, eth_node: EthClient) -> ClientErrorInspectResult:
    # both clients return invalid json. They use single quotes while json needs double ones.
    # Also parity may return something like: 'data': 'Internal("Error message")' which needs
    # special processing
    json_response = str(val_err).replace("'", '"').replace('("', '(').replace('")', ')')
    try:
        error = json.loads(json_response)
    except json.JSONDecodeError:
        return ClientErrorInspectResult.PROPAGATE_ERROR

    if eth_node is EthClient.GETH:
        if error['code'] == -32000:
            if 'insufficient funds' in error['message']:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS
            elif 'always failing transaction' in error['message']:
                return ClientErrorInspectResult.ALWAYS_FAIL
            elif error['message'] == 'replacement transaction underpriced':
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED
            elif error['message'].startswith('known transaction:'):
                return ClientErrorInspectResult.TRANSACTION_PENDING

    elif eth_node is EthClient.PARITY:
        if error['code'] == -32010:
            if 'Insufficient funds' in error['message']:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS
            elif 'another transaction with same nonce in the queue' in error['message']:
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED
            elif 'Transaction with the same hash was already imported' in error['message']:
                return ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED
        elif error['code'] == -32015 and 'Transaction execution error' in error['message']:
            return ClientErrorInspectResult.ALWAYS_FAIL

    return ClientErrorInspectResult.PROPAGATE_ERROR


class ContractProxy:
    def __init__(
            self,
            jsonrpc_client,
            contract: Contract,
    ):
        if contract is None:
            raise ValueError('Contract must not be None')
        if jsonrpc_client is None:
            raise ValueError('JSONRPCClient must not be None')
        self.jsonrpc_client = jsonrpc_client
        self.contract = contract

    def transact(
            self,
            function_name: str,
            startgas: int,
            *args,
            **kargs,
    ) -> typing.TransactionHash:
        data = ContractProxy.get_transaction_data(
            self.contract.abi,
            function_name,
            args=args,
            kwargs=kargs,
        )

        try:
            txhash = self.jsonrpc_client.send_transaction(
                to=self.contract.address,
                startgas=startgas,
                value=kargs.pop('value', 0),
                data=decode_hex(data),
            )
        except ValueError as e:
            action = inspect_client_error(e, self.jsonrpc_client.eth_node)
            if action == ClientErrorInspectResult.INSUFFICIENT_FUNDS:
                raise InsufficientFunds('Insufficient ETH for transaction')
            elif action == ClientErrorInspectResult.TRANSACTION_UNDERPRICED:
                raise ReplacementTransactionUnderpriced(
                    'Transaction was rejected. This is potentially '
                    'caused by the reuse of the previous transaction '
                    'nonce as well as paying an amount of gas less than or '
                    'equal to the previous transaction\'s gas amount',
                )
            elif action == ClientErrorInspectResult.TRANSACTION_PENDING:
                raise TransactionAlreadyPending(
                    'The transaction has already been submitted. Please '
                    'wait until is has been mined or increase the gas price.',
                )
            elif action == ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED:
                # This is like TRANSACTION_PENDING is for geth but happens in parity
                # Unlike with geth this can also happen without multiple transactions
                # being sent via RPC -- due to probably some parity bug:
                # https://github.com/raiden-network/raiden/issues/3211
                # We will try to not crash by looking into the local parity
                # transaction pool to retrieve the transaction hash
                hex_address = to_checksum_address(self.jsonrpc_client.address)
                txhash = self.jsonrpc_client.parity_get_pending_transaction_hash_by_nonce(
                    address=hex_address,
                    nonce=self.jsonrpc_client._available_nonce,
                )
                if txhash:
                    raise TransactionAlreadyPending(
                        'Transaction was submitted via parity but parity saw it as'
                        ' already pending. Could not find the transaction in the '
                        'local transaction pool. Bailing ...',
                    )
                return txhash

            raise e

        return txhash

    @staticmethod
    def get_transaction_data(
            abi: Dict,
            function_name: str,
            args: List = None,
            kwargs: Dict = None,
    ):
        """Get encoded transaction data"""
        args = args or list()
        fn_abi = find_matching_fn_abi(
            abi,
            function_name,
            args=args,
            kwargs=kwargs,
        )
        return encode_transaction_data(
            None,
            function_name,
            contract_abi=abi,
            fn_abi=fn_abi,
            args=args,
            kwargs=kwargs,
        )

    def decode_transaction_input(self, transaction_hash: bytes) -> Dict:
        """Return inputs of a method call"""
        transaction = self.contract.web3.eth.getTransaction(
            transaction_hash,
        )

        return self.contract.decode_function_input(
            transaction['input'],
        )

    def decode_event(self, log: Dict):
        return decode_event(self.contract.abi, log)

    def encode_function_call(self, function: str, args: List = None):
        return self.get_transaction_data(self.contract.abi, function, args)

    def estimate_gas(
            self,
            block_identifier,
            function: str,
            *args,
            **kwargs,
    ) -> typing.Optional[int]:
        """Returns a gas estimate for the function with the given arguments or
        None if the function call will fail due to Insufficient funds or
        the logic in the called function."""
        fn = getattr(self.contract.functions, function)
        address = to_checksum_address(self.jsonrpc_client.address)
        if self.jsonrpc_client.eth_node is constants.EthClient.GETH:
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
            return fn(*args, **kwargs).estimateGas(
                transaction={'from': address},
                block_identifier=block_identifier,
            )
        except ValueError as err:
            action = inspect_client_error(err, self.jsonrpc_client.eth_node)
            will_fail = action in (
                ClientErrorInspectResult.INSUFFICIENT_FUNDS,
                ClientErrorInspectResult.ALWAYS_FAIL,
            )
            if will_fail:
                return None

            raise err

    @property
    def contract_address(self):
        return to_canonical_address(self.contract.address)
