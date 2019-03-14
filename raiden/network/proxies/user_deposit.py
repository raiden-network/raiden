from eth_utils import is_binary_address, to_normalized_address

from raiden.exceptions import InvalidAddress
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.utils.typing import Address, Balance, BlockSpecification
from raiden_contracts.constants import CONTRACT_USER_DEPOSIT
from raiden_contracts.contract_manager import ContractManager


class UserDeposit:
    def __init__(
            self,
            jsonrpc_client: JSONRPCClient,
            user_deposit_address: Address,
            contract_manager: ContractManager,
    ):
        if not is_binary_address(user_deposit_address):
            raise InvalidAddress('Expected binary address format for token nework')

        check_address_has_code(
            jsonrpc_client,
            Address(user_deposit_address),
            CONTRACT_USER_DEPOSIT,
        )

        self.address = user_deposit_address
        self.contract_manager = contract_manager
        self.proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_USER_DEPOSIT),
            to_normalized_address(user_deposit_address),
        )

        self.client = jsonrpc_client

    def effective_balance(self, address: Address, block_identifier: BlockSpecification) -> Balance:
        """ The user's balance with planned withdrawals deducted. """
        fn = getattr(self.proxy.contract.functions, 'effectiveBalance')
        balance = fn(address).call(block_identifier=block_identifier)

        if balance == b'':
            raise RuntimeError(f"Call to 'effectiveBalance' returned nothing")

        return balance
