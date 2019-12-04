from typing import Any, Dict, List

import structlog

from raiden.network.proxies.exceptions import MintFailed
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import log_transaction
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.typing import Address, TokenAmount
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


class CustomToken(Token):
    @staticmethod
    def abi(contract_manager: ContractManager) -> List[Dict[str, Any]]:
        """Overwrittable by subclasses to change the proxies ABI."""
        return contract_manager.get_contract_abi(CONTRACT_CUSTOM_TOKEN)

    def mint(self, amount: TokenAmount) -> None:
        """ Try to mint tokens by calling `min`.

        Raises:
            MintFailed if anything goes wrong.
        """

        checking_block = self.client.get_checking_block()
        log_details: Dict[str, Any] = {"amount": amount}

        with log_transaction(log, "mint", log_details):
            gas_limit = self.proxy.estimate_gas(checking_block, "mint", amount)

            if gas_limit:
                log_details["gas_limit"] = gas_limit
                transaction_hash = self.proxy.transact("mint", gas_limit, amount)

                receipt = self.client.poll(transaction_hash)
                failed_receipt = check_transaction_threw(receipt=receipt)

                if failed_receipt:
                    raise MintFailed(f"Mint failed.")

            else:
                raise MintFailed(
                    "Gas estimation failed. Make sure the token has a method " "mint(uint256)."
                )

    def mint_for(self, amount: TokenAmount, address: Address) -> None:
        """ Try to mint tokens by calling `min`.

        Raises:
            MintFailed if anything goes wrong.
        """

        checking_block = self.client.get_checking_block()
        log_details: Dict[str, Any] = {"amount": amount, "address": Address}

        with log_transaction(log, "mint", log_details):
            gas_limit = self.proxy.estimate_gas(checking_block, "mintFor", amount, address)

            if gas_limit:
                log_details["gas_limit"] = gas_limit
                transaction_hash = self.proxy.transact("mintFor", gas_limit, amount, address)

                receipt = self.client.poll(transaction_hash)
                failed_receipt = check_transaction_threw(receipt=receipt)

                if failed_receipt:
                    raise MintFailed(f"Call to contract method mintFor: Transaction failed.")

            else:
                raise MintFailed(
                    "Gas estimation failed. Make sure the token has a method "
                    "named mintFor(uint256,address)."
                )
