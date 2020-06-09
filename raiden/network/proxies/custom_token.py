from typing import Any, Dict

import structlog

from raiden.network.proxies.exceptions import MintFailed
from raiden.network.proxies.token import Token
from raiden.network.rpc.client import was_transaction_successfully_mined
from raiden.utils.typing import ABI, Address, TokenAmount
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


class CustomToken(Token):
    @staticmethod
    def abi(contract_manager: ContractManager) -> ABI:
        """Overwrittable by subclasses to change the proxies ABI."""
        return contract_manager.get_contract_abi(CONTRACT_CUSTOM_TOKEN)

    def mint(self, amount: TokenAmount) -> None:
        """ Try to mint tokens by calling `mint`.

        Raises:
            MintFailed if anything goes wrong.
        """

        extra_log_details: Dict[str, Any] = {}
        estimated_transaction = self.client.estimate_gas(
            self.proxy, "mint", extra_log_details, amount
        )

        if estimated_transaction is not None:
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                raise MintFailed("Mint failed.")

        else:
            raise MintFailed(
                "Gas estimation failed. Make sure the token has a method mint(uint256)."
            )

    def mint_for(self, amount: TokenAmount, address: Address) -> None:
        """ Try to mint tokens by calling `mintFor`.

        Raises:
            MintFailed if anything goes wrong.
        """

        extra_log_details: Dict[str, Any] = {}
        estimated_transaction = self.client.estimate_gas(
            self.proxy, "mintFor", extra_log_details, amount, address
        )

        if estimated_transaction is not None:
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                raise MintFailed("Call to contract method mintFor: Transaction failed.")

        else:
            raise MintFailed(
                "Gas estimation failed. Make sure the token has a method "
                "named mintFor(uint256,address)."
            )
