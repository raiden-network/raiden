from typing import Any, List, Optional

import structlog
from eth_utils import (
    decode_hex,
    encode_hex,
    event_abi_to_log_topic,
    is_binary_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
)
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import GENESIS_BLOCK_NUMBER, NULL_ADDRESS
from raiden.exceptions import (
    BrokenPreconditionError,
    InvalidToken,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.network.proxies.utils import log_transaction, raise_on_call_returned_empty
from raiden.network.rpc.client import JSONRPCClient, StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    BlockSpecification,
    Dict,
    T_TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    typecheck,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY, EVENT_TOKEN_NETWORK_CREATED
from raiden_contracts.contract_manager import ContractManager, gas_measurements

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService


log = structlog.get_logger(__name__)


class TokenNetworkRegistry:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        registry_address: TokenNetworkRegistryAddress,
        contract_manager: ContractManager,
        blockchain_service: "BlockChainService",
    ) -> None:
        if not is_binary_address(registry_address):
            raise ValueError("Expected binary address format for token network registry")

        check_address_has_code(
            client=jsonrpc_client,
            address=Address(registry_address),
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
            expected_code=decode_hex(
                contract_manager.get_runtime_hexcode(CONTRACT_TOKEN_NETWORK_REGISTRY)
            ),
        )

        self.contract_manager = contract_manager
        proxy = jsonrpc_client.new_contract_proxy(
            abi=self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            contract_address=Address(registry_address),
        )

        self.gas_measurements = gas_measurements(self.contract_manager.contracts_version)

        self.blockchain_service = blockchain_service

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

    def get_token_network(
        self, token_address: TokenAddress, block_identifier: BlockSpecification
    ) -> Optional[TokenNetworkAddress]:
        """ Return the token network address for the given token or None if
        there is no correspoding address.
        """
        typecheck(token_address, T_TargetAddress)

        address = self.proxy.contract.functions.token_to_token_networks(
            to_checksum_address(token_address)
        ).call(block_identifier=block_identifier)
        address = to_canonical_address(address)

        if is_same_address(address, NULL_ADDRESS):
            return None

        return address

    def add_token(
        self,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
        block_identifier: BlockSpecification,
    ) -> TokenNetworkAddress:
        """
        Register token of `token_address` with the token network.
        The limits apply for version 0.13.0 and above of raiden-contracts,
        since instantiation also takes the limits as constructor arguments.
        """
        if block_identifier == "latest":
            raise ValueError(
                'Calling a proxy with "latest" is usually wrong because '
                "the result of the precondition check is not precisely predictable."
            )

        # check preconditions
        try:
            already_registered = self.get_token_network(
                token_address=token_address, block_identifier=block_identifier
            )
        except ValueError:
            # If `block_identifier` has been pruned the checks cannot be performed
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(block_identifier)
        else:
            if already_registered:
                raise BrokenPreconditionError(
                    "The token is already registered in the TokenNetworkRegistry."
                )

        return self._add_token(
            token_address=token_address,
            channel_participant_deposit_limit=channel_participant_deposit_limit,
            token_network_deposit_limit=token_network_deposit_limit,
        )

    def _add_token(
        self,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
    ) -> TokenNetworkAddress:
        if not is_binary_address(token_address):
            raise ValueError("Expected binary address format for token")

        token_proxy = self.blockchain_service.token(token_address)

        if token_proxy.total_supply() == "":
            raise InvalidToken(
                "Given token address does not follow the ERC20 standard (missing `totalSupply()`)"
            )

        log_details: Dict[str, Any] = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "token_address": to_checksum_address(token_address),
        }

        failed_receipt = None
        with log_transaction(log, "add_token", log_details):
            checking_block = self.client.get_checking_block()
            error_prefix = "Call to createERC20TokenNetwork will fail"

            kwarguments = {
                "_token_address": token_address,
                "_channel_participant_deposit_limit": channel_participant_deposit_limit,
                "_token_network_deposit_limit": token_network_deposit_limit,
            }
            gas_limit = self.proxy.estimate_gas(
                checking_block, "createERC20TokenNetwork", **kwarguments
            )

            if gas_limit:
                error_prefix = "Call to createERC20TokenNetwork failed"
                gas_limit = safe_gas_limit(
                    gas_limit,
                    self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"],
                )
                log_details["gas_limit"] = gas_limit
                transaction_hash = self.proxy.transact(
                    "createERC20TokenNetwork", gas_limit, **kwarguments
                )

                receipt = self.client.poll(transaction_hash)
                failed_receipt = check_transaction_threw(receipt=receipt)

            transaction_executed = gas_limit is not None
            if not transaction_executed or failed_receipt:
                if failed_receipt:
                    block = failed_receipt["blockNumber"]
                else:
                    block = checking_block

                required_gas = (
                    gas_limit
                    if gas_limit
                    else self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"]
                )
                self.proxy.jsonrpc_client.check_for_insufficient_eth(
                    transaction_name="createERC20TokenNetwork",
                    transaction_executed=transaction_executed,
                    required_gas=required_gas,
                    block_identifier=block,
                )

                if self.get_token_network(token_address, block):
                    raise RaidenRecoverableError(f"{error_prefix}. Token already registered")

                if self.get_token_network_created(block) >= self.get_max_token_networks(block):
                    raise RaidenRecoverableError(f"{error_prefix}. TokenNetworkRegistry is full.")

                raise RaidenUnrecoverableError(error_prefix)

            token_network_address = self.get_token_network(token_address, "latest")
            if token_network_address is None:
                msg = "createERC20TokenNetwork succeeded but token network address is Null"
                raise RuntimeError(msg)

        return token_network_address

    def tokenadded_filter(
        self,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ) -> StatelessFilter:
        event_abi = self.contract_manager.get_event_abi(
            CONTRACT_TOKEN_NETWORK_REGISTRY, EVENT_TOKEN_NETWORK_CREATED
        )
        topics: List[Optional[str]] = [encode_hex(event_abi_to_log_topic(event_abi))]

        registry_address_bin = self.proxy.contract_address
        return self.client.new_filter(
            contract_address=registry_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def filter_token_added_events(self) -> List[Dict[str, Any]]:
        filter_ = self.proxy.contract.events.TokenNetworkCreated.createFilter(fromBlock=0)
        events = filter_.get_all_entries()
        if filter_.filter_id:
            self.proxy.contract.web3.eth.uninstallFilter(filter_.filter_id)

        return events

    def settlement_timeout_min(self) -> int:
        """ Returns the minimal settlement timeout for the token network registry. """
        return self.proxy.contract.functions.settlement_timeout_min().call()

    def settlement_timeout_max(self) -> int:
        """ Returns the maximal settlement timeout for the token network registry. """
        return self.proxy.contract.functions.settlement_timeout_max().call()

    def get_token_network_created(self, to_block: BlockSpecification) -> int:
        """ Returns the number of TokenNetwork contracts created so far in the
        token network registry.
        """
        return self.proxy.contract.functions.token_network_created().call(
            block_identifier=to_block
        )

    def get_max_token_networks(self, to_block: BlockSpecification) -> int:
        """ Returns the maximal number of TokenNetwork contracts that the
        token network registry.
        """
        return self.proxy.contract.functions.max_token_networks().call(block_identifier=to_block)
