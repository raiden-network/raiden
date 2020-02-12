from typing import Any, List, Optional

import structlog
from eth_utils import decode_hex, encode_hex, to_canonical_address
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import NULL_ADDRESS_BYTES
from raiden.exceptions import (
    AddressWithoutCode,
    BrokenPreconditionError,
    InvalidChannelParticipantDepositLimit,
    InvalidToken,
    InvalidTokenAddress,
    InvalidTokenNetworkDepositLimit,
    MaxTokenNetworkNumberReached,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.network.proxies.metadata import SmartContractMetadata
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import log_transaction, raise_on_call_returned_empty
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.formatting import format_block_id, to_checksum_address
from raiden.utils.smart_contracts import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    BlockSpecification,
    Dict,
    SecretRegistryAddress,
    T_TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    typecheck,
)
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY, CONTRACT_TOKEN_NETWORK_REGISTRY

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.proxies.proxy_manager import ProxyManager


log = structlog.get_logger(__name__)


class TokenNetworkRegistry:
    def __init__(
        self,
        rpc_client: JSONRPCClient,
        metadata: SmartContractMetadata,
        proxy_manager: "ProxyManager",
        block_identifier: BlockSpecification,
    ) -> None:

        check_address_has_code(
            client=rpc_client,
            address=Address(metadata.address),
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
            expected_code=metadata.runtime_bytecode,
            given_block_identifier=block_identifier,
        )

        proxy = rpc_client.new_contract_proxy(
            abi=metadata.abi, contract_address=Address(metadata.address)
        )

        self.address = TokenNetworkRegistryAddress(metadata.address)
        self.proxy_manager = proxy_manager
        self.rpc_client = rpc_client
        self.gas_measurements = metadata.gas_measurements
        self.metadata = metadata
        self.node_address = self.rpc_client.address
        self.proxy = proxy

    def get_token_network(
        self, token_address: TokenAddress, block_identifier: BlockSpecification
    ) -> Optional[TokenNetworkAddress]:
        """ Return the token network address for the given token or None if
        there is no correspoding address.
        """
        typecheck(token_address, T_TargetAddress)

        address = self.proxy.functions.token_to_token_networks(token_address).call(
            block_identifier=block_identifier
        )
        address = to_canonical_address(address)

        if address == NULL_ADDRESS_BYTES:
            return None

        return address

    def add_token(
        self,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
        given_block_identifier: BlockSpecification,
    ) -> TokenNetworkAddress:
        """
        Register token of `token_address` with the token network.
        The limits apply for version 0.13.0 and above of raiden-contracts,
        since instantiation also takes the limits as constructor arguments.
        """
        if given_block_identifier == "latest":
            raise ValueError(
                'Calling a proxy with "latest" is usually wrong because '
                "the result of the precondition check is not precisely predictable."
            )

        if token_address == NULL_ADDRESS_BYTES:
            raise InvalidTokenAddress("The call to register a token at 0x00..00 will fail.")

        if token_network_deposit_limit <= 0:
            raise InvalidTokenNetworkDepositLimit(
                f"Token network deposit limit must be larger than zero, "
                f"{token_network_deposit_limit} given."
            )

        if channel_participant_deposit_limit <= 0:
            raise InvalidTokenNetworkDepositLimit(
                f"Participant deposit limit must be larger than zero, "
                f"{channel_participant_deposit_limit} given"
            )

        if channel_participant_deposit_limit > token_network_deposit_limit:
            raise InvalidChannelParticipantDepositLimit(
                f"Participant deposit limit must be smaller than the network "
                f"deposit limit, {channel_participant_deposit_limit} is larger "
                f"than {token_network_deposit_limit}."
            )

        token_proxy = self.proxy_manager.token(token_address, given_block_identifier)
        try:
            token_supply = token_proxy.total_supply(block_identifier=given_block_identifier)
            already_registered = self.get_token_network(
                token_address=token_address, block_identifier=given_block_identifier
            )
            deprecation_executor = self.get_deprecation_executor(
                block_identifier=given_block_identifier
            )
            settlement_timeout_min = self.settlement_timeout_min(
                block_identifier=given_block_identifier
            )
            settlement_timeout_max = self.settlement_timeout_max(
                block_identifier=given_block_identifier
            )
            chain_id = self.get_chain_id(block_identifier=given_block_identifier)
            secret_registry_address = self.get_secret_registry_address(
                block_identifier=given_block_identifier
            )
            max_token_networks = self.get_max_token_networks(
                block_identifier=given_block_identifier
            )
            token_networks_created = self.get_token_network_created(
                block_identifier=given_block_identifier
            )
        except ValueError:
            # If `given_block_identifier` has been pruned the checks cannot be performed
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(given_block_identifier)
        else:
            if token_networks_created >= max_token_networks:
                raise MaxTokenNetworkNumberReached(
                    f"Number of token networks will exceed the maximum of {max_token_networks}"
                )

            if token_supply is None:
                raise InvalidToken(
                    "Given token address does not follow the "
                    "ERC20 standard (missing `totalSupply()`)"
                )
            if already_registered:
                raise BrokenPreconditionError(
                    "The token is already registered in the TokenNetworkRegistry."
                )

            if deprecation_executor == NULL_ADDRESS_BYTES:
                raise BrokenPreconditionError(
                    "The deprecation executor property for the TokenNetworkRegistry is invalid."
                )

            if chain_id == 0:
                raise BrokenPreconditionError(
                    "The chain ID property for the TokenNetworkRegistry is invalid."
                )

            if chain_id != self.rpc_client.chain_id:
                raise BrokenPreconditionError(
                    f"The provided chain ID {chain_id} does not match the "
                    f"network Raiden is running on: {self.rpc_client.chain_id}."
                )

            if secret_registry_address == NULL_ADDRESS_BYTES:
                raise BrokenPreconditionError(
                    "The secret registry address for the token network is invalid."
                )

            if settlement_timeout_min == 0:
                raise BrokenPreconditionError(
                    "The minimum settlement timeout for the token network "
                    "should be larger than zero."
                )

            if settlement_timeout_max <= settlement_timeout_min:
                raise BrokenPreconditionError(
                    "The maximum settlement timeout for the token network "
                    "should be larger than the minimum settlement timeout."
                )

        log_details = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "token_address": to_checksum_address(token_address),
            "given_block_identifier": format_block_id(given_block_identifier),
            "channel_participant_deposit_limit": channel_participant_deposit_limit,
            "token_network_deposit_limit": token_network_deposit_limit,
        }
        with log_transaction(log, "add_token", log_details):
            return self._add_token(
                token_address=token_address,
                channel_participant_deposit_limit=channel_participant_deposit_limit,
                token_network_deposit_limit=token_network_deposit_limit,
                log_details=log_details,
            )

    def _add_token(
        self,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
        log_details: Dict[Any, Any],
    ) -> TokenNetworkAddress:
        token_network_address = None

        checking_block = self.rpc_client.get_checking_block()

        kwargs = {
            "_token_address": token_address,
            "_channel_participant_deposit_limit": channel_participant_deposit_limit,
            "_token_network_deposit_limit": token_network_deposit_limit,
        }
        gas_limit = self.rpc_client.estimate_gas(
            self.proxy, checking_block, "createERC20TokenNetwork", **kwargs
        )

        if gas_limit:
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"]
            )
            log_details["gas_limit"] = gas_limit
            transaction_hash = self.rpc_client.transact(
                self.proxy, "createERC20TokenNetwork", gas_limit, **kwargs
            )

            receipt = self.rpc_client.poll(transaction_hash)

            if check_transaction_threw(receipt=receipt):
                failed_at_blocknumber = receipt["blockNumber"]
                failed_at_blockhash = receipt["blockHash"]

                max_token_networks = self.get_max_token_networks(
                    block_identifier=failed_at_blocknumber
                )
                token_networks_created = self.get_token_network_created(
                    block_identifier=failed_at_blocknumber
                )
                already_registered = self.get_token_network(
                    token_address=token_address, block_identifier=failed_at_blocknumber
                )
                deprecation_executor = self.get_deprecation_executor(
                    block_identifier=failed_at_blocknumber
                )
                settlement_timeout_min = self.settlement_timeout_min(
                    block_identifier=failed_at_blocknumber
                )
                settlement_timeout_max = self.settlement_timeout_max(
                    block_identifier=failed_at_blocknumber
                )
                chain_id = self.get_chain_id(block_identifier=failed_at_blocknumber)
                secret_registry_address = self.get_secret_registry_address(
                    block_identifier=failed_at_blocknumber
                )

                try:
                    # Creating a new instance to run the constructor checks.
                    token_proxy = Token(
                        jsonrpc_client=self.rpc_client,
                        token_address=token_address,
                        contract_manager=self.proxy_manager.contract_manager,
                        block_identifier=failed_at_blocknumber,
                    )
                except AddressWithoutCode:
                    # This cannot be an unrecoverable error, since the ERC20
                    # code is external.
                    raise RaidenRecoverableError(
                        "Token disappeared! The address "
                        "{to_checksum_address(token_address)} did have code at "
                        "block {log_details['given_block_identifier']}, however "
                        "at block {failed_at_blocknumber} when the registration "
                        "transaction was mined the address didn't have code "
                        "anymore."
                    )

                if receipt["cumulativeGasUsed"] == gas_limit:
                    msg = (
                        f"createERC20TokenNetwork failed and all gas was used "
                        f"({gas_limit}). Estimate gas may have underestimated "
                        f"createERC20TokenNetwork, or succeeded even though an assert is "
                        f"triggered, or the smart contract code has an "
                        f"conditional assert."
                    )
                    raise RaidenRecoverableError(msg)

                check_address_has_code(
                    client=self.rpc_client,
                    address=Address(secret_registry_address),
                    contract_name=CONTRACT_SECRET_REGISTRY,
                    expected_code=decode_hex(
                        self.proxy_manager.contract_manager.get_runtime_hexcode(
                            CONTRACT_SECRET_REGISTRY
                        )
                    ),
                    given_block_identifier=failed_at_blocknumber,
                )

                if token_networks_created >= max_token_networks:
                    raise RaidenRecoverableError(
                        "The number of existing token networks reached the maximum allowed"
                    )

                if already_registered:
                    # Race condition lost, the token network was created in a different
                    # transaction which got mined first.
                    raise RaidenRecoverableError(
                        "The token was already registered in the TokenNetworkRegistry."
                    )

                if deprecation_executor == NULL_ADDRESS_BYTES:
                    raise RaidenUnrecoverableError(
                        "The deprecation executor property for the "
                        "TokenNetworkRegistry is invalid."
                    )

                if chain_id == 0:
                    raise RaidenUnrecoverableError(
                        "The chain ID property for the TokenNetworkRegistry is invalid."
                    )

                if chain_id != self.rpc_client.chain_id:
                    raise RaidenUnrecoverableError(
                        f"The provided chain ID {chain_id} does not match the "
                        f"network Raiden is running on: {self.rpc_client.chain_id}."
                    )

                if secret_registry_address == NULL_ADDRESS_BYTES:
                    raise RaidenUnrecoverableError(
                        "The secret registry address for the token network is invalid."
                    )

                if settlement_timeout_min == 0:
                    raise RaidenUnrecoverableError(
                        "The minimum settlement timeout for the token network "
                        "should be larger than zero."
                    )

                if settlement_timeout_max <= settlement_timeout_min:
                    raise RaidenUnrecoverableError(
                        "The maximum settlement timeout for the token network "
                        "should be larger than the minimum settlement timeout."
                    )

                total_supply = token_proxy.total_supply(block_identifier=failed_at_blocknumber)
                if not total_supply or total_supply <= 0:
                    raise RaidenRecoverableError(
                        f"The given token address is not a valid ERC20 token, "
                        f"total_supply() returned an invalid value {total_supply}."
                    )

                # At this point, the TokenNetworkRegistry fails to instantiate
                # a new TokenNetwork.
                raise RaidenUnrecoverableError(
                    "createERC20TokenNetwork failed for an unknown reason, even "
                    "though the gas estimation succeeded."
                )

            succeeded_at_blockhash = receipt["blockHash"]
            token_network_address = self.get_token_network(token_address, succeeded_at_blockhash)
            if token_network_address is None:
                msg = "createERC20TokenNetwork succeeded but token network address is Null"
                raise RaidenUnrecoverableError(msg)
        else:
            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.rpc_client.get_block("latest")
            failed_at_blockhash_bytes = failed_at["hash"]
            failed_at_blockhash = encode_hex(failed_at_blockhash_bytes)
            failed_at_blocknumber = failed_at["number"]

            max_token_networks = self.get_max_token_networks(
                block_identifier=failed_at_blocknumber
            )
            token_networks_created = self.get_token_network_created(
                block_identifier=failed_at_blocknumber
            )

            already_registered = self.get_token_network(
                token_address=token_address, block_identifier=failed_at_blocknumber
            )
            deprecation_executor = self.get_deprecation_executor(
                block_identifier=failed_at_blocknumber
            )
            settlement_timeout_min = self.settlement_timeout_min(
                block_identifier=failed_at_blocknumber
            )
            settlement_timeout_max = self.settlement_timeout_max(
                block_identifier=failed_at_blocknumber
            )
            chain_id = self.get_chain_id(block_identifier=failed_at_blocknumber)
            secret_registry_address = self.get_secret_registry_address(
                block_identifier=failed_at_blocknumber
            )

            try:
                # Creating a new instance to run the constructor checks.
                token_proxy = Token(
                    jsonrpc_client=self.rpc_client,
                    token_address=token_address,
                    contract_manager=self.proxy_manager.contract_manager,
                    block_identifier=failed_at_blocknumber,
                )
            except AddressWithoutCode:
                # This cannot be an unrecoverable error, since the ERC20
                # code is external.
                raise RaidenRecoverableError(
                    "Token disappeared! The address "
                    "{to_checksum_address(token_address)} did have code at "
                    "block {log_details['given_block_identifier']}, however "
                    "at block {failed_at_blocknumber} when the registration "
                    "transaction was mined the address didn't have code "
                    "anymore."
                )

            check_address_has_code(
                client=self.rpc_client,
                address=Address(secret_registry_address),
                contract_name=CONTRACT_SECRET_REGISTRY,
                expected_code=decode_hex(
                    self.proxy_manager.contract_manager.get_runtime_hexcode(
                        CONTRACT_SECRET_REGISTRY
                    )
                ),
                given_block_identifier=failed_at_blocknumber,
            )

            required_gas = (
                gas_limit
                if gas_limit
                else self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"]
            )
            self.rpc_client.check_for_insufficient_eth(
                transaction_name="createERC20TokenNetwork",
                transaction_executed=False,
                required_gas=required_gas,
                block_identifier=failed_at_blocknumber,
            )

            if token_networks_created >= max_token_networks:
                raise RaidenRecoverableError(
                    "The number of existing token networks reached the maximum allowed"
                )

            if already_registered:
                # Race condition lost, the token network was created in a different
                # transaction which got mined first.
                raise RaidenRecoverableError(
                    "The token was already registered in the TokenNetworkRegistry."
                )

            if deprecation_executor == NULL_ADDRESS_BYTES:
                raise RaidenUnrecoverableError(
                    "The deprecation executor property for the TokenNetworkRegistry is invalid."
                )

            if chain_id == 0:
                raise RaidenUnrecoverableError(
                    "The chain ID property for the TokenNetworkRegistry is invalid."
                )

            if chain_id != self.rpc_client.chain_id:
                raise RaidenUnrecoverableError(
                    f"The provided chain ID {chain_id} does not match the "
                    f"network Raiden is running on: {self.rpc_client.chain_id}."
                )

            if secret_registry_address == NULL_ADDRESS_BYTES:
                raise RaidenUnrecoverableError(
                    "The secret registry address for the token network is invalid."
                )

            if settlement_timeout_min <= 0:
                raise RaidenUnrecoverableError(
                    "The minimum settlement timeout for the token network "
                    "should be larger than zero."
                )

            if settlement_timeout_max <= settlement_timeout_min:
                raise RaidenUnrecoverableError(
                    "The maximum settlement timeout for the token network "
                    "should be larger than the minimum settlement timeout."
                )

            total_supply = token_proxy.total_supply(block_identifier=failed_at_blocknumber)
            if not total_supply or total_supply <= 0:
                raise RaidenRecoverableError(
                    f"The given token address is not a valid ERC20 token, "
                    f"total_supply() returned an invalid value {total_supply}."
                )

            # At this point, the TokenNetworkRegistry fails to instantiate
            # a new TokenNetwork.
            raise RaidenUnrecoverableError(
                f"createERC20TokenNetwork gas estimation failed for an unknown "
                f"reason. Reference block {failed_at_blockhash} "
                f"{failed_at_blocknumber}."
            )
        return token_network_address

    def filter_token_added_events(self) -> List[Dict[str, Any]]:
        filter_ = self.proxy.events.TokenNetworkCreated.createFilter(
            fromBlock=self.metadata.filters_start_at
        )
        events = filter_.get_all_entries()
        if filter_.filter_id:
            self.proxy.web3.eth.uninstallFilter(filter_.filter_id)

        return events

    def get_chain_id(self, block_identifier: BlockSpecification) -> int:
        return self.proxy.functions.chain_id().call(block_identifier=block_identifier)

    def get_secret_registry_address(
        self, block_identifier: BlockSpecification
    ) -> SecretRegistryAddress:
        return SecretRegistryAddress(
            to_canonical_address(
                self.proxy.functions.secret_registry_address().call(
                    block_identifier=block_identifier
                )
            )
        )

    def get_deprecation_executor(self, block_identifier: BlockSpecification) -> Address:
        return Address(
            to_canonical_address(
                self.proxy.functions.deprecation_executor().call(block_identifier=block_identifier)
            )
        )

    def settlement_timeout_min(self, block_identifier: BlockSpecification) -> int:
        """ Returns the minimal settlement timeout for the token network registry. """
        return self.proxy.functions.settlement_timeout_min().call(
            block_identifier=block_identifier
        )

    def settlement_timeout_max(self, block_identifier: BlockSpecification) -> int:
        """ Returns the maximal settlement timeout for the token network registry. """
        return self.proxy.functions.settlement_timeout_max().call(
            block_identifier=block_identifier
        )

    def get_token_network_created(self, block_identifier: BlockSpecification) -> int:
        """ Returns the number of TokenNetwork contracts created so far in the
        token network registry.
        """
        return self.proxy.functions.token_network_created().call(block_identifier=block_identifier)

    def get_max_token_networks(self, block_identifier: BlockSpecification) -> int:
        """ Returns the maximal number of TokenNetwork contracts that the
        token network registry.
        """
        return self.proxy.functions.max_token_networks().call(block_identifier=block_identifier)
