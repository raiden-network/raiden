from typing import Any, List, Optional

import structlog
from eth_utils import to_canonical_address
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import BLOCK_ID_LATEST, NULL_ADDRESS_BYTES
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
from raiden.network.proxies.utils import raise_on_call_returned_empty
from raiden.network.rpc.client import (
    JSONRPCClient,
    check_address_has_code_handle_pruned_block,
    check_transaction_failure,
    was_transaction_successfully_mined,
)
from raiden.utils.formatting import format_block_id, to_checksum_address
from raiden.utils.smart_contracts import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    BlockIdentifier,
    BlockNumber,
    Dict,
    SecretRegistryAddress,
    T_TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
    Tuple,
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
        block_identifier: BlockIdentifier,
    ) -> None:

        check_address_has_code_handle_pruned_block(
            client=rpc_client,
            address=Address(metadata.address),
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
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
        self, token_address: TokenAddress, block_identifier: BlockIdentifier
    ) -> Optional[TokenNetworkAddress]:
        """Return the token network address for the given token or None if
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
        given_block_identifier: BlockIdentifier,
    ) -> Tuple[TransactionHash, TokenNetworkAddress]:
        """
        Register token of `token_address` with the token network.
        The limits apply for version 0.13.0 and above of raiden-contracts,
        since instantiation also takes the limits as constructor arguments.
        """
        if given_block_identifier == BLOCK_ID_LATEST:
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
            controller = self.get_controller(block_identifier=given_block_identifier)
            settlement_timeout_min = self.settlement_timeout_min(
                block_identifier=given_block_identifier
            )
            settlement_timeout_max = self.settlement_timeout_max(
                block_identifier=given_block_identifier
            )
            chain_id = self.get_chain_id()
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

            if controller == NULL_ADDRESS_BYTES:
                raise BrokenPreconditionError(
                    "The controller property for the TokenNetworkRegistry is invalid."
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

        log_details = {"given_block_identifier": format_block_id(given_block_identifier)}
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
    ) -> Tuple[TransactionHash, TokenNetworkAddress]:
        token_network_address = None

        kwargs = {
            "_token_address": token_address,
            "_channel_participant_deposit_limit": channel_participant_deposit_limit,
            "_token_network_deposit_limit": token_network_deposit_limit,
        }
        estimated_transaction = self.rpc_client.estimate_gas(
            self.proxy, "createERC20TokenNetwork", log_details, **kwargs
        )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"],
            )

            transaction_sent = self.rpc_client.transact(estimated_transaction)
            transaction_mined = self.rpc_client.poll_transaction(transaction_sent)
            receipt = transaction_mined.receipt

            if not was_transaction_successfully_mined(transaction_mined):
                failed_at_blocknumber = BlockNumber(receipt["blockNumber"])

                max_token_networks = self.get_max_token_networks(
                    block_identifier=failed_at_blocknumber
                )
                token_networks_created = self.get_token_network_created(
                    block_identifier=failed_at_blocknumber
                )
                already_registered = self.get_token_network(
                    token_address=token_address, block_identifier=failed_at_blocknumber
                )
                controller = self.get_controller(block_identifier=failed_at_blocknumber)
                settlement_timeout_min = self.settlement_timeout_min(
                    block_identifier=failed_at_blocknumber
                )
                settlement_timeout_max = self.settlement_timeout_max(
                    block_identifier=failed_at_blocknumber
                )
                chain_id = self.get_chain_id()
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
                        f"{to_checksum_address(token_address)} did have code at "
                        f"block {log_details['given_block_identifier']}, however "
                        f"at block {failed_at_blocknumber} when the registration "
                        "transaction was mined the address didn't have code "
                        "anymore."
                    )

                check_transaction_failure(transaction_mined, self.rpc_client)

                check_address_has_code_handle_pruned_block(
                    client=self.rpc_client,
                    address=Address(secret_registry_address),
                    contract_name=CONTRACT_SECRET_REGISTRY,
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

                if controller == NULL_ADDRESS_BYTES:
                    raise RaidenUnrecoverableError(
                        "The controller property for the TokenNetworkRegistry is invalid."
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
        else:  # `estimated_transaction` is None
            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at_block = self.rpc_client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = failed_at_block["hash"].hex()
            failed_at_blocknumber = failed_at_block["number"]

            max_token_networks = self.get_max_token_networks(
                block_identifier=failed_at_blocknumber
            )
            token_networks_created = self.get_token_network_created(
                block_identifier=failed_at_blocknumber
            )

            already_registered = self.get_token_network(
                token_address=token_address, block_identifier=failed_at_blocknumber
            )
            controller = self.get_controller(block_identifier=failed_at_blocknumber)
            settlement_timeout_min = self.settlement_timeout_min(
                block_identifier=failed_at_blocknumber
            )
            settlement_timeout_max = self.settlement_timeout_max(
                block_identifier=failed_at_blocknumber
            )
            chain_id = self.get_chain_id()
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

            check_address_has_code_handle_pruned_block(
                client=self.rpc_client,
                address=Address(secret_registry_address),
                contract_name=CONTRACT_SECRET_REGISTRY,
                given_block_identifier=failed_at_blocknumber,
            )

            required_gas = self.gas_measurements["TokenNetworkRegistry createERC20TokenNetwork"]

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

            if controller == NULL_ADDRESS_BYTES:
                raise RaidenUnrecoverableError(
                    "The controller property for the TokenNetworkRegistry is invalid."
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
        return (
            TransactionHash(transaction_mined.transaction_hash),
            TokenNetworkAddress(token_network_address),
        )

    def filter_token_added_events(self) -> List[Dict[str, Any]]:
        filter_ = self.proxy.events.TokenNetworkCreated.createFilter(
            fromBlock=self.metadata.filters_start_at
        )
        events = filter_.get_all_entries()
        if filter_.filter_id:
            self.proxy.web3.eth.uninstallFilter(filter_.filter_id)

        return events

    def get_chain_id(self) -> int:
        return self.rpc_client.chain_id

    def get_secret_registry_address(
        self, block_identifier: BlockIdentifier
    ) -> SecretRegistryAddress:
        return SecretRegistryAddress(
            to_canonical_address(
                self.proxy.functions.secret_registry_address().call(
                    block_identifier=block_identifier
                )
            )
        )

    def get_controller(self, block_identifier: BlockIdentifier) -> Address:
        return Address(
            to_canonical_address(
                self.proxy.functions.controller().call(block_identifier=block_identifier)
            )
        )

    def settlement_timeout_min(self, block_identifier: BlockIdentifier) -> int:
        """Returns the minimal settlement timeout for the token network registry."""
        return self.proxy.functions.settlement_timeout_min().call(
            block_identifier=block_identifier
        )

    def settlement_timeout_max(self, block_identifier: BlockIdentifier) -> int:
        """Returns the maximal settlement timeout for the token network registry."""
        return self.proxy.functions.settlement_timeout_max().call(
            block_identifier=block_identifier
        )

    def get_token_network_created(self, block_identifier: BlockIdentifier) -> int:
        """Returns the number of TokenNetwork contracts created so far in the
        token network registry.
        """
        return self.proxy.functions.token_network_created().call(block_identifier=block_identifier)

    def get_max_token_networks(self, block_identifier: BlockIdentifier) -> int:
        """Returns the maximal number of TokenNetwork contracts that the
        token network registry.
        """
        return self.proxy.functions.max_token_networks().call(block_identifier=block_identifier)
