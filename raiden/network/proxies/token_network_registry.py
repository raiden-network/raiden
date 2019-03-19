from typing import Optional

import structlog
from eth_utils import (
    encode_hex,
    event_abi_to_log_topic,
    is_binary_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)

from raiden.constants import (
    GAS_REQUIRED_FOR_CREATE_ERC20_TOKEN_NETWORK,
    GENESIS_BLOCK_NUMBER,
    NULL_ADDRESS,
)
from raiden.exceptions import InvalidAddress, RaidenRecoverableError, RaidenUnrecoverableError
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, safe_gas_limit
from raiden.utils.typing import (
    Address,
    Any,
    BlockSpecification,
    List,
    PaymentNetworkID,
    T_TargetAddress,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY, EVENT_TOKEN_NETWORK_CREATED
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class TokenNetworkRegistry:
    def __init__(
            self,
            jsonrpc_client,
            registry_address: PaymentNetworkID,
            contract_manager: ContractManager,
    ):
        if not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for token network registry')

        check_address_has_code(
            client=jsonrpc_client,
            address=Address(registry_address),
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
        )

        self.contract_manager = contract_manager
        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            to_normalized_address(registry_address),
        )

        compare_contract_versions(
            proxy=proxy,
            expected_version=contract_manager.contracts_version,
            contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
            address=Address(registry_address),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

    def get_token_network(
            self,
            token_address: TokenAddress,
            block_identifier: BlockSpecification = 'latest',
    ) -> Optional[Address]:
        """ Return the token network address for the given token or None if
        there is no correspoding address.
        """
        if not isinstance(token_address, T_TargetAddress):
            raise ValueError('token_address must be an address')

        address = self.proxy.contract.functions.token_to_token_networks(
            to_checksum_address(token_address),
        ).call(block_identifier=block_identifier)
        address = to_canonical_address(address)

        if is_same_address(address, NULL_ADDRESS):
            return None

        return address

    def add_token_with_limits(
            self,
            token_address: TokenAddress,
            channel_participant_deposit_limit: TokenAmount,
            token_network_deposit_limit: TokenAmount,
    ) -> Address:
        """
        Register token of `token_address` with the token network.
        The limits apply for version 0.13.0 and above of raiden-contracts,
        since instantiation also takes the limits as constructor arguments.
        """
        return self._add_token(
            token_address=token_address,
            additional_arguments=[channel_participant_deposit_limit, token_network_deposit_limit],
        )

    def add_token_without_limits(
            self,
            token_address: TokenAddress,
    ) -> Address:
        """
        Register token of `token_address` with the token network.
        This applies for versions prior to 0.13.0 of raiden-contracts,
        since limits were hardcoded into the TokenNetwork contract.
        """
        return self._add_token(
            token_address=token_address,
            additional_arguments=list(),
        )

    def _add_token(
            self,
            token_address: TokenAddress,
            additional_arguments: List[Any],
    ) -> Address:
        # given_block_identifier is not really used in this function yet as there
        # are no preconditions to check with the given block
        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token')

        log_details = {
            'node': pex(self.node_address),
            'token_address': pex(token_address),
            'registry_address': pex(self.address),
        }
        log.debug('createERC20TokenNetwork called', **log_details)

        checking_block = self.client.get_checking_block()
        error_prefix = 'Call to createERC20TokenNetwork will fail'

        arguments = [token_address] + additional_arguments
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            'createERC20TokenNetwork',
            *arguments,
        )

        if gas_limit:
            error_prefix = 'Call to createERC20TokenNetwork failed'
            transaction_hash = self.proxy.transact(
                'createERC20TokenNetwork',
                safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_CREATE_ERC20_TOKEN_NETWORK),
                *arguments,
            )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        transaction_executed = gas_limit is not None
        if not transaction_executed or receipt_or_none:
            error_type = RaidenUnrecoverableError
            if transaction_executed:
                block = receipt_or_none['blockNumber']
            else:
                block = checking_block

            required_gas = gas_limit if gas_limit else GAS_REQUIRED_FOR_CREATE_ERC20_TOKEN_NETWORK
            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name='createERC20TokenNetwork',
                transaction_executed=transaction_executed,
                required_gas=required_gas,
                block_identifier=block,
            )

            msg = ''
            if self.get_token_network(token_address, block):
                msg = 'Token already registered'
                error_type = RaidenRecoverableError

            error_msg = f'{error_prefix}. {msg}'
            if error_type == RaidenRecoverableError:
                log.warning(error_msg, **log_details)
            else:
                log.critical(error_msg, **log_details)
            raise error_type(error_msg)

        token_network_address = self.get_token_network(token_address, 'latest')
        if token_network_address is None:
            msg = 'createERC20TokenNetwork succeeded but token network address is Null'
            log.critical(msg, **log_details)
            raise RuntimeError(msg)

        log.info(
            'createERC20TokenNetwork successful',
            token_network_address=pex(token_network_address),
            **log_details,
        )

        return token_network_address

    def tokenadded_filter(
            self,
            from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: BlockSpecification = 'latest',
    ) -> StatelessFilter:
        event_abi = self.contract_manager.get_event_abi(
            CONTRACT_TOKEN_NETWORK_REGISTRY,
            EVENT_TOKEN_NETWORK_CREATED,
        )
        topics = [encode_hex(event_abi_to_log_topic(event_abi))]

        registry_address_bin = self.proxy.contract_address
        return self.client.new_filter(
            registry_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def filter_token_added_events(self):
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
