from typing import List

import structlog
from eth_utils import encode_hex, event_abi_to_log_topic, is_binary_address, to_normalized_address
from gevent.event import AsyncResult

from raiden.constants import GAS_REQUIRED_PER_SECRET_IN_BATCH, GENESIS_BLOCK_NUMBER
from raiden.exceptions import InvalidAddress, RaidenUnrecoverableError
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, safe_gas_limit, sha3
from raiden.utils.typing import BlockNumber, BlockSpecification, Secret, SecretHash
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY, EVENT_SECRET_REVEALED
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class SecretRegistry:
    def __init__(
            self,
            jsonrpc_client,
            secret_registry_address,
            contract_manager: ContractManager,
    ):
        if not is_binary_address(secret_registry_address):
            raise InvalidAddress('Expected binary address format for secret registry')

        self.contract_manager = contract_manager
        check_address_has_code(jsonrpc_client, secret_registry_address, CONTRACT_SECRET_REGISTRY)

        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
            to_normalized_address(secret_registry_address),
        )

        compare_contract_versions(
            proxy=proxy,
            expected_version=contract_manager.contracts_version,
            contract_name=CONTRACT_SECRET_REGISTRY,
            address=secret_registry_address,
        )

        self.address = secret_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address
        self.open_secret_transactions = dict()

    def register_secret(self, secret: Secret, given_block_identifier: BlockSpecification):
        self.register_secret_batch([secret], given_block_identifier)

    def register_secret_batch(
            self,
            secrets: List[Secret],
            given_block_identifier: BlockSpecification,
    ):
        secrets_to_register = list()
        secrethashes_to_register = list()
        secrethashes_not_sent = list()
        secret_registry_transaction = AsyncResult()

        for secret in secrets:
            secrethash = sha3(secret)
            secrethash_hex = encode_hex(secrethash)

            is_register_needed = (
                not self.check_registered(secrethash, given_block_identifier) and
                secret not in self.open_secret_transactions
            )
            if is_register_needed:
                secrets_to_register.append(secret)
                secrethashes_to_register.append(secrethash_hex)
                self.open_secret_transactions[secret] = secret_registry_transaction
            else:
                secrethashes_not_sent.append(secrethash_hex)

        log_details = {
            'node': pex(self.node_address),
            'contract': pex(self.address),
            'secrethashes': secrethashes_to_register,
            'secrethashes_not_sent': secrethashes_not_sent,
        }

        if not secrets_to_register:
            log.debug('registerSecretBatch skipped', **log_details)
            return

        checking_block = self.client.get_checking_block()
        error_prefix = 'Call to registerSecretBatch will fail'
        gas_limit = self.proxy.estimate_gas(checking_block, 'registerSecretBatch', secrets)
        if gas_limit:
            error_prefix = 'Call to registerSecretBatch failed'
            try:
                gas_limit = safe_gas_limit(
                    gas_limit,
                    len(secrets) * GAS_REQUIRED_PER_SECRET_IN_BATCH,
                )
                transaction_hash = self.proxy.transact('registerSecretBatch', gas_limit, secrets)
                self.client.poll(transaction_hash)
                receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            except Exception as e:
                secret_registry_transaction.set_exception(e)
                msg = 'Unexpected exception at sending registerSecretBatch transaction'
            else:
                secret_registry_transaction.set(transaction_hash)
            finally:
                for secret in secrets_to_register:
                    self.open_secret_transactions.pop(secret, None)

        transaction_executed = gas_limit is not None
        if not transaction_executed or receipt_or_none:
            if transaction_executed:
                block = receipt_or_none['blockNumber']
            else:
                block = checking_block

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name='registerSecretBatch',
                transaction_executed=transaction_executed,
                required_gas=len(secrets) * GAS_REQUIRED_PER_SECRET_IN_BATCH,
                block_identifier=block,
            )
            error_msg = f'{error_prefix}. {msg}'
            log.critical(error_msg, **log_details)
            raise RaidenUnrecoverableError(error_msg)

        log.info('registerSecretBatch successful', **log_details)

    def get_register_block_for_secrethash(
            self,
            secrethash: SecretHash,
            block_identifier: BlockSpecification,
    ) -> BlockNumber:
        return self.proxy.contract.functions.getSecretRevealBlockHeight(
            secrethash,
        ).call(block_identifier=block_identifier)

    def check_registered(
            self,
            secrethash: SecretHash,
            block_identifier: BlockSpecification,
    ) -> bool:
        return self.get_register_block_for_secrethash(secrethash, block_identifier) > 0

    def secret_registered_filter(
            self,
            from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: BlockSpecification = 'latest',
    ) -> StatelessFilter:
        event_abi = self.contract_manager.get_event_abi(
            CONTRACT_SECRET_REGISTRY,
            EVENT_SECRET_REVEALED,
        )
        topics = [encode_hex(event_abi_to_log_topic(event_abi))]

        return self.client.new_filter(
            self.address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )
