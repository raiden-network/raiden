from typing import List

import structlog
from eth_utils import encode_hex, event_abi_to_log_topic, is_binary_address, to_normalized_address
from gevent.event import AsyncResult

from raiden.constants import GAS_REQUIRED_PER_SECRET_IN_BATCH, GENESIS_BLOCK_NUMBER
from raiden.exceptions import InvalidAddress, TransactionThrew
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, privatekey_to_address, safe_gas_limit, sha3, typing
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
        self.node_address = privatekey_to_address(self.client.privkey)
        self.open_secret_transactions = dict()

    def register_secret(self, secret: typing.Secret):
        self.register_secret_batch([secret])

    def register_secret_batch(self, secrets: List[typing.Secret]):
        secrets_to_register = list()
        secrethashes_to_register = list()
        secrethashes_not_sent = list()
        secret_registry_transaction = AsyncResult()

        for secret in secrets:
            secrethash = sha3(secret)
            secrethash_hex = encode_hex(secrethash)

            is_register_needed = (
                not self.check_registered(secrethash) and
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

        log.debug('registerSecretBatch called', **log_details)

        try:
            transaction_hash = self._register_secret_batch(secrets_to_register)
        except Exception as e:
            log.critical('registerSecretBatch failed', **log_details)
            secret_registry_transaction.set_exception(e)
            raise
        else:
            log.info('registerSecretBatch successful', **log_details)
            secret_registry_transaction.set(transaction_hash)
        finally:
            for secret in secrets_to_register:
                self.open_secret_transactions.pop(secret, None)

    def _register_secret_batch(self, secrets):
        gas_limit = self.proxy.estimate_gas('registerSecretBatch', secrets)
        gas_limit = safe_gas_limit(gas_limit, len(secrets) * GAS_REQUIRED_PER_SECRET_IN_BATCH)
        transaction_hash = self.proxy.transact('registerSecretBatch', gas_limit, secrets)
        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            raise TransactionThrew('registerSecretBatch', receipt_or_none)

        return transaction_hash

    def get_register_block_for_secrethash(self, secrethash: typing.Keccak256) -> int:
        return self.proxy.contract.functions.getSecretRevealBlockHeight(secrethash).call()

    def check_registered(self, secrethash: typing.Keccak256) -> bool:
        return self.get_register_block_for_secrethash(secrethash) > 0

    def secret_registered_filter(
            self,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
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
