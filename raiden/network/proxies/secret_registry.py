from typing import List

import structlog
from eth_utils import encode_hex, event_abi_to_log_topic, is_binary_address, to_normalized_address
from gevent.event import AsyncResult
from web3.exceptions import BadFunctionCallOutput
from web3.utils.filters import Filter

from raiden.exceptions import (
    AddressWrongContract,
    ContractVersionMismatch,
    InvalidAddress,
    TransactionThrew,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.settings import EXPECTED_CONTRACTS_VERSION
from raiden.utils import compare_versions, pex, privatekey_to_address, sha3, typing
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY, EVENT_SECRET_REVEALED
from raiden_contracts.contract_manager import CONTRACT_MANAGER

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class SecretRegistry:
    def __init__(
            self,
            jsonrpc_client,
            secret_registry_address,
    ):
        if not is_binary_address(secret_registry_address):
            raise InvalidAddress('Expected binary address format for secret registry')

        check_address_has_code(jsonrpc_client, secret_registry_address, CONTRACT_SECRET_REGISTRY)

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_SECRET_REGISTRY),
            to_normalized_address(secret_registry_address),
        )

        try:
            if not compare_versions(
                    proxy.contract.functions.contract_version().call(),
                    EXPECTED_CONTRACTS_VERSION,
            ):
                raise ContractVersionMismatch('Incompatible ABI for SecretRegistry')
        except BadFunctionCallOutput:
            raise AddressWrongContract('')

        self.address = secret_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.open_secret_transactions = dict()

    def register_secret(self, secret: typing.Secret):
        self.register_secret_batch([secret])

    def register_secret_batch(self, secrets: List[typing.Secret]):
        secret_batch = list()
        secret_registry_transaction = AsyncResult()

        for secret in secrets:
            secrethash = sha3(secret)
            if not self.check_registered(secrethash):
                if secret not in self.open_secret_transactions:
                    secret_batch.append(secret)
                    self.open_secret_transactions[secret] = secret_registry_transaction
            else:
                log.info(
                    f'secret {encode_hex(secrethash)} already registered.',
                    node=pex(self.node_address),
                    contract=pex(self.address),
                    secrethash=encode_hex(secrethash),
                )

        if not secret_batch:
            return

        log.info(
            'registerSecretBatch called',
            node=pex(self.node_address),
            contract=pex(self.address),
        )

        try:
            transaction_hash = self._register_secret_batch(secret_batch)
        except Exception as e:
            secret_registry_transaction.set_exception(e)
            raise
        else:
            secret_registry_transaction.set(transaction_hash)
        finally:
            for secret in secret_batch:
                self.open_secret_transactions.pop(secret, None)

    def _register_secret_batch(self, secrets):
        transaction_hash = self.proxy.transact(
            'registerSecretBatch',
            secrets,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            log.critical(
                'registerSecretBatch failed',
                node=pex(self.node_address),
                contract=pex(self.address),
                secrets=secrets,
            )
            raise TransactionThrew('registerSecretBatch', receipt_or_none)

        log.info(
            'registerSecretBatch successful',
            node=pex(self.node_address),
            contract=pex(self.address),
            secrets=secrets,
        )
        return transaction_hash

    def get_register_block_for_secrethash(self, secrethash: typing.Keccak256) -> int:
        return self.proxy.contract.functions.getSecretRevealBlockHeight(secrethash).call()

    def check_registered(self, secrethash: typing.Keccak256) -> bool:
        return self.get_register_block_for_secrethash(secrethash) > 0

    def secret_registered_filter(
            self,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ) -> Filter:
        event_abi = CONTRACT_MANAGER.get_event_abi(
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
