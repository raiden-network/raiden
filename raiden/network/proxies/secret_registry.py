import structlog
from binascii import unhexlify

from web3.utils.filters import Filter
from eth_utils import (
    is_binary_address,
    to_normalized_address,
    event_abi_to_log_topic,
    encode_hex,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    EVENT_SECRET_REVEALED,
)
from raiden.exceptions import TransactionThrew, InvalidAddress
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    pex,
    typing,
    sha3,
    privatekey_to_address,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class SecretRegistry:
    def __init__(
            self,
            jsonrpc_client,
            secret_registry_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        # pylint: disable=too-many-arguments

        if not is_binary_address(secret_registry_address):
            raise InvalidAddress('Expected binary address format for secret registry')

        check_address_has_code(jsonrpc_client, secret_registry_address, 'Registry')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_SECRET_REGISTRY),
            to_normalized_address(secret_registry_address),
        )

        # TODO: add this back
        # CONTRACT_MANAGER.check_contract_version(
        #     proxy.functions.contract_version().call(),
        #     CONTRACT_SECRET_REGISTRY
        # )

        self.address = secret_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.node_address = privatekey_to_address(self.client.privkey)

    def register_secret(self, secret: typing.Secret):
        secrethash = sha3(secret)
        if self.check_registered(secrethash):
            log.info(
                'secret already registered',
                node=pex(self.node_address),
                contract=pex(self.address),
                secrethash=encode_hex(secrethash),
            )
            return

        log.info(
            'registerSecret called',
            node=pex(self.node_address),
            contract=pex(self.address),
        )

        transaction_hash = self.proxy.transact(
            'registerSecret',
            secret,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            log.critical(
                'registerSecret failed',
                node=pex(self.node_address),
                contract=pex(self.address),
                secret=secret,
            )
            raise TransactionThrew('registerSecret', receipt_or_none)

        log.info(
            'registerSecret successful',
            node=pex(self.node_address),
            contract=pex(self.address),
            secret=secret,
        )

    def get_register_block_for_secrehash(self, secrethash: typing.Keccak256) -> int:
        return self.proxy.contract.functions.getSecretRevealBlockHeight(secrethash).call()

    def check_registered(self, secrethash: typing.Keccak256) -> bool:
        return self.get_register_block_for_secrehash(secrethash) > 0

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
