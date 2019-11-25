from typing import List

import gevent
import structlog
from eth_utils import (
    decode_hex,
    encode_hex,
    event_abi_to_log_topic,
    is_binary_address,
    to_checksum_address,
)
from gevent.event import AsyncResult
from gevent.lock import Semaphore

from raiden.constants import GAS_REQUIRED_PER_SECRET_IN_BATCH, RECEIPT_FAILURE_CODE
from raiden.exceptions import (
    NoStateForBlockIdentifier,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.network.proxies.utils import log_transaction
from raiden.network.rpc.client import JSONRPCClient, StatelessFilter, check_address_has_code
from raiden.utils import safe_gas_limit
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    BlockSpecification,
    Dict,
    Optional,
    Secret,
    SecretHash,
    Union,
)
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY, EVENT_SECRET_REVEALED
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


class SecretRegistry:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        secret_registry_address: Address,
        contract_manager: ContractManager,
    ) -> None:
        if not is_binary_address(secret_registry_address):
            raise ValueError("Expected binary address format for secret registry")

        self.contract_manager = contract_manager
        check_address_has_code(
            client=jsonrpc_client,
            address=secret_registry_address,
            contract_name=CONTRACT_SECRET_REGISTRY,
            expected_code=decode_hex(
                contract_manager.get_runtime_hexcode(CONTRACT_SECRET_REGISTRY)
            ),
        )

        proxy = jsonrpc_client.new_contract_proxy(
            abi=self.contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
            contract_address=secret_registry_address,
        )

        # There should be only one smart contract deployed, to avoid race
        # conditions for on-chain unlocks.

        self.address = secret_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

        # The dictionary of open transactions is used to avoid sending a
        # transaction for the same secret more than once. This requires
        # synchronization for the local threads.
        self.open_secret_transactions: Dict[Secret, AsyncResult] = dict()
        self._open_secret_transactions_lock = Semaphore()

    def register_secret(self, secret: Secret) -> None:
        self.register_secret_batch([secret])

    def register_secret_batch(self, secrets: List[Secret]) -> None:
        """Register a batch of secrets. Check if they are already registered at
        the given block identifier."""
        secrets_to_register = list()
        secrethashes_to_register = list()
        secrethashes_not_sent = list()
        transaction_result = AsyncResult()
        wait_for = set()

        # secret registration has no preconditions:
        #
        # - The action does not depend on any state, it's always valid to call
        #   it.
        # - This action is always susceptible to race conditions.
        #
        # Therefore this proxy only needs to detect if the secret is already
        # registered, to avoid sending obviously unecessary transactions, and
        # it has to handle race conditions.

        with self._open_secret_transactions_lock:
            verification_block_hash = self.client.get_confirmed_blockhash()

            for secret in secrets:
                secrethash = sha256_secrethash(secret)
                secrethash_hex = encode_hex(secrethash)

                # Do the local test on `open_secret_transactions` first, then
                # if necessary do an RPC call.
                #
                # The call to `is_secret_registered` has two conflicting
                # requirements:
                #
                # - Avoid sending duplicated transactions for the same lock
                # - Operating on a consistent/confirmed view of the blockchain
                #   (if a secret has been registered in a block that is not
                #   confirmed it doesn't count yet, an optimization would be to
                #   *not* send the transaction and wait for the confirmation)
                #
                # The code below respects the consistent blockchain view,
                # meaning that if this proxy method is called with an old
                # blockhash an unecessary transaction will be sent, and the
                # error will be treated as a race-condition.
                other_result = self.open_secret_transactions.get(secret)

                if other_result is not None:
                    wait_for.add(other_result)
                    secrethashes_not_sent.append(secrethash_hex)
                elif not self.is_secret_registered(secrethash, verification_block_hash):
                    secrets_to_register.append(secret)
                    secrethashes_to_register.append(secrethash_hex)
                    self.open_secret_transactions[secret] = transaction_result

        # From here on the lock is not required. Context-switches will happen
        # for the gas estimation and the transaction, however the
        # synchronization data is limited to the open_secret_transactions
        log_details = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "secrethashes": secrethashes_to_register,
            "secrethashes_not_sent": secrethashes_not_sent,
        }

        with log_transaction(log, "register_secret_batch", log_details):
            if secrets_to_register:
                self._register_secret_batch(secrets_to_register, transaction_result, log_details)

            gevent.joinall(wait_for, raise_error=True)

    def _register_secret_batch(
        self,
        secrets_to_register: List[Secret],
        transaction_result: AsyncResult,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        gas_limit = self.proxy.estimate_gas(
            checking_block, "registerSecretBatch", secrets_to_register
        )
        receipt = None
        transaction_hash = None
        msg = None

        if gas_limit:
            gas_limit = safe_gas_limit(
                gas_limit, len(secrets_to_register) * GAS_REQUIRED_PER_SECRET_IN_BATCH
            )
            log_details["gas_limit"] = gas_limit

            try:
                transaction_hash = self.proxy.transact(
                    "registerSecretBatch", gas_limit, secrets_to_register
                )
                receipt = self.client.poll(transaction_hash)
            except Exception as e:  # pylint: disable=broad-except
                msg = f"Unexpected exception {e} at sending registerSecretBatch transaction."

        # Clear `open_secret_transactions` regardless of the transaction being
        # successfully executed or not.
        with self._open_secret_transactions_lock:
            for secret in secrets_to_register:
                self.open_secret_transactions.pop(secret)

        # As of version `0.4.0` of the contract has *no* asserts or requires.
        # Therefore the only reason for the transaction to fail is if there is
        # a bug.
        unrecoverable_error = (
            gas_limit is None or receipt is None or receipt["status"] == RECEIPT_FAILURE_CODE
        )

        exception: Union[RaidenRecoverableError, RaidenUnrecoverableError]
        if unrecoverable_error:
            # If the transaction was sent it must not fail. If this happened
            # some of our assumptions is broken therefore the error is
            # unrecoverable
            if receipt is not None:
                if receipt["gasUsed"] == gas_limit:
                    # The transaction failed and all gas was used. This can
                    # happen because of:
                    #
                    # - A compiler bug if an invalid opcode was executed.
                    # - A configuration bug if an assert was executed,
                    # because version 0.4.0 of the secret registry does not have an
                    # assert.
                    # - An ethereum client bug if the gas_limit was
                    # underestimated.
                    #
                    # Safety cannot be guaranteed under any of these cases,
                    # this error is unrecoverable.
                    error = (
                        "Secret registration failed because of a bug in either "
                        "the solidity compiler, the running ethereum client, or "
                        "a configuration error in Raiden."
                    )
                else:
                    # The transaction failed and *not* all gas was used. This
                    # can happen because of:
                    #
                    # - A compiler bug if a revert was introduced.
                    # - A configuration bug, because for 0.4.0 the secret
                    # registry does not have a revert.
                    error = (
                        "Secret registration failed because of a configuration "
                        "bug or compiler bug. Please double check the secret "
                        "smart contract is at version 0.4.0, if it is then a "
                        "compiler bug was hit."
                    )

                exception = RaidenUnrecoverableError(error)
                transaction_result.set_exception(exception)
                raise exception

            # If gas_limit is set and there is no receipt then an exception was
            # raised while sending the transaction. This should only happen if
            # the account is being used concurrently, which is not supported.
            # This can happen because:
            #
            # - The nonce of the transaction was already used
            # - The nonce was reused *and* the account didn't have enough ether
            # to pay for the gas
            #
            # Safety cannot be guaranteed under any of these cases, this error
            # is unrecoverable. *Note*: This assumes the ethereum client
            # takes into account the current transactions in the pool.
            if gas_limit:
                assert msg, "Unexpected control flow, an exception should have been raised."
                error = (
                    f"Sending the the transaction for registerSecretBatch "
                    f"failed with: `{msg}`.  This happens if the same ethereum "
                    f"account is being used by more than one program which is not "
                    f"supported."
                )

                exception = RaidenUnrecoverableError(error)
                transaction_result.set_exception(exception)
                raise exception

            # gas_limit can fail because:
            #
            # - The Ethereum client detected the transaction could not
            # successfully execute, this happens if an assert/revert is hit.
            # - The account is lacking funds to pay for the gas.
            #
            # Either of these is a bug. The contract does not use
            # assert/revert, and the account should always be funded
            assert gas_limit
            self.proxy.rpc_client.check_for_insufficient_eth(
                transaction_name="registerSecretBatch",
                transaction_executed=True,
                required_gas=gas_limit,
                block_identifier=checking_block,
            )
            error = "Call to registerSecretBatch couldn't be done"

            exception = RaidenRecoverableError(error)
            transaction_result.set_exception(exception)
            raise exception

        # The local **MUST** transaction_result be set before waiting for the
        # other results, otherwise we have a dead-lock
        transaction_result.set(transaction_hash)

    def get_secret_registration_block_by_secrethash(
        self, secrethash: SecretHash, block_identifier: BlockSpecification
    ) -> Optional[BlockNumber]:
        """Return the block number at which the secret for `secrethash` was
        registered, None if the secret was never registered.
        """
        result = self.proxy.contract.functions.getSecretRevealBlockHeight(secrethash).call(
            block_identifier=block_identifier
        )

        # Block 0 either represents the genesis block or an empty entry in the
        # secret mapping. This is important for custom genesis files used while
        # testing. To avoid problems the smart contract can be added as part of
        # the genesis file, however it's important for its storage to be
        # empty.
        if result == 0:
            return None

        return result

    def is_secret_registered(
        self, secrethash: SecretHash, block_identifier: BlockSpecification
    ) -> bool:
        """True if the secret for `secrethash` is registered at `block_identifier`.

        Throws NoStateForBlockIdentifier if the given block_identifier
        is older than the pruning limit
        """
        if not self.client.can_query_state_for_block(block_identifier):
            raise NoStateForBlockIdentifier()

        block = self.get_secret_registration_block_by_secrethash(
            secrethash=secrethash, block_identifier=block_identifier
        )
        return block is not None

    def secret_registered_filter(self, from_block: BlockNumber) -> StatelessFilter:
        event_abi = self.contract_manager.get_event_abi(
            CONTRACT_SECRET_REGISTRY, EVENT_SECRET_REVEALED
        )
        topics: List[Optional[str]] = [encode_hex(event_abi_to_log_topic(event_abi))]

        return self.client.new_filter(
            contract_address=self.address, topics=topics, from_block=from_block
        )
