# -*- coding: utf-8 -*-
import logging
from binascii import unhexlify
from typing import Optional, List

from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_NETTING_CHANNEL,
)
from raiden.exceptions import TransactionThrew
from raiden import messages
from raiden.network.rpc.client import check_address_has_code
from raiden.network.proxies.token import Token
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    pex,
    privatekey_to_address,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class NettingChannel:
    def __init__(
            self,
            jsonrpc_client,
            channel_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        self.address = channel_address
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout

        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL),
            address_encoder(channel_address),
        )

        # check we are a participant of the given channel
        self.detail()
        self._check_exists()

    def _check_exists(self):
        check_address_has_code(self.client, self.address, 'Netting Channel')

    def _call_and_check_result(self, function_name: str):
        call_result = self.proxy.call(function_name)

        if call_result == b'':
            self._check_exists()
            raise RuntimeError(
                "Call to '{}' returned nothing".format(function_name)
            )

        return call_result

    def token_address(self):
        """ Returns the type of token that can be transferred by the channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        address = self._call_and_check_result('tokenAddress')
        return address_decoder(address)

    def detail(self):
        """ Returns a dictionary with the details of the netting channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        data = self._call_and_check_result('addressAndBalance')

        settle_timeout = self.settle_timeout()
        our_address = privatekey_to_address(self.client.privkey)

        if address_decoder(data[0]) == our_address:
            return {
                'our_address': address_decoder(data[0]),
                'our_balance': data[1],
                'partner_address': address_decoder(data[2]),
                'partner_balance': data[3],
                'settle_timeout': settle_timeout,
            }

        if address_decoder(data[2]) == our_address:
            return {
                'our_address': address_decoder(data[2]),
                'our_balance': data[3],
                'partner_address': address_decoder(data[0]),
                'partner_balance': data[1],
                'settle_timeout': settle_timeout,
            }

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def settle_timeout(self):
        """ Returns the netting channel settle_timeout.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        return self._call_and_check_result('settleTimeout')

    def opened(self):
        """ Returns the block in which the channel was created.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        return self._call_and_check_result('opened')

    def closed(self):
        """ Returns the block in which the channel was closed or 0.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        return self._call_and_check_result('closed')

    def closing_address(self):
        """ Returns the address of the closer, if the channel is closed, None
        otherwise.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closer = self.proxy.call('closingAddress')

        if closer:
            return address_decoder(closer)

        return None

    def can_transfer(self):
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closed = self.closed()

        if closed != 0:
            return False

        return self.detail()['our_balance'] > 0

    def deposit(self, amount):
        """ Deposit amount token in the channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
            RuntimeError: If the netting channel token address is empty.
        """
        if not isinstance(amount, int):
            raise ValueError('amount needs to be an integral number.')

        token_address = self.token_address()

        token = Token(
            self.client,
            token_address,
            self.poll_timeout,
        )
        current_balance = token.balance_of(self.node_address)

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        if log.isEnabledFor(logging.INFO):
            log.info('deposit called', contract=pex(self.address), amount=amount)

        transaction_hash = estimate_and_transact(
            self.proxy,
            'deposit',
            amount,
        )

        self.client.poll(
            unhexlify(transaction_hash),
            timeout=self.poll_timeout,
        )

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical('deposit failed', contract=pex(self.address))
            self._check_exists()
            raise TransactionThrew('Deposit', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info('deposit sucessfull', contract=pex(self.address), amount=amount)

    def close(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        """ Close the channel using the provided balance proof.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        if log.isEnabledFor(logging.INFO):
            log.info(
                'close called',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

        transaction_hash = estimate_and_transact(
            self.proxy,
            'close',
            nonce,
            transferred_amount,
            locksroot,
            extra_hash,
            signature,
        )
        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical(
                'close failed',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )
            self._check_exists()
            raise TransactionThrew('Close', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'close sucessfull',
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

    def update_transfer(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        if signature:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'updateTransfer called',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )

            transaction_hash = estimate_and_transact(
                self.proxy,
                'updateTransfer',
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature,
            )

            self.client.poll(
                unhexlify(transaction_hash),
                timeout=self.poll_timeout,
            )

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'updateTransfer failed',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )
                self._check_exists()
                raise TransactionThrew('Update Transfer', receipt_or_none)

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'updateTransfer sucessfull',
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )

    def withdraw(self, unlock_proofs):
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)

        if log.isEnabledFor(logging.INFO):
            log.info('withdraw called', contract=pex(self.address))

        failed = False
        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

            merkleproof_encoded = ''.join(merkle_proof)

            transaction_hash = estimate_and_transact(
                self.proxy,
                'withdraw',
                locked_encoded,
                merkleproof_encoded,
                secret,
            )

            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            lock = messages.Lock.from_bytes(locked_encoded)
            if receipt_or_none:
                lock = messages.Lock.from_bytes(locked_encoded)
                log.critical(
                    'withdraw failed',
                    contract=pex(self.address),
                    lock=lock,
                )
                self._check_exists()
                failed = True

            if log.isEnabledFor(logging.INFO):
                log.info(
                    'withdraw sucessfull',
                    contract=pex(self.address),
                    lock=lock,
                )

        if failed:
            raise TransactionThrew('Withdraw', receipt_or_none)

    def settle(self):
        if log.isEnabledFor(logging.INFO):
            log.info('settle called')

        transaction_hash = estimate_and_transact(
            self.proxy,
            'settle',
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.info('settle failed', contract=pex(self.address))
            self._check_exists()
            raise TransactionThrew('Settle', receipt_or_none)

        if log.isEnabledFor(logging.INFO):
            log.info('settle sucessfull', contract=pex(self.address))

    def events_filter(
            self,
            topics: Optional[List],
            from_block: Optional[int] = None,
            to_block: Optional[int] = None) -> Filter:
        """ Install a new filter for an array of topics emitted by the netting contract.
        Args:
            topics: A list of event ids to filter for. Can also be None,
                    in which case all events are queried.
            from_block: The block number at which to start looking for events.
            to_block: The block number at which to stop looking for events.
        Return:
            Filter: The filter instance.
        """
        netting_channel_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            netting_channel_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )

    def all_events_filter(self, from_block=None, to_block=None):
        """ Install a new filter for all the events emitted by the current netting channel contract

        Return:
            Filter: The filter instance.
        """
        return self.events_filter(None, from_block, to_block)
