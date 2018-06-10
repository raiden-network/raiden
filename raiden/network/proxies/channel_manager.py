# -*- coding: utf-8 -*-
from binascii import unhexlify
from typing import List, Tuple
from eth_utils import (
    is_binary_address,
    to_checksum_address,
    to_normalized_address,
    to_canonical_address,
)

import structlog
from gevent.event import AsyncResult
from web3.utils.filters import Filter

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    EVENT_CHANNEL_NEW,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.exceptions import (
    DuplicatedChannelError,
    InvalidSettleTimeout,
    SamePeerAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    pex,
    privatekey_to_address,
)
from raiden.utils.typing import Address, BlockSpecification
from raiden.constants import NULL_ADDRESS

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class ChannelManager:
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        # pylint: disable=too-many-arguments
        contract = jsonrpc_client.new_contract(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
            to_normalized_address(manager_address),
        )

        self.proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(manager_address):
            raise ValueError('manager_address must be a valid address')

        check_address_has_code(jsonrpc_client, manager_address, 'Channel Manager')

        CONTRACT_MANAGER.check_contract_version(
            self.version(),
            CONTRACT_CHANNEL_MANAGER
        )

        self.address = manager_address
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.open_channel_transactions = dict()

    def token_address(self) -> Address:
        """ Return the token of this manager. """
        token_address = self.proxy.contract.functions.tokenAddress().call()
        return to_canonical_address(token_address)

    def new_netting_channel(self, other_peer: Address, settle_timeout: int) -> Address:
        """ Creates and deploys a new netting channel contract.

        Args:
            other_peer: The peer to open the channel with.
            settle_timeout: The settle timout to use for this channel.

        Returns:
            The address of the new netting channel.
        """
        if not is_binary_address(other_peer):
            raise ValueError('The other_peer must be a valid address')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise InvalidSettleTimeout('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        local_address = privatekey_to_address(self.client.privkey)
        if local_address == other_peer:
            raise SamePeerAddress('The other peer must not have the same address as the client.')

        # Prevent concurrent attempts to open a channel with the same token and
        # partner address.
        if other_peer not in self.open_channel_transactions:
            new_open_channel_transaction = AsyncResult()
            self.open_channel_transactions[other_peer] = new_open_channel_transaction

            try:
                transaction_hash = self._new_netting_channel(other_peer, settle_timeout)
            except Exception as e:
                new_open_channel_transaction.set_exception(e)
                raise
            else:
                new_open_channel_transaction.set(transaction_hash)
            finally:
                self.open_channel_transactions.pop(other_peer, None)
        else:
            # All other concurrent threads should block on the result of opening this channel
            transaction_hash = self.open_channel_transactions[other_peer].get()

        netting_channel_results_encoded = self.proxy.contract.functions.getChannelWith(
            to_checksum_address(other_peer)
        ).call({'from': to_checksum_address(self.client.sender)})

        # address is at index 0
        netting_channel_address_encoded = netting_channel_results_encoded

        if not netting_channel_address_encoded:
            log.error(
                'netting_channel_address failed',
                peer1=pex(local_address),
                peer2=pex(other_peer)
            )
            raise RuntimeError('netting_channel_address failed')

        netting_channel_address_bin = to_canonical_address(netting_channel_address_encoded)

        log.info(
            'new_netting_channel called',
            peer1=pex(local_address),
            peer2=pex(other_peer),
            netting_channel=pex(netting_channel_address_bin),
        )

        return netting_channel_address_bin

    def _new_netting_channel(self, other_peer, settle_timeout):
        if self.channel_exists(other_peer):
            raise DuplicatedChannelError('Channel with given partner address already exists')

        transaction_hash = self.proxy.transact(
            'newChannel',
            other_peer,
            settle_timeout,
        )

        if not transaction_hash:
            raise RuntimeError('open channel transaction failed')

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        return transaction_hash

    def channels_addresses(self) -> List[Tuple[Address, Address]]:
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.contract.functions.getChannelsParticipants().call()

        channel_flat = [
            to_canonical_address(channel)
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return list(zip(channel_iter, channel_iter))

    def channels_by_participant(self, participant_address: Address) -> List[Address]:
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.contract.functions.nettingContractsByAddress(
            to_checksum_address(participant_address),
        ).call({'from': to_checksum_address(self.client.sender)})

        return [
            to_canonical_address(address)
            for address in address_list
        ]

    def channel_exists(self, participant_address: Address) -> bool:
        existing_channel = self.proxy.contract.functions.getChannelWith(
            to_checksum_address(participant_address),
        ).call({'from': to_checksum_address(self.client.sender)})

        exists = False

        if existing_channel != NULL_ADDRESS:
            exists = self.proxy.contract.functions.contractExists(
                to_checksum_address(existing_channel)
            ).call({'from': to_checksum_address(self.client.sender)})

        return exists

    def channelnew_filter(
            self,
            from_block: BlockSpecification = 0,
            to_block: BlockSpecification = 'latest',
    ) -> Filter:
        """ Install a new filter for ChannelNew events.

        Args:
            from_block: Create filter starting from this block number (default: 0).
            to_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]

        channel_manager_address_bin = self.proxy.contract_address
        return self.client.new_filter(
            channel_manager_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def version(self):
        return self.proxy.contract.functions.contract_version().call()
