# -*- coding: utf-8 -*-
import logging
from binascii import unhexlify
from typing import List, Union, Tuple

from ethereum import slogging

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    EVENT_CHANNEL_NEW,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.exceptions import (
    DuplicatedChannelError,
    SamePeerAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    isaddress,
    pex,
    privatekey_to_address,
)
from raiden.utils.typing import address

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class ChannelManager:
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(manager_address):
            raise ValueError('manager_address must be a valid address')

        check_address_has_code(jsonrpc_client, manager_address, 'Channel Manager')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
            address_encoder(manager_address),
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout

    def token_address(self) -> address:
        """ Return the token of this manager. """
        return address_decoder(self.proxy.call('tokenAddress'))

    def new_netting_channel(self, other_peer: address, settle_timeout: int) -> address:
        """ Creates and deploys a new netting channel contract.

        Args:
            other_peer: The peer to open the channel with.
            settle_timeout: The settle timout to use for this channel.

        Returns:
            The address of the new netting channel.
        """
        if not isaddress(other_peer):
            raise ValueError('The other_peer must be a valid address')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        local_address = privatekey_to_address(self.client.privkey)
        if local_address == other_peer:
            raise SamePeerAddress('The other peer must not have the same address as the client.')

        transaction_hash = estimate_and_transact(
            self.proxy,
            'newChannel',
            other_peer,
            settle_timeout,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        netting_channel_results_encoded = self.proxy.call(
            'getChannelWith',
            other_peer,
        )

        # address is at index 0
        netting_channel_address_encoded = netting_channel_results_encoded

        if not netting_channel_address_encoded:
            log.error(
                'netting_channel_address failed',
                peer1=pex(local_address),
                peer2=pex(other_peer)
            )
            raise RuntimeError('netting_channel_address failed')

        netting_channel_address_bin = address_decoder(netting_channel_address_encoded)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'new_netting_channel called',
                peer1=pex(local_address),
                peer2=pex(other_peer),
                netting_channel=pex(netting_channel_address_bin),
            )

        return netting_channel_address_bin

    def channels_addresses(self) -> List[Tuple[address, address]]:
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.call(
            'getChannelsParticipants',
        )

        channel_flat = [
            address_decoder(channel)
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return list(zip(channel_iter, channel_iter))

    def channels_by_participant(self, participant_address: address) -> List[address]:
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.call(
            'nettingContractsByAddress',
            participant_address,
        )

        return [
            address_decoder(address)
            for address in address_list
        ]

    def channelnew_filter(
            self,
            from_block: Union[str, int] = 0,
            to_block: Union[str, int] = 'latest') -> Filter:
        """ Install a new filter for ChannelNew events.

        Args:
            start_block:Create filter starting from this block number (default: 0).
            end_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]

        channel_manager_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            channel_manager_address_bin,
            topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )
